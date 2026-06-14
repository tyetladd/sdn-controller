"""
SDN Node Monitor - health and performance monitoring.

Monitors:
- Tunnel connectivity (handshake freshness)
- Bandwidth usage (RX/TX per peer)
- Interface status
- Peer connectivity changes
- Alerts on anomalies
"""

import time
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Set, Callable

from node.agent import NodeAgent, NodeStatus, TunnelStatus


@dataclass
class Alert:
    """A monitoring alert."""
    level: str  # info, warning, critical
    node: str
    message: str
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "node": self.node,
            "message": self.message,
            "timestamp": self.timestamp,
            "resolved": self.resolved,
        }


@dataclass
class TrafficStats:
    """Traffic statistics over a time window."""
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_rate: float = 0.0   # bytes/sec
    tx_rate: float = 0.0   # bytes/sec
    window_start: float = field(default_factory=time.time)
    window_end: float = 0.0

    def update(self, rx: int, tx: int) -> None:
        now = time.time()
        elapsed = now - self.window_start
        if elapsed > 0:
            self.rx_rate = (rx - self.rx_bytes) / elapsed
            self.tx_rate = (tx - self.tx_bytes) / elapsed
        self.rx_bytes = rx
        self.tx_bytes = tx
        self.window_end = now
        self.window_start = now


class NodeMonitor:
    """Monitors an SDN node's health and performance.

    Tracks:
    - Peer connectivity (handshake freshness)
    - Traffic rates per peer
    - Interface uptime
    - Config changes
    - Anomaly detection and alerting
    """

    # Thresholds
    HANDSHAKE_STALE_SECONDS = 180    # 3 min — peer considered disconnected
    HANDSHAKE_CRITICAL_SECONDS = 600 # 10 min — peer critically disconnected
    HIGH_TRAFFIC_RATE_MBPS = 800     # Alert on sustained high traffic

    def __init__(self, agent: NodeAgent):
        self.agent = agent
        self._traffic_stats: Dict[str, TrafficStats] = {}
        self._alerts: List[Alert] = []
        self._alert_callbacks: List[Callable] = []
        self._peer_seen: Set[str] = set()
        self._handshake_history: Dict[str, List[float]] = defaultdict(list)
        self._start_time = time.time()

    def add_alert_callback(self, cb: Callable) -> None:
        """Register a callback for new alerts."""
        self._alert_callbacks.append(cb)

    def collect_metrics(self) -> Dict[str, Any]:
        """Collect current metrics from the agent."""
        status = self.agent.get_status()
        if not status:
            return {}

        now = time.time()
        metrics = {
            "timestamp": now,
            "node": status.node_name,
            "interface": status.interface,
            "uptime_seconds": status.uptime_seconds,
            "peer_count": status.peer_count,
            "peers": [],
            "alerts": len(self._alerts),
        }

        for peer_status in status.peers:
            peer_key = peer_status.peer_public_key
            peer_metrics = {
                "peer": peer_key[:16] + "...",
                "endpoint": peer_status.endpoint,
                "connected": peer_status.connected,
                "latest_handshake": peer_status.latest_handshake,
                "transfer_rx": peer_status.transfer_rx,
                "transfer_tx": peer_status.transfer_tx,
                "allowed_ips": peer_status.allowed_ips,
            }

            # Calculate traffic rate
            if peer_key not in self._traffic_stats:
                self._traffic_stats[peer_key] = TrafficStats(
                    rx_bytes=peer_status.transfer_rx,
                    tx_bytes=peer_status.transfer_tx,
                )

            stats = self._traffic_stats[peer_key]
            stats.update(peer_status.transfer_rx, peer_status.transfer_tx)
            peer_metrics["rx_rate_mbps"] = round(
                (stats.rx_rate * 8) / 1_000_000, 2
            )
            peer_metrics["tx_rate_mbps"] = round(
                (stats.tx_rate * 8) / 1_000_000, 2
            )

            # Handshake freshness
            if peer_status.latest_handshake:
                ago = now - peer_status.latest_handshake
                peer_metrics["handshake_ago_seconds"] = round(ago, 1)
            else:
                peer_metrics["handshake_ago_seconds"] = None

            metrics["peers"].append(peer_metrics)

        return metrics

    def check_health(self) -> List[Alert]:
        """Run health checks and return any new alerts."""
        status = self.agent.get_status()
        if not status:
            return []

        now = time.time()
        new_alerts = []

        for peer_status in status.peers:
            # Check handshake staleness
            if peer_status.latest_handshake:
                ago = now - peer_status.latest_handshake
                if ago > self.HANDSHAKE_CRITICAL_SECONDS:
                    alert = Alert(
                        level="critical",
                        node=self.agent.node_name,
                        message=(
                            f"Peer {peer_status.peer_public_key[:16]}... "
                            f"handshake is {ago:.0f}s old (critical)"
                        ),
                    )
                    new_alerts.append(alert)
                elif ago > self.HANDSHAKE_STALE_SECONDS:
                    alert = Alert(
                        level="warning",
                        node=self.agent.node_name,
                        message=(
                            f"Peer {peer_status.peer_public_key[:16]}... "
                            f"handshake is {ago:.0f}s old (stale)"
                        ),
                    )
                    new_alerts.append(alert)
            else:
                # Never handshaked
                if peer_status.peer_public_key in self._peer_seen:
                    alert = Alert(
                        level="warning",
                        node=self.agent.node_name,
                        message=(
                            f"Peer {peer_status.peer_public_key[:16]}... "
                            f"has never completed a handshake"
                        ),
                    )
                    new_alerts.append(alert)

            self._peer_seen.add(peer_status.peer_public_key)

        # Check traffic anomalies
        for peer_key, stats in self._traffic_stats.items():
            rate_mbps = (stats.rx_rate * 8) / 1_000_000
            if rate_mbps > self.HIGH_TRAFFIC_RATE_MBPS:
                alert = Alert(
                    level="info",
                    node=self.agent.node_name,
                    message=(
                        f"High traffic on peer {peer_key[:16]}...: "
                        f"{rate_mbps:.1f} Mbps RX"
                    ),
                )
                new_alerts.append(alert)

        # Resolve old alerts
        for alert in self._alerts:
            if not alert.resolved:
                # Auto-resolve after 5 minutes
                if now - alert.timestamp > 300:
                    alert.resolved = True

        self._alerts.extend(new_alerts)
        for alert in new_alerts:
            for cb in self._alert_callbacks:
                cb(alert)

        return new_alerts

    def get_alerts(
        self, include_resolved: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all alerts."""
        alerts = self._alerts
        if not include_resolved:
            alerts = [a for a in alerts if not a.resolved]
        return [a.to_dict() for a in alerts]

    def get_health_summary(self) -> Dict[str, Any]:
        """Get a concise health summary."""
        metrics = self.collect_metrics()
        alerts = self.get_alerts()

        connected = sum(
            1 for p in metrics.get("peers", []) if p.get("connected")
        )
        total = len(metrics.get("peers", []))

        return {
            "node": self.agent.node_name,
            "healthy": all(a["level"] != "critical" for a in alerts),
            "uptime_hours": round(
                metrics.get("uptime_seconds", 0) / 3600, 2
            ),
            "peers_connected": f"{connected}/{total}",
            "alert_count": len(alerts),
            "alerts": [a["message"] for a in alerts if a["level"] == "critical"],
            "warnings": [a["message"] for a in alerts if a["level"] == "warning"],
        }

    def save_metrics_history(self, path: Path) -> None:
        """Append current metrics to a history file."""
        metrics = self.collect_metrics()
        if not metrics:
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        record = json.dumps(metrics)
        with open(path, "a") as f:
            f.write(record + "\n")

    def reset_stats(self) -> None:
        """Reset all traffic statistics."""
        self._traffic_stats.clear()
        self._handshake_history.clear()
        self._peer_seen.clear()
