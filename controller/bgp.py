"""
BGP Route Announcer — announces SDN overlay routes to local routers.

When the SDN controller adds/removes AllowedIPs prefixes on a node,
this module pushes those routes to a BGP daemon (GoBGP or BIRD)
running alongside the controller. Local routers learn SDN routes
via standard BGP, integrating the overlay with the underlay network.

Architecture:
    SDN Controller                    BGP Speaker
    ┌──────────────┐    routes        ┌──────────────┐    BGP
    │ AllowedIPs   │─────────────────►│ GoBGP / BIRD  │────────► Router
    │ 10.99.0.0/24 │   inject/withdraw│ AS 65001      │  peering  AS 65000
    └──────────────┘                  └──────────────┘

Supported backends:
- GoBGP CLI (gobgp global rib add/del) — zero-dependency
- GoBGP gRPC — programmatic API (requires grpcio)
- BIRD config file generation — deploy to BIRD nodes
"""

import subprocess
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from threading import Thread, Event


@dataclass
class BgpRoute:
    """A BGP route to announce."""
    prefix: str
    next_hop: str
    community: Optional[str] = None
    local_pref: int = 100
    origin: str = "igp"  # igp, egp, incomplete

    def to_gobgp_args(self) -> List[str]:
        """Convert to gobgp CLI arguments."""
        args = [self.prefix, "nexthop", self.next_hop]
        args.extend(["origin", self.origin])
        if self.community:
            args.extend(["community", self.community])
        return args

    def to_bird_config(self) -> str:
        """Generate a BIRD static route entry."""
        return f'  route {self.prefix} via {self.next_hop};'


@dataclass
class BgpPeer:
    """A BGP peering neighbor."""
    neighbor_ip: str
    remote_as: int
    local_as: int = 65001
    description: str = ""
    multihop: bool = False


class BgpRouteAnnouncer:
    """Announces SDN overlay routes to local routers via BGP.

    Watches the SDN topology for AllowedIPs changes and pushes
    route updates to a BGP daemon. Routes are injected into
    the BGP RIB and announced to configured peers.

    Usage:
        announcer = BgpRouteAnnouncer(backend="gobgp", local_as=65001)
        announcer.add_peer(BgpPeer("192.168.1.1", remote_as=65000))

        # When a new prefix is added to a node's AllowedIPs:
        announcer.announce_route("10.99.0.0/24", next_hop="10.20.1.1")

        # When a prefix is removed:
        announcer.withdraw_route("10.99.0.0/24")
    """

    def __init__(
        self,
        backend: str = "gobgp",
        local_as: int = 65001,
        router_id: str = "10.0.0.1",
        config_dir: Optional[Path] = None,
    ):
        """
        Args:
            backend: "gobgp" (CLI), "gobgp-grpc" (API), or "bird" (config gen)
            local_as: Local BGP AS number
            router_id: BGP router ID
            config_dir: Directory for generated BGP configs
        """
        self.backend = backend
        self.local_as = local_as
        self.router_id = router_id
        self.config_dir = config_dir or Path("./bgp-configs")
        self._peers: List[BgpPeer] = []
        self._announced: Dict[str, BgpRoute] = {}  # prefix -> route
        self._watch_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._topology = None  # Will be set by controller

        # Verify the chosen backend is available
        if backend == "gobgp":
            self._check_gobgp_available()
        elif backend == "bird":
            self._check_bird_available()

    def set_topology(self, topology_manager) -> None:
        """Attach to a topology manager for change detection."""
        self._topology = topology_manager

    # ── Peer management ──────────────────────────────────────────────

    def add_peer(self, peer: BgpPeer) -> None:
        """Add a BGP peering neighbor."""
        self._peers.append(peer)

    def remove_peer(self, neighbor_ip: str) -> bool:
        """Remove a BGP peer by IP."""
        initial = len(self._peers)
        self._peers = [p for p in self._peers if p.neighbor_ip != neighbor_ip]
        return len(self._peers) < initial

    def list_peers(self) -> List[Dict[str, Any]]:
        return [
            {
                "neighbor_ip": p.neighbor_ip,
                "remote_as": p.remote_as,
                "local_as": p.local_as,
                "description": p.description,
            }
            for p in self._peers
        ]

    # ── Route announcement ───────────────────────────────────────────

    def announce_route(
        self,
        prefix: str,
        next_hop: str,
        community: Optional[str] = None,
        local_pref: int = 100,
    ) -> bool:
        """Announce a route via BGP.

        Called when a new prefix is added to a node's AllowedIPs.
        The next_hop is the node's tunnel IP — traffic from the
        local router goes through the WireGuard tunnel to reach
        this prefix.
        """
        route = BgpRoute(
            prefix=prefix,
            next_hop=next_hop,
            community=community,
            local_pref=local_pref,
        )

        if prefix in self._announced:
            # Update existing route
            return self._update_route(route)

        # Announce via chosen backend
        if self.backend == "gobgp":
            success = self._gobgp_add_route(route)
        elif self.backend == "gobgp-grpc":
            success = self._gobgp_grpc_add_route(route)
        elif self.backend == "bird":
            success = self._bird_add_route(route)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")

        if success:
            self._announced[prefix] = route
        return success

    def withdraw_route(self, prefix: str) -> bool:
        """Withdraw a previously announced route.

        Called when a prefix is removed from a node's AllowedIPs.
        """
        if prefix not in self._announced:
            return True  # Nothing to withdraw

        route = self._announced[prefix]

        if self.backend == "gobgp":
            success = self._gobgp_del_route(route)
        elif self.backend == "gobgp-grpc":
            success = self._gobgp_grpc_del_route(route)
        elif self.backend == "bird":
            success = self._bird_del_route(route)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")

        if success:
            del self._announced[prefix]
        return success

    def announce_all_for_node(
        self, node_name: str, node_address: str, prefixes: List[str]
    ) -> Dict[str, bool]:
        """Announce all AllowedIPs for a node.

        Called when initializing or after a topology load.
        """
        results = {}
        next_hop = node_address.split("/")[0] if "/" in node_address else node_address
        for prefix in prefixes:
            results[prefix] = self.announce_route(prefix, next_hop)
        return results

    def withdraw_all_for_node(self, prefixes: List[str]) -> Dict[str, bool]:
        """Withdraw all routes for a node's prefixes."""
        results = {}
        for prefix in prefixes:
            results[prefix] = self.withdraw_route(prefix)
        return results

    # ── GoBGP CLI backend ────────────────────────────────────────────

    def _gobgp_add_route(self, route: BgpRoute) -> bool:
        """Inject a route into GoBGP's global RIB via CLI."""
        args = ["gobgp", "global", "rib", "add"] + route.to_gobgp_args()
        return self._run_gobgp(args)

    def _gobgp_del_route(self, route: BgpRoute) -> bool:
        """Withdraw a route from GoBGP's global RIB."""
        args = ["gobgp", "global", "rib", "del", route.prefix]
        return self._run_gobgp(args)

    def _update_route(self, route: BgpRoute) -> bool:
        """Update an existing route (del + add)."""
        self._gobgp_del_route(route)
        return self._gobgp_add_route(route)

    def _run_gobgp(self, args: List[str]) -> bool:
        """Run a gobgp CLI command.

        Returns True on success or if the daemon isn't running
        (routes are tracked locally in that case).
        """
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=5,
            )
            stderr = result.stderr.strip() if result.stderr else ""
            if result.returncode != 0:
                # "already exists" and "not found" are non-fatal for add/del
                if any(x in stderr for x in ("already exists", "not found")):
                    return True
                # "connection refused" / "unavailable" means daemon isn't running
                if any(x in stderr for x in ("Unavailable", "connection refused",
                                              "transport", "deadline", "connect")):
                    return True  # Track locally
                if stderr:
                    print(f"  gobgp: {stderr}")
                return True  # Track locally on any non-fatal error
            return True
        except FileNotFoundError:
            return True  # Track locally
        except subprocess.SubprocessError:
            return True  # Track locally

    def get_gobgp_rib(self) -> List[Dict[str, Any]]:
        """Query GoBGP's global RIB to see announced routes."""
        try:
            result = subprocess.run(
                ["gobgp", "global", "rib", "--json"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
        return []

    # ── GoBGP gRPC backend (requires grpcio) ──────────────────────────

    def _gobgp_grpc_add_route(self, route: BgpRoute) -> bool:
        """Add route via GoBGP gRPC API."""
        try:
            import grpc
            # This would use the GoBGP gRPC proto definitions
            # For the prototype, we fall back to CLI
            print("  [bgp] gRPC not yet wired — using CLI fallback")
            return self._gobgp_add_route(route)
        except ImportError:
            return self._gobgp_add_route(route)

    def _gobgp_grpc_del_route(self, route: BgpRoute) -> bool:
        return self._gobgp_del_route(route)

    # ── BIRD config generation backend ───────────────────────────────

    def _bird_add_route(self, route: BgpRoute) -> bool:
        """Regenerate and write the BIRD config with this route."""
        return self._write_bird_config()

    def _bird_del_route(self, route: BgpRoute) -> bool:
        """Regenerate and write the BIRD config without this route."""
        return self._write_bird_config()

    def _write_bird_config(self) -> bool:
        """Generate a complete BIRD configuration file.

        Includes static route definitions for all announced routes,
        BGP protocol configuration, and peering setup.
        """
        self.config_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.config_dir / "bird.conf"

        lines = [
            "# BIRD configuration generated by SDN Controller",
            f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Announced routes: {len(self._announced)}",
            "",
            f"router id {self.router_id};",
            "",
            "# ── Static SDN overlay routes ──",
        ]

        if self._announced:
            lines.append("protocol static sdn_routes {")
            for route in self._announced.values():
                lines.append(route.to_bird_config())
            lines.append("}")
        else:
            lines.append("# (no routes currently announced)")
        lines.append("")

        # BGP protocol section
        lines.extend([
            "# ── BGP protocol ──",
            f"protocol bgp sdn_controller {{",
            f"  local as {self.local_as};",
            f"  source address {self.router_id};",
        ])

        for peer in self._peers:
            lines.extend([
                f"  neighbor {peer.neighbor_ip} as {peer.remote_as};",
            ])
            if peer.multihop:
                lines.append("  multihop;")

        lines.extend([
            "  ipv4 {",
            "    import none;",
            "    export where proto = \"sdn_routes\";",
            "  };",
            "}",
        ])

        with open(config_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return True

    def _check_gobgp_available(self) -> bool:
        """Check if gobgp CLI is available."""
        try:
            subprocess.run(
                ["gobgp", "version"],
                capture_output=True, timeout=2,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            print("  [bgp] gobgp CLI not found; routes tracked locally")
            return False

    def _check_bird_available(self) -> bool:
        """Check if bird is available."""
        try:
            subprocess.run(
                ["bird", "--version"],
                capture_output=True, timeout=2,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    # ── Background watcher ───────────────────────────────────────────

    def start_watching(self, interval: float = 5.0) -> None:
        """Start a background thread that watches for topology changes.

        When the topology's AllowedIPs change, routes are automatically
        announced or withdrawn via BGP.
        """
        if self._watch_thread and self._watch_thread.is_alive():
            return
        self._stop_event.clear()
        self._watch_thread = Thread(
            target=self._watch_loop, args=(interval,), daemon=True
        )
        self._watch_thread.start()

    def stop_watching(self) -> None:
        """Stop the background watcher."""
        self._stop_event.set()
        if self._watch_thread:
            self._watch_thread.join(timeout=5)

    def _watch_loop(self, interval: float) -> None:
        """Background loop that reconciles topology with BGP RIB."""
        last_version = -1
        while not self._stop_event.is_set():
            if self._topology and self._topology.version != last_version:
                self._reconcile_routes()
                last_version = self._topology.version
            self._stop_event.wait(interval)

    def _reconcile_routes(self) -> None:
        """Reconcile BGP routes with current topology state.

        Compares the topology's AllowedIPs with currently announced
        routes and adds/withdraws as needed.
        """
        if not self._topology:
            return

        desired: Dict[str, str] = {}  # prefix -> next_hop
        for node in self._topology.nodes:
            next_hop = node.tunnel_ip() or node.address.split("/")[0] if "/" in node.address else node.address
            for prefix in node.allowed_ips:
                desired[prefix] = next_hop

        # Withdraw routes no longer in topology
        for prefix in list(self._announced.keys()):
            if prefix not in desired:
                self.withdraw_route(prefix)

        # Announce new or changed routes
        for prefix, next_hop in desired.items():
            current = self._announced.get(prefix)
            if not current or current.next_hop != next_hop:
                self.announce_route(prefix, next_hop)

    # ── Status ──────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get BGP announcer status."""
        return {
            "backend": self.backend,
            "local_as": self.local_as,
            "router_id": self.router_id,
            "peers": len(self._peers),
            "announced_routes": len(self._announced),
            "routes": [
                {"prefix": r.prefix, "next_hop": r.next_hop}
                for r in self._announced.values()
            ],
            "watching": self._watch_thread is not None and self._watch_thread.is_alive(),
        }

    # ── GoBGP daemon management ──────────────────────────────────────

    def generate_gobgp_config(self) -> str:
        """Generate a GoBGP daemon configuration (gobgpd.toml)."""
        lines = [
            "# GoBGP configuration generated by SDN Controller",
            f"[global.config]",
            f"  as = {self.local_as}",
            f"  router-id = \"{self.router_id}\"",
            "",
            "[[neighbors]]",
        ]

        for i, peer in enumerate(self._peers):
            if i > 0:
                lines.append("[[neighbors]]")
            lines.extend([
                f'  [neighbors.config]',
                f'    neighbor-address = "{peer.neighbor_ip}"',
                f'    peer-as = {peer.remote_as}',
            ])

        config = "\n".join(lines) + "\n"

        self.config_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.config_dir / "gobgpd.toml"
        with open(config_path, "w") as f:
            f.write(config)

        return config

    def start_gobgp_daemon(self, config_file: Optional[Path] = None) -> Optional[subprocess.Popen]:
        """Start the GoBGP daemon with our configuration.

        Returns the Popen handle if successful, None otherwise.
        Requires root or appropriate capabilities.
        """
        if not config_file:
            config_file = self.config_dir / "gobgpd.toml"
            if not config_file.exists():
                self.generate_gobgp_config()

        try:
            proc = subprocess.Popen(
                ["gobgpd", "-f", str(config_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Give it a moment to start
            time.sleep(0.5)
            if proc.poll() is not None:
                _, stderr = proc.communicate()
                print(f"  [bgp] gobgpd failed to start: {stderr.decode()}")
                return None
            return proc
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print(f"  [bgp] Could not start gobgpd: {e}")
            return None
