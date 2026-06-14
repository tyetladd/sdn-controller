"""
Topology manager for SDN controller.

Manages the network topology including:
- Node lifecycle (add, remove, update)
- Tunnel lifecycle (create, remove, update links between nodes)
- Topology versioning and diffing
- Consistency validation
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
import json
import time

from common.config import (
    TopologyConfig, NodeConfig, TunnelConfig,
    PolicyRule, AmneziaObfuscation,
)
from common.keys import KeyManager
from common.net import AddressAllocator


@dataclass
class TopologySnapshot:
    """A point-in-time snapshot of the topology."""
    topology: TopologyConfig
    timestamp: float = field(default_factory=time.time)
    version: int = 0


class TopologyManager:
    """Central topology manager for the SDN.

    Maintains the authoritative state of the network topology,
    handles node and tunnel lifecycle, and provides query methods
    for the controller.
    """

    def __init__(
        self,
        topology: Optional[TopologyConfig] = None,
        key_manager: Optional[KeyManager] = None,
        bgp_announcer = None,  # Optional[BgpRouteAnnouncer]
    ):
        self._topology = topology or TopologyConfig(name="default")
        self._key_manager = key_manager or KeyManager()
        self._bgp = bgp_announcer
        self._allocator = AddressAllocator(
            network_cidr=self._topology.network_cidr
        )
        self._snapshots: List[TopologySnapshot] = []
        self._version = 0
        self._auto_assign_addresses()
        self._auto_assign_keys()

        # Announce initial routes via BGP if announcer is attached
        if self._bgp:
            self._bgp.set_topology(self)
            self._announce_all_routes()

    def _auto_assign_addresses(self) -> None:
        """Auto-assign tunnel IPs to nodes that don't have one.

        Uses 10.255.0.0/16 for tunnel endpoint addresses, allocating
        /24 subnets per logical grouping.
        """
        for node in self._topology.nodes:
            if not node.address:
                ip = self._allocator.allocate_ip(node.name)
                node.address = f"{ip}/32"

    def _auto_assign_keys(self) -> None:
        """Auto-generate Curve25519 key pairs for nodes without keys."""
        for node in self._topology.nodes:
            if not node.private_key:
                kp = self._key_manager.get_or_generate(node.name)
                node.private_key = kp.private_key
                node.public_key = kp.public_key

    def _announce_all_routes(self) -> None:
        """Announce all current AllowedIPs via BGP."""
        if not self._bgp:
            return
        for node in self._topology.nodes:
            if node.allowed_ips and node.address:
                self._bgp.announce_all_for_node(
                    node.name, node.address, node.allowed_ips
                )

    def attach_bgp(self, bgp_announcer) -> None:
        """Attach a BGP route announcer to this topology manager."""
        self._bgp = bgp_announcer
        self._bgp.set_topology(self)
        self._announce_all_routes()

    @property
    def name(self) -> str:
        return self._topology.name

    @property
    def nodes(self) -> List[NodeConfig]:
        return self._topology.nodes

    @property
    def tunnels(self) -> List[TunnelConfig]:
        return self._topology.tunnels

    @property
    def policies(self) -> List[PolicyRule]:
        return self._topology.policies

    @property
    def version(self) -> int:
        return self._version

    # ── Node management ──────────────────────────────────────────────

    def add_node(
        self,
        name: str,
        endpoint: Optional[str] = None,
        listen_port: int = 51820,
        address: Optional[str] = None,
        allowed_ips: Optional[List[str]] = None,
        obfuscation: Optional[AmneziaObfuscation] = None,
        private_key: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> NodeConfig:
        """Add a new node to the topology."""
        if self._topology.get_node(name):
            raise ValueError(f"Node '{name}' already exists")

        # Generate keys if not provided
        if not private_key:
            keypair = self._key_manager.get_or_generate(name)
            private_key = keypair.private_key
            public_key = keypair.public_key
        else:
            kp = self._key_manager.get_or_generate(name)
            public_key = kp.public_key

        # Allocate tunnel IP if not specified
        if not address:
            ip = self._allocator.allocate_ip(name)
            address = f"{ip}/24"

        node = NodeConfig(
            name=name,
            endpoint=endpoint,
            listen_port=listen_port,
            private_key=private_key,
            public_key=public_key,
            address=address,
            allowed_ips=allowed_ips or [],
            obfuscation=obfuscation or AmneziaObfuscation(),
            tags=tags or {},
        )
        self._topology.nodes.append(node)
        self._bump_version()
        return node

    def remove_node(self, name: str) -> bool:
        """Remove a node and all its tunnels from the topology."""
        node = self._topology.get_node(name)
        if not node:
            return False

        # Remove all tunnels involving this node
        self._topology.tunnels = [
            t for t in self._topology.tunnels
            if t.source_node != name and t.target_node != name
        ]

        # Remove the node
        self._topology.nodes = [
            n for n in self._topology.nodes if n.name != name
        ]

        # Release IP
        if node.address:
            try:
                import ipaddress
                ip = ipaddress.ip_address(
                    node.address.split("/")[0]
                )
                self._allocator.release_ip(ip)
            except ValueError:
                pass

        self._key_manager.remove_key(name)
        self._bump_version()
        return True

    def get_node(self, name: str) -> Optional[NodeConfig]:
        return self._topology.get_node(name)

    def list_nodes(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": n.name,
                "address": n.address,
                "endpoint": n.endpoint,
                "public_key": n.public_key,
                "allowed_ips": n.allowed_ips,
                "peer_count": len(
                    self._topology.get_peers_for_node(n.name)
                ),
                "obfuscation_enabled": n.obfuscation.enabled,
                "tags": n.tags,
            }
            for n in self._topology.nodes
        ]

    # ── Tunnel management ────────────────────────────────────────────

    def create_tunnel(
        self,
        source_node: str,
        target_node: str,
        metric: int = 1,
        obfuscation: Optional[AmneziaObfuscation] = None,
    ) -> TunnelConfig:
        """Create a tunnel between two nodes."""
        if source_node == target_node:
            raise ValueError("Source and target nodes must be different")

        src = self._topology.get_node(source_node)
        if not src:
            raise ValueError(f"Source node '{source_node}' not found")

        dst = self._topology.get_node(target_node)
        if not dst:
            raise ValueError(f"Target node '{target_node}' not found")

        # Check for duplicate
        for existing in self._topology.tunnels:
            if (
                existing.source_node == source_node
                and existing.target_node == target_node
            ) or (
                existing.source_node == target_node
                and existing.target_node == source_node
            ):
                raise ValueError(
                    f"Tunnel between '{source_node}' and '{target_node}' "
                    f"already exists"
                )

        tunnel = TunnelConfig(
            name=f"{source_node}-{target_node}",
            source_node=source_node,
            target_node=target_node,
            source_address=src.tunnel_ip() or src.address,
            target_address=dst.tunnel_ip() or dst.address,
            metric=metric,
            obfuscation=obfuscation,
        )
        self._topology.tunnels.append(tunnel)
        self._bump_version()
        return tunnel

    def remove_tunnel(self, source_node: str, target_node: str) -> bool:
        """Remove a tunnel between two nodes."""
        initial_count = len(self._topology.tunnels)
        self._topology.tunnels = [
            t for t in self._topology.tunnels
            if not (
                (t.source_node == source_node and t.target_node == target_node)
                or (t.source_node == target_node and t.target_node == source_node)
            )
        ]
        removed = len(self._topology.tunnels) < initial_count
        if removed:
            self._bump_version()
        return removed

    def list_tunnels(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._topology.tunnels]

    # ── Runtime reconfiguration ──────────────────────────────────────

    def update_node_allowed_ips(
        self, node_name: str, allowed_ips: List[str]
    ) -> Dict[str, Any]:
        """Update a node's AllowedIPs and return the diff for peer updates.

        When a remote gateway gets a new prefix, call this to update
        its AllowedIPs. It returns the list of peers that need their
        WireGuard configs updated — without tearing down any tunnels.

        Returns a dict with:
          - node: updated node name
          - added: new prefixes
          - removed: removed prefixes
          - current: full AllowedIPs list
          - peers_to_update: list of {peer_name, peer_pubkey, new_allowed_ips}
        """
        node = self._topology.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")

        old_ips = set(node.allowed_ips)
        new_ips = set(allowed_ips)

        added = list(new_ips - old_ips)
        removed = list(old_ips - new_ips)

        # Update the node's AllowedIPs
        node.allowed_ips = allowed_ips

        # Find all peers that need updating — every node that has a
        # tunnel TO this node needs to update their [Peer] section
        peers_to_update = []
        for tunnel in self._topology.tunnels:
            peer_name = None
            if tunnel.source_node == node_name:
                peer_name = tunnel.target_node
            elif tunnel.target_node == node_name:
                peer_name = tunnel.source_node

            if peer_name:
                peer = self._topology.get_node(peer_name)
                if peer:
                    # The peer's AllowedIPs for this node = node.added_ips + node.address
                    peer_allowed = [node.address] + allowed_ips if node.address else list(allowed_ips)
                    peers_to_update.append({
                        "peer_name": peer_name,
                        "peer_public_key": peer.public_key,
                        "peer_endpoint": peer.endpoint,
                        "new_allowed_ips_for_this_node": peer_allowed,
                    })

        # Notify BGP announcer of prefix changes
        if self._bgp:
            next_hop = node.tunnel_ip() or (
                node.address.split("/")[0] if "/" in node.address else node.address
            )
            for prefix in removed:
                self._bgp.withdraw_route(prefix)
            for prefix in added:
                self._bgp.announce_route(prefix, next_hop)

        self._bump_version()
        return {
            "node": node_name,
            "added": added,
            "removed": removed,
            "current": allowed_ips,
            "peers_to_update": peers_to_update,
        }

    def add_node_prefix(self, node_name: str, prefix: str) -> Dict[str, Any]:
        """Add a single prefix to a node's AllowedIPs (live update).

        Example: a remote gateway is now advertising 10.99.0.0/24.
        Call add_node_prefix('spoke-1', '10.99.0.0/24') and all
        peers will be told to route that prefix through this node.
        """
        node = self._topology.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")

        if prefix in node.allowed_ips:
            return self.update_node_allowed_ips(node_name, node.allowed_ips)

        new_ips = list(node.allowed_ips) + [prefix]
        return self.update_node_allowed_ips(node_name, new_ips)

    def remove_node_prefix(self, node_name: str, prefix: str) -> Dict[str, Any]:
        """Remove a single prefix from a node's AllowedIPs (live update)."""
        node = self._topology.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")

        new_ips = [ip for ip in node.allowed_ips if ip != prefix]
        return self.update_node_allowed_ips(node_name, new_ips)

    # ── Policy management ────────────────────────────────────────────

    def add_policy(
        self,
        name: str,
        source: str,
        destination: str,
        action: str = "allow",
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        priority: int = 100,
    ) -> PolicyRule:
        """Add an access control policy."""
        rule = PolicyRule(
            name=name,
            source=source,
            destination=destination,
            action=action,
            port=port,
            protocol=protocol,
            priority=priority,
        )
        self._topology.policies.append(rule)
        self._bump_version()
        return rule

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name."""
        initial = len(self._topology.policies)
        self._topology.policies = [
            p for p in self._topology.policies if p.name != name
        ]
        removed = len(self._topology.policies) < initial
        if removed:
            self._bump_version()
        return removed

    def list_policies(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._topology.policies]

    # ── Queries ──────────────────────────────────────────────────────

    def get_node_peers(self, node_name: str) -> List[NodeConfig]:
        """Get all peers for a given node."""
        tunnels = self._topology.get_peers_for_node(node_name)
        peers = []
        for tunnel in tunnels:
            peer_name = (
                tunnel.target_node
                if tunnel.source_node == node_name
                else tunnel.source_node
            )
            peer = self._topology.get_node(peer_name)
            if peer:
                peers.append(peer)
        return peers

    def get_node_tunnel_count(self, node_name: str) -> int:
        return len(self._topology.get_tunnels_for_node(node_name))

    def is_connected(self) -> bool:
        """Check if the topology graph is fully connected.

        Uses DFS to verify all nodes are reachable from the first node.
        """
        if len(self._topology.nodes) <= 1:
            return True

        # Build adjacency list
        adj: Dict[str, Set[str]] = {
            n.name: set() for n in self._topology.nodes
        }
        for tunnel in self._topology.tunnels:
            adj[tunnel.source_node].add(tunnel.target_node)
            adj[tunnel.target_node].add(tunnel.source_node)

        # DFS from first node
        start = self._topology.nodes[0].name
        visited = set()

        def dfs(node: str):
            visited.add(node)
            for neighbor in adj.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor)

        dfs(start)
        return len(visited) == len(self._topology.nodes)

    def get_topology_summary(self) -> Dict[str, Any]:
        """Get a summary of the current topology."""
        connected = self.is_connected()
        return {
            "name": self._topology.name,
            "version": self._version,
            "node_count": len(self._topology.nodes),
            "tunnel_count": len(self._topology.tunnels),
            "policy_count": len(self._topology.policies),
            "connected": connected,
            "network_cidr": self._topology.network_cidr,
            "obfuscation_enabled": self._topology.obfuscation_enabled,
        }

    # ── State management ─────────────────────────────────────────────

    def snapshot(self) -> TopologySnapshot:
        """Create a point-in-time snapshot of current topology."""
        snap = TopologySnapshot(
            topology=self._topology,
            timestamp=time.time(),
            version=self._version,
        )
        self._snapshots.append(snap)
        return snap

    def export(self) -> Dict[str, Any]:
        """Export the full topology as a dictionary."""
        return self._topology.to_dict()

    def import_from_dict(self, data: Dict[str, Any]) -> None:
        """Import topology from dictionary."""
        self._topology = TopologyConfig.from_dict(data)
        self._allocator = AddressAllocator(
            network_cidr=self._topology.network_cidr
        )
        self._version = 0
        self._auto_assign_addresses()

    def save(self, path: Path) -> None:
        """Save topology to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.export(), f, indent=2)

    def load(self, path: Path) -> None:
        """Load topology from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        self.import_from_dict(data)

    def _bump_version(self) -> None:
        self._version += 1

    def to_config(self) -> TopologyConfig:
        """Return the underlying TopologyConfig."""
        return self._topology
