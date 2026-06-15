"""
VXLAN Overlay Manager — L2 overlay on top of WireGuard tunnels.

VXLAN (RFC 7348) creates a virtual Layer 2 network over a Layer 3 underlay.
When layered on top of WireGuard, VXLAN dramatically reduces management
overhead: WireGuard AllowedIPs only need to carry the VXLAN tunnel endpoint
IPs (fixed, per-node). All behind-node subnets are routed within VXLAN.

Architecture:

    ┌──────────────────────────────────────────────────┐
    │                VXLAN Overlay (172.30.0.0/16)      │
    │                                                   │
    │   Node A         Node B         Node C            │
    │   .1             .2             .3                │
    │   │192.168.1/24  │192.168.2/24 │192.168.3/24     │
    │   │10.99/24     │10.88/16     │172.31/16         │
    └───┼──────────────┼──────────────┼─────────────────┘
        │              │              │
    ┌───┼──────────────┼──────────────┼─────────────────┐
    │   │ WireGuard tunnels (encrypted underlay)         │
    │   │                                               │
    │   Node A ───────── Node B ───────── Node C         │
    │   10.20.1.1        10.20.2.1        10.20.3.1      │
    └───────────────────────────────────────────────────┘

Benefits over AllowedIPs-only approach:
- Adding a subnet behind a node: 0 WireGuard config changes
- AllowedIPs per peer is fixed (just the peer's VXLAN endpoint IP)
- VXLAN creates a single broadcast domain — ARP/ND works natively
- BGP within VXLAN distributes subnet routes without the controller
- New nodes join the VXLAN segment, exchange routes, done

Implementation:
- Static FDB entries (no multicast needed — we know all tunnel endpoints)
- Each node gets a vxlan interface with a /24 address in the VXLAN subnet
- FDB maps remote VXLAN IPs to remote WireGuard tunnel IPs
- The controller generates per-node setup scripts + FDB entries
"""

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

from common.config import TopologyConfig, NodeConfig, TunnelConfig


@dataclass
class VxlanConfig:
    """VXLAN overlay configuration."""
    vni: int = 100
    vxlan_network: str = "172.30.0.0/16"
    vxlan_subnet_prefix: int = 24
    mtu: int = 1400           # 1420(WG) - 50(VXLAN encap) - 20(IP) margin
    dst_port: int = 4789       # IANA standard VXLAN port
    fdb_mode: str = "static"   # static (unicast FDB) or multicast

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vni": self.vni,
            "vxlan_network": self.vxlan_network,
            "vxlan_subnet_prefix": self.vxlan_subnet_prefix,
            "mtu": self.mtu,
            "dst_port": self.dst_port,
            "fdb_mode": self.fdb_mode,
        }


@dataclass
class VxlanNodeEntry:
    """Per-node VXLAN configuration."""
    node_name: str
    vxlan_ip: str             # IP on the VXLAN interface (e.g., 172.30.0.1/24)
    wg_tunnel_ip: str         # WireGuard tunnel IP (underlay destination for VXLAN)
    fdb_entries: List[Dict[str, str]] = field(default_factory=list)
    # fdb_entries: [{mac: "aa:bb:...", dst: "10.20.2.1"}, ...]


class VxlanOverlayManager:
    """Manages VXLAN overlay on top of WireGuard tunnels.

    Assigns VXLAN IPs to nodes, builds the FDB (Forwarding Database),
    and generates per-node setup scripts or configuration.

    The FDB maps remote VXLAN endpoint IPs to their underlying
    WireGuard tunnel IPs. Since we know the full topology, we use
    static FDB entries — no multicast or head-end replication needed.
    """

    def __init__(
        self,
        topology: TopologyConfig,
        vxlan_config: Optional[VxlanConfig] = None,
    ):
        self.topology = topology
        self.vxlan_config = vxlan_config or VxlanConfig()
        self._vxlan_network = ipaddress.ip_network(
            self.vxlan_config.vxlan_network, strict=False
        )
        self._node_entries: Dict[str, VxlanNodeEntry] = {}
        self._assign_vxlan_ips()

    def _assign_vxlan_ips(self) -> None:
        """Assign each node an IP in the VXLAN subnet."""
        # Use the last /24 of the VXLAN network for endpoint IPs
        vxlan_subnet = list(self._vxlan_network.subnets(
            new_prefix=self.vxlan_config.vxlan_subnet_prefix
        ))[0]

        host_ips = list(vxlan_subnet.hosts())
        for i, node in enumerate(self.topology.nodes):
            if i >= len(host_ips):
                raise RuntimeError(
                    f"VXLAN subnet {vxlan_subnet} too small for "
                    f"{len(self.topology.nodes)} nodes"
                )
            vxlan_ip = str(host_ips[i])
            wg_ip = node.tunnel_ip() or (
                node.address.split("/")[0] if "/" in node.address
                else node.address
            )

            self._node_entries[node.name] = VxlanNodeEntry(
                node_name=node.name,
                vxlan_ip=f"{vxlan_ip}/{self.vxlan_config.vxlan_subnet_prefix}",
                wg_tunnel_ip=wg_ip,
            )

    def build_fdb(self) -> Dict[str, List[Dict[str, str]]]:
        """Build the static FDB for each node.

        Returns: {node_name: [{vxlan_ip, mac, dst_wg_ip}, ...]}

        Each node needs an FDB entry for every OTHER node, mapping
        the remote VXLAN IP to the remote WireGuard tunnel IP.
        Traffic to a VXLAN IP is encapsulated and sent unicast to
        the destination's WireGuard tunnel IP.
        """
        fdb = {}
        for node_name, entry in self._node_entries.items():
            entries = []
            for other_name, other_entry in self._node_entries.items():
                if other_name == node_name:
                    continue
                other_vxlan_ip = other_entry.vxlan_ip.split("/")[0]
                entries.append({
                    "vxlan_ip": other_vxlan_ip,
                    "dst_wg_ip": other_entry.wg_tunnel_ip,
                    "mac": self._derive_vxlan_mac(other_vxlan_ip),
                })
            entry.fdb_entries = entries
            fdb[node_name] = entries
        return fdb

    @staticmethod
    def _derive_vxlan_mac(vxlan_ip: str) -> str:
        """Derive a deterministic VXLAN MAC from the VXLAN IP.

        Uses the standard pattern: 02:00:XX:XX:XX:XX from the IP bytes.
        """
        parts = vxlan_ip.split(".")
        if len(parts) == 4:
            return f"02:00:{int(parts[0]):02x}:{int(parts[1]):02x}:{int(parts[2]):02x}:{int(parts[3]):02x}"
        return "02:00:00:00:00:00"

    def get_node_entry(self, node_name: str) -> Optional[VxlanNodeEntry]:
        return self._node_entries.get(node_name)

    def list_nodes(self) -> List[Dict[str, Any]]:
        return [
            {
                "node": e.node_name,
                "vxlan_ip": e.vxlan_ip,
                "wg_tunnel_ip": e.wg_tunnel_ip,
                "fdb_entries": len(e.fdb_entries),
            }
            for e in self._node_entries.values()
        ]

    # ── Config generation ──────────────────────────────────────────

    def generate_setup_script(self, node_name: str) -> str:
        """Generate a bash script to set up VXLAN on a node.

        Creates the vxlan interface, adds FDB entries, assigns the IP,
        and brings the interface up. Run once on each node after
        WireGuard tunnels are established.
        """
        entry = self._node_entries.get(node_name)
        if not entry:
            raise ValueError(f"Node '{node_name}' not found")

        vxlan_ip_raw = entry.vxlan_ip.split("/")[0]
        cfg = self.vxlan_config

        lines = [
            "#!/bin/bash",
            f"# VXLAN overlay setup for {node_name}",
            f"# Generated by SDN Controller",
            f"# VNI: {cfg.vni}, Network: {cfg.vxlan_network}",
            "",
            f"VXLAN_IF=\"vxlan{cfg.vni}\"",
            f"VXLAN_IP=\"{vxlan_ip_raw}/{cfg.vxlan_subnet_prefix}\"",
            "",
            "# Remove existing interface if present",
            f"ip link del $VXLAN_IF 2>/dev/null || true",
            "",
            f"# Create VXLAN interface",
            f"# - Uses unicast FDB (no multicast) since we know all peers",
            f"ip link add $VXLAN_IF type vxlan \\",
            f"    id {cfg.vni} \\",
            f"    dstport {cfg.dst_port} \\",
            f"    local {entry.wg_tunnel_ip} \\",
            f"    nolearning \\",
            f"    mtu {cfg.mtu}",
            "",
            "# Assign IP",
            f"ip addr add $VXLAN_IP dev $VXLAN_IF",
            "",
            "# Add static FDB entries (map remote VXLAN IP → remote WG IP)",
        ]

        for fdb_entry in entry.fdb_entries:
            lines.extend([
                f"bridge fdb append {fdb_entry['mac']} "
                f"dev $VXLAN_IF dst {fdb_entry['dst_wg_ip']}",
            ])

        lines.extend([
            "",
            "# Bring up the interface",
            "ip link set $VXLAN_IF up",
            "",
            f"echo \"VXLAN interface $VXLAN_IF up: $VXLAN_IP\"",
        ])

        return "\n".join(lines) + "\n"

    def generate_vxlan_routes(self, node_name: str) -> List[str]:
        """Generate routes for behind-node subnets within the VXLAN.

        Each route sends traffic for a node's AllowedIPs subnets
        through the VXLAN interface to the node's VXLAN IP.

        These are LOCAL routes only — BGP between nodes can
        distribute them automatically, avoiding manual updates.
        """
        entry = self._node_entries.get(node_name)
        if not entry:
            return []

        routes = []
        for node in self.topology.nodes:
            if node.name == node_name:
                continue
            remote_entry = self._node_entries.get(node.name)
            if not remote_entry:
                continue
            remote_vxlan_ip = remote_entry.vxlan_ip.split("/")[0]

            for prefix in node.allowed_ips:
                routes.append(
                    f"ip route add {prefix} via {remote_vxlan_ip} "
                    f"dev vxlan{self.vxlan_config.vni} "
                    f"# {node.name}"
                )
        return routes

    def generate_all_setup_scripts(
        self, output_dir: Path
    ) -> Dict[str, Path]:
        """Generate VXLAN setup scripts for all nodes."""
        output_dir.mkdir(parents=True, exist_ok=True)
        written = {}
        for node_name in self._node_entries:
            script = self.generate_setup_script(node_name)
            path = output_dir / f"vxlan-setup-{node_name}.sh"
            with open(path, "w") as f:
                f.write(script)
            path.chmod(0o755)
            written[node_name] = path
        return written

    def generate_wg_config_with_vxlan(
        self, node_name: str, base_wg_config: str
    ) -> str:
        """Augment a WireGuard config with VXLAN setup commands.

        Adds PreUp/PostUp/PreDown commands to the [Interface] section
        so VXLAN is created/destroyed with the WireGuard interface.

        The WireGuard AllowedIPs for peers should only include the
        peer's VXLAN tunnel IP (/32), NOT all their behind-subnets.
        """
        entry = self._node_entries.get(node_name)
        if not entry:
            return base_wg_config

        vxlan_if = f"vxlan{self.vxlan_config.vni}"
        vxlan_ip_raw = entry.vxlan_ip.split("/")[0]

        # Build PreUp/PostUp/PreDown/PostDown commands
        pre_up = [
            f"ip link del {vxlan_if} 2>/dev/null || true",
            f"ip link add {vxlan_if} type vxlan "
            f"id {self.vxlan_config.vni} "
            f"dstport {self.vxlan_config.dst_port} "
            f"local {entry.wg_tunnel_ip} "
            f"nolearning "
            f"mtu {self.vxlan_config.mtu}",
        ]
        for fdb_entry in entry.fdb_entries:
            pre_up.append(
                f"bridge fdb append {fdb_entry['mac']} "
                f"dev {vxlan_if} dst {fdb_entry['dst_wg_ip']}"
            )

        post_up = [
            f"ip addr add {entry.vxlan_ip} dev {vxlan_if}",
            f"ip link set {vxlan_if} up",
        ]
        # Add routes for behind-node subnets within VXLAN
        for node in self.topology.nodes:
            if node.name == node_name:
                continue
            remote = self._node_entries.get(node.name)
            if not remote:
                continue
            remote_ip = remote.vxlan_ip.split("/")[0]
            for prefix in node.allowed_ips:
                post_up.append(
                    f"ip route add {prefix} via {remote_ip} dev {vxlan_if}"
                )

        pre_down = [f"ip link set {vxlan_if} down"]
        post_down = [f"ip link del {vxlan_if} 2>/dev/null || true"]

        # Inject into WG config
        lines = base_wg_config.strip().split("\n")
        result = []
        interface_section = True

        for line in lines:
            result.append(line)
            # Inject PreUp/PostUp before first [Peer], right after Interface
            if interface_section and line.startswith("[Peer]"):
                interface_section = False
                for cmd in pre_up:
                    result.insert(-1, f"PreUp = {cmd}")
                for cmd in post_up:
                    result.insert(-1, f"PostUp = {cmd}")
                for cmd in pre_down:
                    result.insert(-1, f"PreDown = {cmd}")
                for cmd in post_down:
                    result.insert(-1, f"PostDown = {cmd}")

        return "\n".join(result)

    def get_status(self) -> Dict[str, Any]:
        return {
            "vni": self.vxlan_config.vni,
            "vxlan_network": self.vxlan_config.vxlan_network,
            "node_count": len(self._node_entries),
            "mtu": self.vxlan_config.mtu,
            "fdb_mode": self.vxlan_config.fdb_mode,
            "nodes": self.list_nodes(),
        }
