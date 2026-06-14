"""
Tunnel configuration generator for WireGuard and AmneziaWG.

Generates per-node WireGuard/AmneziaWG configuration files compatible
with wg-quick and the AmneziaWG fork. Handles:

- Standard WireGuard config generation
- AmneziaWG-obfuscated config generation
- Peer endpoint configuration
- Routing table setup (AllowedIPs)
- Pre-shared key support for post-quantum resistance
"""

import os
import base64
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

from common.config import (
    TopologyConfig, NodeConfig, TunnelConfig,
    AmneziaObfuscation,
)


@dataclass
class GeneratedPeerConfig:
    """A generated peer section for a WireGuard config."""
    public_key: str
    endpoint: Optional[str] = None
    allowed_ips: List[str] = None
    persistent_keepalive: int = 25
    preshared_key: Optional[str] = None

    def __post_init__(self):
        if self.allowed_ips is None:
            self.allowed_ips = []


@dataclass
class GeneratedNodeConfig:
    """Complete generated config for one node."""
    node_name: str
    private_key: str
    address: str
    listen_port: int
    mtu: int = 1420
    dns: Optional[List[str]] = None
    peers: List[GeneratedPeerConfig] = None
    # AmneziaWG-specific
    obfuscation: Optional[Dict[str, Any]] = None
    # Firewall rules
    pre_up: Optional[List[str]] = None
    post_up: Optional[List[str]] = None
    pre_down: Optional[List[str]] = None
    post_down: Optional[List[str]] = None

    def __post_init__(self):
        if self.peers is None:
            self.peers = []


class TunnelConfigGenerator:
    """Generates WireGuard/AmneziaWG configuration files from topology.

    Supports both standard WireGuard configs (wg-quick compatible) and
    AmneziaWG-obfuscated configs that include DPI evasion parameters.

    Output formats:
    - Native WG config (INI-style, wg-quick compatible)
    - AmneziaWG config (extends WG config with obfuscation sections)
    - JSON representation for API consumption
    """

    # AmneziaWG default obfuscation values
    DEFAULT_JUNK_COUNT = 5
    DEFAULT_JUNK_MIN = 40
    DEFAULT_JUNK_MAX = 80
    DEFAULT_PERSISTENT_KEEPALIVE = 25

    def __init__(self, topology: TopologyConfig):
        self.topology = topology

    def generate_all_configs(self) -> Dict[str, GeneratedNodeConfig]:
        """Generate configs for all nodes in the topology."""
        configs = {}
        for node in self.topology.nodes:
            configs[node.name] = self.generate_node_config(node.name)
        return configs

    def generate_node_config(self, node_name: str) -> GeneratedNodeConfig:
        """Generate the full WireGuard config for a specific node."""
        node = self.topology.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found in topology")

        # Build peer list from tunnels
        peers = []
        for tunnel in self.topology.get_peers_for_node(node_name):
            peer_name = tunnel.target_node
            peer_node = self.topology.get_node(peer_name)
            if not peer_node:
                continue

            # Collect AllowedIPs for this peer
            allowed_ips = []
            if peer_node.address:
                allowed_ips.append(peer_node.address)
            allowed_ips.extend(peer_node.allowed_ips)

            peer_config = GeneratedPeerConfig(
                public_key=peer_node.public_key or "",
                endpoint=peer_node.endpoint,
                allowed_ips=allowed_ips,
                persistent_keepalive=self.DEFAULT_PERSISTENT_KEEPALIVE,
            )
            peers.append(peer_config)

        # Build AmneziaWG obfuscation section if enabled
        obfuscation = None
        if node.obfuscation.enabled:
            obfuscation = self._build_obfuscation_section(node.obfuscation)
        elif self.topology.default_obfuscation and self.topology.default_obfuscation.enabled:
            obfuscation = self._build_obfuscation_section(
                self.topology.default_obfuscation
            )

        # Build pre-up / post-up rules
        pre_up = []
        post_up = []
        pre_down = []
        post_down = []

        if self.topology.policies:
            post_up, pre_down = self._build_firewall_rules(
                node, self.topology.policies
            )

        return GeneratedNodeConfig(
            node_name=node_name,
            private_key=node.private_key or "",
            address=node.address,
            listen_port=node.listen_port,
            mtu=self.topology.mtu,
            peers=peers,
            obfuscation=obfuscation,
            pre_up=pre_up or None,
            post_up=post_up or None,
            pre_down=pre_down or None,
            post_down=post_down or None,
        )

    def render_wg_quick_config(
        self, node_config: GeneratedNodeConfig
    ) -> str:
        """Render a wg-quick compatible INI configuration file.

        Output follows the standard WireGuard config format:
        [Interface] section with keys/address/port
        [Peer] sections for each connected peer
        """
        lines = []

        # [Interface] section
        lines.append("[Interface]")
        lines.append(f"PrivateKey = {node_config.private_key}")
        lines.append(f"Address = {node_config.address}")
        lines.append(f"ListenPort = {node_config.listen_port}")
        lines.append(f"MTU = {node_config.mtu}")

        if node_config.dns:
            lines.append(f"DNS = {', '.join(node_config.dns)}")

        # Pre/Post commands
        for cmd in (node_config.pre_up or []):
            lines.append(f"PreUp = {cmd}")
        for cmd in (node_config.post_up or []):
            lines.append(f"PostUp = {cmd}")
        for cmd in (node_config.pre_down or []):
            lines.append(f"PreDown = {cmd}")
        for cmd in (node_config.post_down or []):
            lines.append(f"PostDown = {cmd}")

        lines.append("")

        # [Peer] sections
        for peer in node_config.peers:
            lines.append("[Peer]")
            lines.append(f"PublicKey = {peer.public_key}")
            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")
            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")
            if peer.allowed_ips:
                lines.append(
                    f"AllowedIPs = {', '.join(peer.allowed_ips)}"
                )
            if peer.persistent_keepalive:
                lines.append(
                    f"PersistentKeepalive = {peer.persistent_keepalive}"
                )
            lines.append("")

        return "\n".join(lines)

    def render_amneziawg_config(
        self, node_config: GeneratedNodeConfig
    ) -> str:
        """Render an AmneziaWG configuration with obfuscation.

        AmneziaWG extends the standard WireGuard config with additional
        [Amnezia] sections and obfuscation parameters in the [Interface]
        and [Peer] sections.
        """
        base_config = self.render_wg_quick_config(node_config)

        if not node_config.obfuscation:
            return base_config

        # Insert AmneziaWG obfuscation parameters
        obs = node_config.obfuscation
        extra_lines = []

        # Add JunkPacket* settings to [Interface] section
        if obs.get("Jc", 0) > 0:
            extra_lines.append(f"JunkPacketCount = {obs['Jc']}")
            extra_lines.append(f"JunkPacketMinSize = {obs.get('Jmin', 40)}")
            extra_lines.append(f"JunkPacketMaxSize = {obs.get('Jmax', 80)}")

        if obs.get("S1"):
            extra_lines.append(f"InitPacketJunk = {obs['S1']}")
        if obs.get("S2"):
            extra_lines.append(f"ResponsePacketJunk = {obs['S2']}")

        # Inject after the [Interface] section, before first [Peer]
        if extra_lines:
            # Find insertion point: after the Interface section, before Peer
            interface_end = base_config.find("\n[Peer]")
            if interface_end == -1:
                interface_end = len(base_config)
            prefix = base_config[:interface_end]
            suffix = base_config[interface_end:]

            obs_block = "\n".join(extra_lines)
            base_config = f"{prefix}\n{obs_block}\n{suffix}"

        return base_config

    def render_json_config(
        self, node_config: GeneratedNodeConfig
    ) -> Dict[str, Any]:
        """Render configuration as a JSON-serializable dictionary."""
        config = {
            "interface": {
                "private_key": node_config.private_key,
                "address": node_config.address,
                "listen_port": node_config.listen_port,
                "mtu": node_config.mtu,
                "dns": node_config.dns,
                "pre_up": node_config.pre_up,
                "post_up": node_config.post_up,
                "pre_down": node_config.pre_down,
                "post_down": node_config.post_down,
            },
            "peers": [
                {
                    "public_key": p.public_key,
                    "endpoint": p.endpoint,
                    "allowed_ips": p.allowed_ips,
                    "persistent_keepalive": p.persistent_keepalive,
                    "preshared_key": p.preshared_key,
                }
                for p in node_config.peers
            ],
        }
        if node_config.obfuscation:
            config["obfuscation"] = node_config.obfuscation
        return config

    def write_all_configs(
        self, output_dir: Path, format: str = "wg-quick"
    ) -> Dict[str, Path]:
        """Write config files for all nodes to disk.

        Args:
            output_dir: Directory to write configs
            format: 'wg-quick', 'amneziawg', or 'json'

        Returns:
            Dict mapping node_name -> config file path
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        configs = self.generate_all_configs()
        written = {}

        for node_name, node_config in configs.items():
            if format == "amneziawg":
                content = self.render_amneziawg_config(node_config)
                ext = ".awg.conf"
            elif format == "json":
                import json
                content = json.dumps(
                    self.render_json_config(node_config), indent=2
                )
                ext = ".json"
            else:
                content = self.render_wg_quick_config(node_config)
                ext = ".conf"

            filepath = output_dir / f"{node_name}{ext}"
            with open(filepath, "w") as f:
                f.write(content)
            written[node_name] = filepath

        return written

    def _build_obfuscation_section(
        self, obf: AmneziaObfuscation
    ) -> Dict[str, Any]:
        """Build AmneziaWG obfuscation parameter dict."""
        section: Dict[str, Any] = {"enabled": True}
        if obf.junk_packet_count > 0:
            section["Jc"] = obf.junk_packet_count
            section["Jmin"] = obf.junk_packet_min_size
            section["Jmax"] = obf.junk_packet_max_size
        if obf.init_packet_junk:
            section["S1"] = obf.init_packet_junk
        if obf.response_packet_junk:
            section["S2"] = obf.response_packet_junk
        if obf.header_obfuscation_keys:
            section["H"] = obf.header_obfuscation_keys
        return section

    def _build_firewall_rules(
        self,
        node: NodeConfig,
        policies: List[Any],
    ) -> tuple:
        """Build iptables/nftables rules from policies.

        Returns (post_up_rules, pre_down_rules) as lists of strings.
        Uses iptables commands to implement policy-based access control
        on the WireGuard interface (wg0).
        """
        post_up = []
        pre_down = []

        for policy in policies:
            if policy.action == "allow":
                # Allow traffic from source to destination
                rule = self._policy_to_iptables(policy, node)
                if rule:
                    post_up.append(rule)
                    # Cleanup on down
                    pre_down.append(rule.replace("-A", "-D", 1))
            elif policy.action == "deny":
                # Deny traffic and log
                rule = self._policy_to_iptables(policy, node, deny=True)
                if rule:
                    post_up.append(rule)
                    pre_down.append(rule.replace("-A", "-D", 1))

        return post_up, pre_down

    def _policy_to_iptables(
        self, policy: Any, node: NodeConfig, deny: bool = False
    ) -> Optional[str]:
        """Convert a policy rule to an iptables command."""
        # Determine if this policy applies to this node
        if policy.source not in (node.name, node.address):
            return None

        chain = "FORWARD"
        action = "DROP" if deny else "ACCEPT"
        parts = [
            "iptables",
            f"-A {chain}",
            "-i wg0",
            "-o wg0",
        ]

        if policy.destination:
            parts.append(f"-d {policy.destination}")

        if policy.protocol:
            parts.append(f"-p {policy.protocol}")

        if policy.port:
            parts.append(f"--dport {policy.port}")

        parts.append(f"-j {action}")

        # Add comment for traceability
        parts.append(f'-m comment --comment "SDN:{policy.name}"')

        return " ".join(parts)
