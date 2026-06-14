"""
Configuration parsing and validation for SDN topologies.

Supports YAML topology definitions with:
- Standard WireGuard parameters
- AmneziaWG obfuscation settings
- Multi-site network definitions
"""

import yaml
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class AmneziaObfuscation:
    """AmneziaWG obfuscation parameters for DPI bypass.

    AmneziaWG adds obfuscation to the WireGuard handshake and data packets
    to evade deep packet inspection. These parameters control the obfuscation
    behavior.
    """
    enabled: bool = False

    # Jc: packet reorder count for junk packets before real data (0-128)
    junk_packet_count: int = 0

    # Jmin/Jmax: min/max size of junk packets in bytes
    junk_packet_min_size: int = 40
    junk_packet_max_size: int = 80

    # S1/S2: init/response packet obfuscation (base64-encoded random strings)
    init_packet_junk: Optional[str] = None
    response_packet_junk: Optional[str] = None

    # H1-H4: header obfuscation markers
    header_obfuscation_keys: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        if not self.enabled:
            return {"enabled": False}
        d = {"enabled": True}
        d["Jc"] = self.junk_packet_count
        d["Jmin"] = self.junk_packet_min_size
        d["Jmax"] = self.junk_packet_max_size
        if self.init_packet_junk:
            d["S1"] = self.init_packet_junk
        if self.response_packet_junk:
            d["S2"] = self.response_packet_junk
        if self.header_obfuscation_keys:
            d["H"] = self.header_obfuscation_keys
        return d

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "AmneziaObfuscation":
        """Parse from YAML dictionary."""
        if data is None:
            return cls()
        return cls(
            enabled=data.get("enabled", False),
            junk_packet_count=data.get("Jc", 0),
            junk_packet_min_size=data.get("Jmin", 40),
            junk_packet_max_size=data.get("Jmax", 80),
            init_packet_junk=data.get("S1"),
            response_packet_junk=data.get("S2"),
            header_obfuscation_keys=data.get("H", []),
        )


@dataclass
class NodeConfig:
    """Configuration for a single SDN node."""
    name: str
    endpoint: Optional[str] = None           # public IP:port for WireGuard
    listen_port: int = 51820
    private_key: Optional[str] = None        # generated if not provided
    public_key: Optional[str] = None         # derived from private key
    address: str = ""                         # tunnel IP (CIDR)
    allowed_ips: List[str] = field(default_factory=list)  # routed subnets
    obfuscation: AmneziaObfuscation = field(default_factory=AmneziaObfuscation)
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def tunnel_ip(self) -> Optional[str]:
        """Extract the tunnel IP (without prefix) from address."""
        if not self.address:
            return None
        return self.address.split("/")[0] if "/" in self.address else self.address

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "listen_port": self.listen_port,
            "address": self.address,
        }
        if self.endpoint:
            d["endpoint"] = self.endpoint
        if self.private_key:
            d["private_key"] = self.private_key
        if self.public_key:
            d["public_key"] = self.public_key
        if self.allowed_ips:
            d["allowed_ips"] = self.allowed_ips
        if self.obfuscation.enabled:
            d["obfuscation"] = self.obfuscation.to_dict()
        if self.tags:
            d["tags"] = self.tags
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NodeConfig":
        return cls(
            name=data["name"],
            endpoint=data.get("endpoint"),
            listen_port=data.get("listen_port", 51820),
            private_key=data.get("private_key"),
            public_key=data.get("public_key"),
            address=data.get("address", ""),
            allowed_ips=data.get("allowed_ips", []),
            obfuscation=AmneziaObfuscation.from_dict(data.get("obfuscation")),
            tags=data.get("tags", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TunnelConfig:
    """Configuration for a tunnel between two nodes."""
    name: str
    source_node: str
    target_node: str
    source_address: str = ""
    target_address: str = ""
    metric: int = 1                          # routing metric
    obfuscation: Optional[AmneziaObfuscation] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "source": self.source_node,
            "target": self.target_node,
            "metric": self.metric,
        }
        if self.source_address:
            d["source_address"] = self.source_address
        if self.target_address:
            d["target_address"] = self.target_address
        if self.obfuscation and self.obfuscation.enabled:
            d["obfuscation"] = self.obfuscation.to_dict()
        return d


@dataclass
class PolicyRule:
    """Access control policy rule between subnets."""
    name: str
    source: str          # source subnet or node
    destination: str     # destination subnet or node
    action: str = "allow"  # allow | deny | rate-limit
    port: Optional[int] = None
    protocol: Optional[str] = None  # tcp, udp, icmp
    priority: int = 100

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "source": self.source,
            "destination": self.destination,
            "action": self.action,
            "priority": self.priority,
        }
        if self.port is not None:
            d["port"] = self.port
        if self.protocol:
            d["protocol"] = self.protocol
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyRule":
        return cls(
            name=data["name"],
            source=data["source"],
            destination=data["destination"],
            action=data.get("action", "allow"),
            port=data.get("port"),
            protocol=data.get("protocol"),
            priority=data.get("priority", 100),
        )


@dataclass
class TopologyConfig:
    """Complete SDN topology definition."""
    name: str
    description: str = ""
    version: str = "1.0"
    network_cidr: str = "10.0.0.0/8"        # overall SDN address space
    mtu: int = 1420
    nodes: List[NodeConfig] = field(default_factory=list)
    tunnels: List[TunnelConfig] = field(default_factory=list)
    policies: List[PolicyRule] = field(default_factory=list)
    obfuscation_enabled: bool = False
    default_obfuscation: Optional[AmneziaObfuscation] = None

    def get_node(self, name: str) -> Optional[NodeConfig]:
        for node in self.nodes:
            if node.name == name:
                return node
        return None

    def get_tunnels_for_node(self, node_name: str) -> List[TunnelConfig]:
        return [
            t for t in self.tunnels
            if t.source_node == node_name or t.target_node == node_name
        ]

    def get_peers_for_node(self, node_name: str) -> List[TunnelConfig]:
        """Get tunnels where node is the source (i.e. peers it connects to)."""
        return [t for t in self.tunnels if t.source_node == node_name]

    def validate(self) -> List[str]:
        """Validate topology and return list of errors."""
        errors = []
        node_names = {n.name for n in self.nodes}

        for tunnel in self.tunnels:
            if tunnel.source_node not in node_names:
                errors.append(
                    f"Tunnel '{tunnel.name}': source node '{tunnel.source_node}' "
                    f"not found in nodes"
                )
            if tunnel.target_node not in node_names:
                errors.append(
                    f"Tunnel '{tunnel.name}': target node '{tunnel.target_node}' "
                    f"not found in nodes"
                )

        for policy in self.policies:
            for addr in [policy.source, policy.destination]:
                # Could be node name or CIDR
                if addr not in node_names:
                    try:
                        ipaddress.ip_network(addr, strict=False)
                    except ValueError:
                        errors.append(
                            f"Policy '{policy.name}': '{addr}' is neither a "
                            f"node name nor a valid CIDR"
                        )

        for node in self.nodes:
            if node.address:
                try:
                    ipaddress.ip_network(node.address, strict=False)
                except ValueError as e:
                    errors.append(
                        f"Node '{node.name}': invalid address '{node.address}': {e}"
                    )

        return errors

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "network_cidr": self.network_cidr,
            "mtu": self.mtu,
            "nodes": [n.to_dict() for n in self.nodes],
            "tunnels": [t.to_dict() for t in self.tunnels],
            "policies": [p.to_dict() for p in self.policies],
        }
        if self.description:
            d["description"] = self.description
        if self.obfuscation_enabled:
            d["obfuscation_enabled"] = True
        if self.default_obfuscation and self.default_obfuscation.enabled:
            d["default_obfuscation"] = self.default_obfuscation.to_dict()
        return d

    @staticmethod
    def _parse_tunnel_dict(t: Dict[str, Any]) -> TunnelConfig:
        """Parse a tunnel dict, mapping source/target to source_node/target_node."""
        source = t.get("source") or t.get("source_node", "")
        target = t.get("target") or t.get("target_node", "")
        return TunnelConfig(
            name=t.get("name", f"{source}-{target}"),
            source_node=source,
            target_node=target,
            source_address=t.get("source_address", ""),
            target_address=t.get("target_address", ""),
            metric=t.get("metric", 1),
            obfuscation=AmneziaObfuscation.from_dict(t.get("obfuscation")) if t.get("obfuscation") else None,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopologyConfig":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            network_cidr=data.get("network_cidr", "10.0.0.0/8"),
            mtu=data.get("mtu", 1420),
            nodes=[NodeConfig.from_dict(n) for n in data.get("nodes", [])],
            tunnels=[cls._parse_tunnel_dict(t) if isinstance(t, dict) else t
                     for t in data.get("tunnels", [])],
            policies=[PolicyRule.from_dict(p) for p in data.get("policies", [])],
            obfuscation_enabled=data.get("obfuscation_enabled", False),
            default_obfuscation=AmneziaObfuscation.from_dict(
                data.get("default_obfuscation")
            ),
        )


def load_topology(path: Path) -> TopologyConfig:
    """Load and validate a topology from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    # Handle tunnel shorthand (list of node pairs)
    if "tunnels" in data:
        parsed_tunnels = []
        for t in data["tunnels"]:
            if isinstance(t, str):
                # Shorthand: "nodeA:nodeB" or "nodeA->nodeB"
                if "->" in t:
                    src, dst = t.split("->")
                elif ":" in t:
                    src, dst = t.split(":")
                else:
                    raise ValueError(f"Invalid tunnel shorthand: {t}")
                parsed_tunnels.append({
                    "name": f"{src}-{dst}",
                    "source": src.strip(),
                    "target": dst.strip(),
                })
            elif isinstance(t, dict):
                parsed_tunnels.append(t)
        data["tunnels"] = parsed_tunnels

    topology = TopologyConfig.from_dict(data)
    errors = topology.validate()
    if errors:
        raise ValueError(f"Topology validation errors:\n  " + "\n  ".join(errors))
    return topology


def save_topology(topology: TopologyConfig, path: Path) -> None:
    """Save a topology to a YAML file."""
    with open(path, "w") as f:
        yaml.dump(topology.to_dict(), f, default_flow_style=False, sort_keys=False)
