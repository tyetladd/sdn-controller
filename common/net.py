"""
Network utilities for SDN controller.

Handles:
- IP address allocation from the SDN address space
- Subnet management
- Network validation
- Route calculation
"""

import ipaddress
import math
from typing import List, Optional, Tuple


class AddressAllocator:
    """Allocates IP addresses from the SDN address space.

    Manages a pool of subnets and allocates /24 blocks for sites
    and /32 addresses for individual node tunnel interfaces.
    """

    def __init__(self, network_cidr: str = "10.0.0.0/8"):
        self.network = ipaddress.ip_network(network_cidr, strict=False)
        self._allocated_subnets: List[ipaddress.IPv4Network] = []
        self._allocated_ips: List[ipaddress.IPv4Address] = []

    def allocate_subnet(
        self, name: str, prefixlen: int = 24
    ) -> ipaddress.IPv4Network:
        """Allocate a subnet for a site/group."""
        for subnet in self.network.subnets(new_prefix=prefixlen):
            candidate = ipaddress.ip_network(subnet)
            if not any(
                candidate.overlaps(allocated)
                for allocated in self._allocated_subnets
            ):
                if not self._is_reserved(candidate):
                    self._allocated_subnets.append(candidate)
                    return candidate
        raise RuntimeError(
            f"No available /{prefixlen} subnet in {self.network}"
        )

    def allocate_ip(self, node_name: str) -> ipaddress.IPv4Address:
        """Allocate a single IP for a node tunnel interface.

        Uses the first /24 block from the network. In a real deployment,
        this would be coordinated with subnet allocations.
        """
        # Use 10.255.0.0/16 for tunnel endpoint IPs
        tunnel_net = ipaddress.ip_network("10.255.0.0/16")
        for ip in tunnel_net.hosts():
            if ip not in self._allocated_ips and str(ip).endswith(".0"):
                continue
            if ip not in self._allocated_ips:
                self._allocated_ips.append(ip)
                return ip
        raise RuntimeError("No available tunnel IPs")

    def _is_reserved(self, network: ipaddress.IPv4Network) -> bool:
        """Check if a subnet is reserved."""
        reserved_prefixes = [
            ipaddress.ip_network("10.255.0.0/16"),  # Tunnel endpoint IPs
        ]
        return any(network.overlaps(r) for r in reserved_prefixes)

    def release_subnet(self, network: ipaddress.IPv4Network) -> None:
        """Release an allocated subnet back to the pool."""
        self._allocated_subnets = [
            s for s in self._allocated_subnets if s != network
        ]

    def release_ip(self, ip: ipaddress.IPv4Address) -> None:
        """Release an allocated IP back to the pool."""
        self._allocated_ips = [
            a for a in self._allocated_ips if a != ip
        ]

    def list_allocations(self) -> dict:
        return {
            "subnets": [str(s) for s in self._allocated_subnets],
            "ips": [str(ip) for ip in self._allocated_ips],
        }


def validate_cidr(cidr: str) -> bool:
    """Validate a CIDR notation string."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP is in a private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def find_next_available_subnet(
    base_network: ipaddress.IPv4Network,
    existing_subnets: List[ipaddress.IPv4Network],
    prefixlen: int = 24,
) -> Optional[ipaddress.IPv4Network]:
    """Find the next available subnet within a base network."""
    for subnet in base_network.subnets(new_prefix=prefixlen):
        candidate = ipaddress.ip_network(subnet)
        if not any(candidate.overlaps(e) for e in existing_subnets):
            return candidate
    return None


def calculate_routing_table(
    nodes: dict, tunnels: list
) -> dict:
    """Calculate optimal routes between all nodes.

    Uses simple shortest-path (Dijkstra) over the tunnel graph.
    Returns a routing table: {source_name: {dest_name: next_hop}}
    """
    # Build adjacency list
    adj: dict = {}
    for node_name in nodes:
        adj[node_name] = []

    for tunnel in tunnels:
        src = tunnel.get("source", tunnel.get("source_node", ""))
        dst = tunnel.get("target", tunnel.get("target_node", ""))
        metric = tunnel.get("metric", 1)

        if src not in adj:
            adj[src] = []
        if dst not in adj:
            adj[dst] = []

        adj[src].append((dst, metric))
        adj[dst].append((src, metric))

    # Dijkstra from each node
    routing_table = {}
    for source in nodes:
        dist = {n: math.inf for n in nodes}
        prev = {n: None for n in nodes}
        dist[source] = 0
        unvisited = set(nodes.keys())

        while unvisited:
            current = min(unvisited, key=lambda n: dist[n])
            if dist[current] == math.inf:
                break
            unvisited.remove(current)

            for neighbor, weight in adj.get(current, []):
                if neighbor in unvisited:
                    new_dist = dist[current] + weight
                    if new_dist < dist[neighbor]:
                        dist[neighbor] = new_dist
                        prev[neighbor] = current

        # Build next-hop table for this source
        routes = {}
        for dest in nodes:
            if dest == source:
                continue
            # Trace back to find next hop
            current = dest
            while prev.get(current) is not None and prev[current] != source:
                current = prev[current]
            if prev.get(current) == source:
                routes[dest] = current
            elif current != source and dist[dest] < math.inf:
                routes[dest] = current

        routing_table[source] = routes

    return routing_table
