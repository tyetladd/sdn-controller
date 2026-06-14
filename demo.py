#!/usr/bin/env python3
"""
SDN Prototype Demo Script

Demonstrates the full SDN controller lifecycle:
1. Load topology definitions
2. Generate WireGuard/AmneziaWG configurations
3. Manage keys
4. Evaluate policies
5. Show the REST API (conceptually)
6. Export configurations for deployment

This demo works without kernel modules — it generates and validates
configurations that would be deployed to real nodes.
"""

import json
import sys
import os
from pathlib import Path

# Ensure we can import from the project
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.config import load_topology, TopologyConfig
from common.keys import KeyManager
from common.net import AddressAllocator, calculate_routing_table
from controller.topology import TopologyManager
from controller.tunnel import TunnelConfigGenerator
from controller.policy import PolicyEngine


SEPARATOR = "=" * 70
SEPARATOR_THIN = "-" * 50


def print_header(title: str):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def print_step(step: int, description: str):
    print(f"\n  [{step}] {description}")
    print(f"  {SEPARATOR_THIN}")


def demo_keys():
    """Demo: Key generation and management."""
    print_header("KEY MANAGEMENT DEMO")

    km = KeyManager()
    nodes = ["node-nyc", "node-lon", "node-sgp", "node-sfo"]

    print_step(1, "Generating Curve25519 key pairs for all nodes")
    for node in nodes:
        kp = km.generate_keypair(node)
        print(f"    {node}:")
        print(f"      Public:  {kp.public_key}")
        print(f"      Created: {kp.created_at}")

    print_step(2, "Listing all public keys (safe for distribution)")
    keys = km.list_keys()
    for name, pubkey in keys.items():
        print(f"    {name}: {pubkey}")

    print_step(3, "Rotating key for node-nyc")
    old = km.get_keypair("node-nyc")
    new = km.rotate_key("node-nyc")
    print(f"    Old public key: {old.public_key}")
    print(f"    New public key: {new.public_key}")

    return km


def demo_topology_loader():
    """Demo: Loading and validating topologies."""
    print_header("TOPOLOGY LOADING DEMO")

    examples_dir = Path(__file__).resolve().parent / "examples"
    topologies = {}

    for yaml_file in sorted(examples_dir.glob("*.yaml")):
        print_step(0, f"Loading '{yaml_file.stem}' topology")
        try:
            topo = load_topology(yaml_file)
            topologies[yaml_file.stem] = topo
            print(f"    Name:        {topo.name}")
            print(f"    Description: {topo.description[:80]}...")
            print(f"    Nodes:       {len(topo.nodes)}")
            print(f"    Tunnels:     {len(topo.tunnels)}")
            print(f"    Policies:    {len(topo.policies)}")
            print(f"    Obfuscation: {'Enabled' if topo.obfuscation_enabled else 'Disabled'}")
            print(f"    Valid:       ✓")
        except Exception as e:
            print(f"    Error: {e}")

    return topologies


def demo_topology_manager(topologies: dict):
    """Demo: Topology manager with programmatic node management."""
    print_header("TOPOLOGY MANAGER DEMO")

    # Use a loaded topology if available, otherwise start fresh
    topo = topologies.get("simple_pair") if topologies else None
    tm = TopologyManager(topo)
    print_step(1, f"Starting with topology: {tm.name}")
    print(f"    Initial nodes: {len(tm.nodes)}")
    print(f"    Initial tunnels: {len(tm.tunnels)}")

    # If no nodes were loaded, create a minimal test topology
    if not tm.nodes:
        print_step(2, "Creating initial test nodes")
        tm.add_node(
            name="node-alpha",
            endpoint="192.168.1.10:51820",
            address="10.255.1.1/32",
            allowed_ips=["10.255.1.0/24"],
            tags={"env": "test"},
        )
        tm.add_node(
            name="node-beta",
            endpoint="192.168.2.20:51820",
            address="10.255.1.2/32",
            allowed_ips=["10.255.2.0/24"],
            tags={"env": "test"},
        )
        tm.create_tunnel("node-alpha", "node-beta")
        print(f"    Created 2 nodes + 1 tunnel")

    print_step(3, "Adding a new node programmatically")
    node = tm.add_node(
        name="node-gamma",
        endpoint="192.168.3.30:51820",
        allowed_ips=["10.255.3.0/24"],
        tags={"env": "test", "region": "west"},
    )
    print(f"    Added: {node.name}")
    print(f"    Address: {node.address}")
    print(f"    Public key: {node.public_key}")

    print_step(4, "Creating tunnels to the new node")
    t1 = tm.create_tunnel("node-alpha", "node-gamma")
    print(f"    Created: {t1.name} (src={t1.source_node}, dst={t1.target_node})")
    t2 = tm.create_tunnel("node-beta", "node-gamma")
    print(f"    Created: {t2.name} (src={t2.source_node}, dst={t2.target_node})")

    print_step(5, "Topology summary")
    summary = tm.get_topology_summary()
    for k, v in summary.items():
        print(f"    {k}: {v}")

    print_step(6, "Cleaning up — removing gamma node")
    tm.remove_tunnel("node-alpha", "node-gamma")
    tm.remove_tunnel("node-beta", "node-gamma")
    tm.remove_node("node-gamma")
    print(f"    Nodes remaining: {len(tm.nodes)}")
    print(f"    Tunnels remaining: {len(tm.tunnels)}")

    return tm


def demo_config_generation(tm: TopologyManager):
    """Demo: Generate WireGuard and AmneziaWG configs."""
    print_header("CONFIGURATION GENERATION DEMO")

    # Load mesh topology for richer config demo
    examples_dir = Path(__file__).resolve().parent / "examples"
    mesh_topo = load_topology(examples_dir / "mesh.yaml")
    mesh_tm = TopologyManager(mesh_topo)

    print_step(1, "Generating standard WireGuard configs")
    generator = TunnelConfigGenerator(mesh_tm.to_config())
    configs = generator.generate_all_configs()

    for node_name, config in configs.items():
        print(f"\n    --- {node_name} ---")
        print(f"    Interface: {config.address}")
        print(f"    Listen port: {config.listen_port}")
        print(f"    MTU: {config.mtu}")
        print(f"    Peers: {len(config.peers)}")
        for peer in config.peers:
            print(f"      -> {peer.public_key[:16]}... "
                  f"endpoint={peer.endpoint} "
                  f"allowed_ips={peer.allowed_ips}")

    print_step(2, "Rendering wg-quick config for node-nyc")
    nyc_config = generator.generate_node_config("node-nyc")
    wg_config = generator.render_wg_quick_config(nyc_config)
    print(wg_config[:500] + "...\n")

    print_step(3, "Rendering AmneziaWG config (with obfuscation) for node-nyc")
    awg_config = generator.render_amneziawg_config(nyc_config)
    print(awg_config[:600] + "...\n")

    print_step(4, "Writing all configs to disk")
    out_dir = Path("/tmp/sdn-configs-demo")
    written = generator.write_all_configs(out_dir, format="wg-quick")
    print(f"    Standard WG configs: {len(written)} files in {out_dir}")
    for name, path in written.items():
        print(f"      {path}")

    written_awg = generator.write_all_configs(
        Path("/tmp/sdn-configs-demo-awg"), format="amneziawg"
    )
    print(f"    AmneziaWG configs: {len(written_awg)} files")

    print_step(5, "JSON config export (for API consumption)")
    json_config = generator.render_json_config(nyc_config)
    print(json.dumps(json_config, indent=2)[:400] + "...\n")


def demo_policy_engine(topologies: dict):
    """Demo: Policy evaluation engine."""
    print_header("POLICY ENGINE DEMO")

    pe = PolicyEngine(default_action="deny")

    # Load policies from mesh topology
    mesh = topologies.get("mesh")
    if mesh:
        pe.load_policies(mesh.policies)
        print_step(1, f"Loaded {len(mesh.policies)} policies from mesh topology")
        for rule in mesh.policies:
            print(f"    {rule.name}: {rule.source} -> {rule.destination} "
                  f"[{rule.action}] (priority={rule.priority})")

    print_step(2, "Evaluating flows")
    test_flows = [
        {"source_ip": "10.10.1.5", "dest_ip": "10.10.3.10", "desc": "US-East -> APAC (allowed)"},
        {"source_ip": "10.10.3.5", "dest_ip": "10.10.1.10", "desc": "APAC -> US-East SSH (denied)"},
        {"source_ip": "10.10.3.5", "dest_ip": "10.10.1.10", "desc": "APAC -> US-East HTTP (allowed)"},
        {"source_ip": "192.168.1.1", "dest_ip": "10.10.1.1", "desc": "External -> SDN (denied by default)"},
    ]

    for i, flow in enumerate(test_flows):
        action, rule = pe.evaluate(
            source_ip=flow["source_ip"],
            dest_ip=flow["dest_ip"],
            protocol="tcp" if i in [1, 2] else None,
            port=22 if i == 1 else (80 if i == 2 else None),
        )
        print(f"    [{action.upper():6s}] {flow['desc']}")
        if rule:
            print(f"             Matched rule: {rule}")
        else:
            print(f"             Matched rule: (default)")

    print_step(3, "Bulk evaluation")
    flows = [
        {"source_ip": "10.10.1.5", "dest_ip": "10.10.2.20", "port": 443, "protocol": "tcp"},
        {"source_ip": "10.10.3.5", "dest_ip": "10.10.1.50", "port": 22, "protocol": "tcp"},
        {"source_ip": "10.10.2.1", "dest_ip": "10.10.4.1", "port": 8080, "protocol": "tcp"},
    ]
    results = pe.evaluate_bulk(flows)
    for r in results:
        print(f"    {r['source_ip']} -> {r['dest_ip']}:{r.get('port','')} "
              f"= {r['action']} ({r.get('matched_rule', 'default')})")

    print_step(4, "Policy engine statistics")
    stats = pe.get_stats()
    print(f"    Rules: {stats['total_rules']}")
    print(f"    Default action: {stats['default_action']}")
    for rule in stats["rules"]:
        print(f"    {rule['name']}: {rule['hits']} hits")


def demo_address_allocation():
    """Demo: IP address allocation from SDN address space."""
    print_header("ADDRESS ALLOCATION DEMO")

    allocator = AddressAllocator("10.0.0.0/8")

    print_step(1, "Allocating subnets for sites")
    sites = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2"]
    for site in sites:
        subnet = allocator.allocate_subnet(site, prefixlen=24)
        print(f"    {site}: {subnet}")

    print_step(2, "Allocating tunnel IPs for nodes")
    nodes = ["gw-1", "gw-2", "gw-3", "gw-4", "gw-5"]
    for node in nodes:
        ip = allocator.allocate_ip(node)
        print(f"    {node}: {ip}")

    print_step(3, "Current allocations")
    allocs = allocator.list_allocations()
    print(f"    Subnets: {allocs['subnets']}")
    print(f"    Tunnel IPs: {allocs['ips']}")


def demo_routing():
    """Demo: Route calculation across the topology."""
    print_header("ROUTING TABLE DEMO")

    print_step(1, "Building routing tables for mesh topology")
    examples_dir = Path(__file__).resolve().parent / "examples"
    mesh = load_topology(examples_dir / "mesh.yaml")

    nodes_dict = {
        n.name: n.address for n in mesh.nodes
    }
    tunnels_list = [
        {
            "source": t.source_node,
            "target": t.target_node,
            "metric": t.metric,
        }
        for t in mesh.tunnels
    ]

    routing = calculate_routing_table(nodes_dict, tunnels_list)
    for src, routes in routing.items():
        print(f"  From {src}:")
        for dst, next_hop in sorted(routes.items()):
            print(f"    -> {dst}: via {next_hop}")


def demo_node_agent():
    """Demo: Node agent (conceptual — no actual tunnel setup)."""
    print_header("NODE AGENT DEMO (conceptual)")

    from node.agent import NodeAgent
    from node.monitor import NodeMonitor

    print_step(1, "Creating node agent for 'node-nyc'")
    agent = NodeAgent(
        node_name="node-nyc",
        controller_url="http://localhost:8080",
        config_dir=Path("/tmp/sdn-node-agent-demo"),
        interface="wg0",
    )

    # Simulate applying a config
    config = {
        "interface": {
            "private_key": "gNt0i4XGmH7U9J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y=",
            "address": "10.10.1.1/32",
            "listen_port": 51820,
            "mtu": 1420,
            "dns": ["10.10.1.1"],
        },
        "peers": [
            {
                "public_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl=",
                "endpoint": "203.0.113.20:51820",
                "allowed_ips": ["10.10.2.0/24"],
                "persistent_keepalive": 25,
            },
            {
                "public_key": "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsrqpo=",
                "endpoint": "192.0.2.30:51820",
                "allowed_ips": ["10.10.3.0/24"],
                "persistent_keepalive": 25,
            },
        ],
    }

    print_step(2, "Applying JSON configuration")
    success = agent.apply_json_config(config)
    print(f"    Config applied: {success}")
    status = agent.get_status()
    if status:
        print(f"    Interface: {status.interface}")
        print(f"    Address: {status.address}")
        print(f"    Peers: {status.peer_count}")

    print_step(3, "Creating monitor and collecting metrics")
    monitor = NodeMonitor(agent)
    metrics = monitor.collect_metrics()
    print(f"    Node: {metrics.get('node')}")
    print(f"    Uptime: {metrics.get('uptime_seconds', 0):.1f}s")
    print(f"    Peers: {metrics.get('peer_count', 0)}")

    print_step(4, "Running health check")
    alerts = monitor.check_health()
    if alerts:
        for alert in alerts:
            print(f"    [{alert.level.upper()}] {alert.message}")
    else:
        print(f"    No alerts (expected — no actual tunnels running)")

    summary = monitor.get_health_summary()
    print(f"    Health: {'✓ Healthy' if summary['healthy'] else '✗ Unhealthy'}")
    print(f"    Peers connected: {summary['peers_connected']}")


def main():
    print_header("SDN CONTROLLER PROTOTYPE — COMPREHENSIVE DEMO")
    print("  Software-Defined Networking over AmneziaWG/WireGuard Tunnels")
    print("  (Runs without kernel modules — generates deployable configs)")
    print()

    # 1. Key Management
    km = demo_keys()

    # 2. Topology Loading
    topologies = demo_topology_loader()

    # 3. Topology Manager
    tm = demo_topology_manager(topologies)

    # 4. Configuration Generation
    demo_config_generation(tm)

    # 5. Policy Engine
    demo_policy_engine(topologies)

    # 6. Address Allocation
    demo_address_allocation()

    # 7. Routing Calculation
    demo_routing()

    # 8. Node Agent
    demo_node_agent()

    # Summary
    print_header("DEMO COMPLETE")
    print(f"""
  Successfully demonstrated:

  ✓ Key Management
    - Curve25519 key pair generation
    - Key distribution and rotation

  ✓ Topology Management
    - YAML topology definition
    - Node/tunnel lifecycle management
    - Topology validation

  ✓ Configuration Generation
    - WireGuard wg-quick configs
    - AmneziaWG obfuscated configs
    - JSON API format

  ✓ Policy Engine
    - Allow/deny rules with priority
    - Protocol/port filtering
    - Zero-trust default-deny model

  ✓ Address Allocation
    - Subnet allocation from SDN space
    - Tunnel IP assignment

  ✓ Routing
    - Dijkstra shortest-path calculation
    - Metric-based route selection

  ✓ Node Agent
    - Config application
    - Health monitoring
    - Alert generation

  Topology files: examples/*.yaml
  Generated configs: /tmp/sdn-configs-demo/
  CLI tool: cli/sdnctl.py
  REST API: controller/api.py
""")


if __name__ == "__main__":
    main()
