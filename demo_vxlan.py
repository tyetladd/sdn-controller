#!/usr/bin/env python3
"""
VXLAN-over-WireGuard Demo — management overhead comparison.

Shows how VXLAN dramatically reduces WireGuard AllowedIPs
management when behind-node subnets change.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.config import load_topology, TopologyConfig
from controller.tunnel import TunnelConfigGenerator
from controller.vxlan import VxlanOverlayManager, VxlanConfig

SEP = "=" * 72


def count_allowed_ips(configs: dict) -> dict:
    """Count AllowedIPs entries per peer across all node configs."""
    counts = {}
    total = 0
    for node_name, config in configs.items():
        node_total = sum(len(p.allowed_ips) for p in config.peers)
        counts[node_name] = {
            "peers": len(config.peers),
            "total_allowed_ips": node_total,
        }
        total += node_total
    counts["__total__"] = total
    return counts


def main():
    print(SEP)
    print("  VXLAN-over-WireGuard: Management Overhead Comparison")
    print(SEP)
    print()

    # Load topology WITH VXLAN
    print("─── Loading vxlan_mesh topology ───")
    topo = load_topology("examples/vxlan_mesh.yaml")
    print(f"  Nodes: {len(topo.nodes)}")
    print(f"  Tunnels: {len(topo.tunnels)}")
    print(f"  VXLAN: {'enabled' if topo.vxlan.enabled else 'disabled'}")
    print(f"  VXLAN network: {topo.vxlan.vxlan_network}")
    print(f"  VXLAN VNI: {topo.vxlan.vni}")
    print()

    # Build VXLAN overlay
    vxlan = VxlanOverlayManager(topo)
    vxlan.build_fdb()

    # Generate configs WITH VXLAN
    gen_vxlan = TunnelConfigGenerator(topo, vxlan_manager=vxlan)
    configs_vxlan = gen_vxlan.generate_all_configs()
    counts_vxlan = count_allowed_ips(configs_vxlan)

    # Generate configs WITHOUT VXLAN (for comparison)
    gen_plain = TunnelConfigGenerator(topo)  # no VXLAN manager
    configs_plain = gen_plain.generate_all_configs()
    counts_plain = count_allowed_ips(configs_plain)

    # ── Comparison ──
    print("─── AllowedIPs Comparison ───")
    print(f"  {'Node':<20} {'Without VXLAN':>16} {'With VXLAN':>16} {'Reduction':>12}")
    print(f"  {'-'*20} {'-'*16} {'-'*16} {'-'*12}")

    for node in topo.nodes:
        name = node.name
        plain = counts_plain[name]["total_allowed_ips"]
        vxlan_count = counts_vxlan[name]["total_allowed_ips"]
        reduction = plain - vxlan_count
        pct = f"{reduction/plain*100:.0f}%" if plain > 0 else "N/A"
        print(f"  {name:<20} {plain:>16} {vxlan_count:>16} {reduction:>8} ({pct})")

    total_plain = counts_plain["__total__"]
    total_vxlan = counts_vxlan["__total__"]
    print(f"  {'-'*20} {'-'*16} {'-'*16} {'-'*12}")
    print(f"  {'TOTAL':<20} {total_plain:>16} {total_vxlan:>16} "
          f"{total_plain - total_vxlan:>8} ({((total_plain - total_vxlan)/total_plain*100):.0f}%)")
    print()

    # ── What changes when you add a subnet ──
    print("─── What happens when you add a new subnet (10.99.0.0/24) behind node-nyc ───")
    print()

    # Without VXLAN
    print("  Without VXLAN:")
    print("    Every peer of node-nyc needs its AllowedIPs updated:")
    for node in topo.nodes:
        if node.name == "node-nyc":
            peers = topo.get_peers_for_node(node.name)
            print(f"    - node-nyc has {len(peers)} peers that all need updating")
            print(f"    - Each other node's config: add \"10.99.0.0/24\" to [Peer] node-nyc")
    plain_new_total = total_plain + len(topo.nodes) - 1
    print(f"    Total AllowedIPs entries would become: {plain_new_total}")
    print()

    # With VXLAN
    print("  With VXLAN:")
    print("    WireGuard configs: 0 changes needed")
    print(f"    VXLAN routing: add one route on node-nyc:")
    nyc_entry = vxlan.get_node_entry("node-nyc")
    vxlan_if = f"vxlan{topo.vxlan.vni}"
    print(f"      ip route add 10.99.0.0/24 dev {vxlan_if}")
    print(f"    Or via BGP within VXLAN: peer learns it automatically")
    print(f"    Total AllowedIPs entries: still {total_vxlan} (unchanged)")
    print()

    # ── VXLAN setup script ──
    print("─── Generated VXLAN setup script for node-nyc ───")
    script = vxlan.generate_setup_script("node-nyc")
    print(script[:800])
    if len(script) > 800:
        print(f"  ... ({len(script)} bytes total)")
    print()

    # ── VXLAN routes ──
    print("─── VXLAN routes for node-nyc (behind-node subnets) ───")
    routes = vxlan.generate_vxlan_routes("node-nyc")
    for route in routes[:10]:
        print(f"  {route}")
    print(f"  ... ({len(routes)} routes total)")
    print()

    # ── WG config with VXLAN PreUp/PostUp ──
    print("─── WireGuard config with VXLAN integration (node-nyc) ───")
    nyc_config = gen_vxlan.generate_node_config("node-nyc")
    wg_config = gen_vxlan.render_wg_quick_config(nyc_config)
    augmented = vxlan.generate_wg_config_with_vxlan("node-nyc", wg_config)
    # Show just the interface section with VXLAN hooks
    lines = augmented.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("[Peer]"):
            break
        print(f"  {line}")
    print(f"  ... ({len(lines)} lines total)")
    print()

    # ── Summary ──
    print(SEP)
    print("  Summary")
    print(SEP)
    print(f"""
  Without VXLAN:
    - {total_plain} total AllowedIPs entries across all peers
    - Adding a subnet: update {len(topo.nodes) - 1} peer configs
    - Behind-node subnets coupled to WireGuard config management
    - Best for: ≤5 nodes, infrequent subnet changes

  With VXLAN:
    - {total_vxlan} total AllowedIPs entries (fixed, per-node VXLAN IPs)
    - Adding a subnet: 0 WireGuard changes, 1 VXLAN route or BGP announcement
    - WireGuard handles transport, VXLAN handles routing
    - Best for: 5-100+ nodes, dynamic subnet changes, container workloads
    - Overhead: 50 bytes VXLAN header, MTU reduced to {topo.vxlan.mtu}
""")

    # Write VXLAN setup scripts
    out_dir = Path("/tmp/sdn-vxlan-demo")
    written = vxlan.generate_all_setup_scripts(out_dir)
    print(f"  VXLAN setup scripts written to {out_dir}/")
    for name, path in written.items():
        print(f"    {path}")


if __name__ == "__main__":
    main()
