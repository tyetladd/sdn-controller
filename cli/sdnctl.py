#!/usr/bin/env python3
"""
sdnctl - SDN Controller CLI management tool.

Commands:
  sdnctl topology show                Show current topology
  sdnctl topology load <file>         Load topology from YAML
  sdnctl topology save <file>         Save topology to JSON
  sdnctl topology summary             Show topology summary

  sdnctl node list                    List all nodes
  sdnctl node show <name>             Show node details
  sdnctl node add <name> [opts]       Add a new node
  sdnctl node remove <name>           Remove a node

  sdnctl tunnel list                  List all tunnels
  sdnctl tunnel create <src> <dst>    Create a tunnel
  sdnctl tunnel remove <src> <dst>    Remove a tunnel

  sdnctl policy list                  List all policies
  sdnctl policy add <name> [opts]     Add a policy
  sdnctl policy remove <name>         Remove a policy
  sdnctl policy evaluate <src> <dst>  Evaluate policy for a flow

  sdnctl config generate [opts]       Generate all node configs
  sdnctl config show <node>           Show node config
  sdnctl config export <dir>          Export all configs to directory

  sdnctl key generate <node>          Generate keys for a node
  sdnctl key list                     List all public keys
  sdnctl key rotate <node>            Rotate keys for a node

  sdnctl server start [opts]          Start the REST API server
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import (
    TopologyConfig, NodeConfig, TunnelConfig,
    PolicyRule, AmneziaObfuscation,
    load_topology, save_topology,
)
from common.keys import KeyManager
from controller.topology import TopologyManager
from controller.tunnel import TunnelConfigGenerator
from controller.policy import PolicyEngine


class SdnCtl:
    """Main CLI handler for SDN management."""

    def __init__(self):
        self.tm: Optional[TopologyManager] = None
        self.key_manager = KeyManager()

    def cmd_topology(self, args):
        """Handle topology subcommands."""
        if args.topology_action == "show":
            if not self.tm:
                print("No topology loaded. Use 'topology load' first.")
                return
            print(json.dumps(self.tm.export(), indent=2))

        elif args.topology_action == "load":
            path = Path(args.file)
            if not path.exists():
                print(f"Error: file not found: {path}")
                return
            try:
                topology = load_topology(path)
                self.tm = TopologyManager(topology, self.key_manager)
                print(f"Loaded topology '{self.tm.name}'")
                print(f"  Nodes: {len(self.tm.nodes)}")
                print(f"  Tunnels: {len(self.tm.tunnels)}")
                print(f"  Policies: {len(self.tm.policies)}")
            except Exception as e:
                print(f"Error loading topology: {e}")
                return 1

        elif args.topology_action == "save":
            if not self.tm:
                print("No topology loaded.")
                return
            path = Path(args.file)
            self.tm.save(path)
            print(f"Saved topology to {path}")

        elif args.topology_action == "summary":
            if not self.tm:
                print("No topology loaded.")
                return
            summary = self.tm.get_topology_summary()
            print(f"Topology: {summary['name']} (v{summary['version']})")
            print(f"  Nodes:    {summary['node_count']}")
            print(f"  Tunnels:  {summary['tunnel_count']}")
            print(f"  Policies: {summary['policy_count']}")
            print(f"  Connected: {summary['connected']}")
            print(f"  Network:  {summary['network_cidr']}")
            print(f"  Obfuscation: {summary['obfuscation_enabled']}")

    def cmd_node(self, args):
        """Handle node subcommands."""
        if args.node_action == "list":
            if not self.tm:
                print("No topology loaded.")
                return
            nodes = self.tm.list_nodes()
            if not nodes:
                print("No nodes defined.")
                return
            print(f"{'Name':<20} {'Address':<18} {'Endpoint':<24} {'Peers':<6} {'Obs'}")
            print("-" * 85)
            for n in nodes:
                print(
                    f"{n['name']:<20} {n['address']:<18} "
                    f"{n.get('endpoint') or '-':<24} "
                    f"{n['peer_count']:<6} "
                    f"{'✓' if n.get('obfuscation_enabled') else '-'}"
                )

        elif args.node_action == "show":
            if not self.tm:
                print("No topology loaded.")
                return
            node = self.tm.get_node(args.node_name)
            if not node:
                print(f"Node '{args.node_name}' not found.")
                return
            print(json.dumps(node.to_dict(), indent=2))

        elif args.node_action == "add":
            if not self.tm:
                print("No topology loaded. Use 'topology load' first.")
                return
            try:
                node = self.tm.add_node(
                    name=args.node_name,
                    endpoint=args.endpoint,
                    listen_port=args.listen_port or 51820,
                    address=args.address,
                    allowed_ips=args.allowed_ips.split(",") if args.allowed_ips else [],
                )
                print(f"Added node '{node.name}'")
                print(f"  Address: {node.address}")
                print(f"  Public key: {node.public_key}")
            except Exception as e:
                print(f"Error: {e}")
                return 1

        elif args.node_action == "remove":
            if not self.tm:
                print("No topology loaded.")
                return
            if self.tm.remove_node(args.node_name):
                print(f"Removed node '{args.node_name}'")
            else:
                print(f"Node '{args.node_name}' not found.")
                return 1

    def cmd_tunnel(self, args):
        """Handle tunnel subcommands."""
        if args.tunnel_action == "list":
            if not self.tm:
                print("No topology loaded.")
                return
            tunnels = self.tm.list_tunnels()
            if not tunnels:
                print("No tunnels defined.")
                return
            print(f"{'Name':<30} {'Source':<20} {'Target':<20} {'Metric'}")
            print("-" * 75)
            for t in tunnels:
                print(
                    f"{t['name']:<30} "
                    f"{t.get('source', t.get('source_node', '?')):<20} "
                    f"{t.get('target', t.get('target_node', '?')):<20} "
                    f"{t['metric']}"
                )

        elif args.tunnel_action == "create":
            if not self.tm:
                print("No topology loaded.")
                return
            try:
                tunnel = self.tm.create_tunnel(
                    source_node=args.source,
                    target_node=args.target,
                    metric=args.metric or 1,
                )
                print(f"Created tunnel '{tunnel.name}'")
            except Exception as e:
                print(f"Error: {e}")
                return 1

        elif args.tunnel_action == "remove":
            if not self.tm:
                print("No topology loaded.")
                return
            if self.tm.remove_tunnel(args.source, args.target):
                print(f"Removed tunnel between '{args.source}' and '{args.target}'")
            else:
                print("Tunnel not found.")
                return 1

    def cmd_policy(self, args):
        """Handle policy subcommands."""
        if args.policy_action == "list":
            if not self.tm:
                print("No topology loaded.")
                return
            policies = self.tm.list_policies()
            if not policies:
                print("No policies defined.")
                return
            print(f"{'Name':<24} {'Source':<20} {'Dest':<20} {'Action':<8} {'Priority'}")
            print("-" * 80)
            for p in policies:
                print(
                    f"{p['name']:<24} {p['source']:<20} "
                    f"{p['destination']:<20} {p['action']:<8} {p['priority']}"
                )

        elif args.policy_action == "add":
            if not self.tm:
                print("No topology loaded.")
                return
            try:
                policy = self.tm.add_policy(
                    name=args.policy_name,
                    source=args.source,
                    destination=args.destination,
                    action=args.action or "allow",
                    port=args.port,
                    protocol=args.protocol,
                    priority=args.priority or 100,
                )
                print(f"Added policy '{policy.name}' ({policy.action})")
            except Exception as e:
                print(f"Error: {e}")
                return 1

        elif args.policy_action == "remove":
            if not self.tm:
                print("No topology loaded.")
                return
            if self.tm.remove_policy(args.policy_name):
                print(f"Removed policy '{args.policy_name}'")
            else:
                print(f"Policy '{args.policy_name}' not found.")
                return 1

        elif args.policy_action == "evaluate":
            if not self.tm:
                print("No topology loaded.")
                return
            pe = PolicyEngine()
            pe.load_policies(self.tm.policies)
            action, rule = pe.evaluate(
                source_ip=args.source,
                dest_ip=args.destination,
                protocol=args.protocol,
                port=args.port,
            )
            print(f"Flow: {args.source} -> {args.destination}")
            if args.protocol:
                print(f"  Protocol: {args.protocol}")
            if args.port:
                print(f"  Port: {args.port}")
            print(f"  Action: {action}")
            if rule:
                print(f"  Matched rule: {rule}")
            else:
                print(f"  Matched rule: (default)")

    def cmd_config(self, args):
        """Handle config subcommands."""
        if args.config_action == "generate":
            if not self.tm:
                print("No topology loaded.")
                return
            out_dir = Path(args.output_dir or "./configs")
            fmt = args.format or "wg-quick"

            generator = TunnelConfigGenerator(self.tm.to_config())
            written = generator.write_all_configs(out_dir, format=fmt)

            print(f"Generated {len(written)} configs in {out_dir}/")
            if fmt == "amneziawg":
                print("Format: AmneziaWG (with DPI obfuscation)")
            else:
                print(f"Format: {fmt}")
            for name, path in written.items():
                size = path.stat().st_size
                print(f"  {name} -> {path.name} ({size} bytes)")

        elif args.config_action == "show":
            if not self.tm:
                print("No topology loaded.")
                return
            node = self.tm.get_node(args.node_name)
            if not node:
                print(f"Node '{args.node_name}' not found.")
                return

            fmt = args.format or "wg-quick"
            generator = TunnelConfigGenerator(self.tm.to_config())
            node_config = generator.generate_node_config(args.node_name)

            if fmt == "amneziawg":
                print(generator.render_amneziawg_config(node_config))
            elif fmt == "json":
                print(json.dumps(
                    generator.render_json_config(node_config), indent=2
                ))
            else:
                print(generator.render_wg_quick_config(node_config))

        elif args.config_action == "export":
            if not self.tm:
                print("No topology loaded.")
                return
            out_dir = Path(args.output_dir)
            fmt = args.format or "wg-quick"

            generator = TunnelConfigGenerator(self.tm.to_config())
            written = generator.write_all_configs(out_dir, format=fmt)

            print(f"Exported {len(written)} configs to {out_dir}/")
            for name, path in written.items():
                print(f"  {path}")

    def cmd_key(self, args):
        """Handle key subcommands."""
        if args.key_action == "generate":
            kp = self.key_manager.generate_keypair(args.node_name)
            print(f"Generated key pair for '{args.node_name}'")
            print(f"  Public key: {kp.public_key}")

        elif args.key_action == "list":
            keys = self.key_manager.list_keys()
            if not keys:
                print("No keys generated.")
                return
            for name, pubkey in keys.items():
                print(f"  {name}: {pubkey}")

        elif args.key_action == "rotate":
            kp = self.key_manager.rotate_key(args.node_name)
            print(f"Rotated keys for '{args.node_name}'")
            print(f"  New public key: {kp.public_key}")

        elif args.key_action == "save":
            path = Path(args.file) if args.file else None
            self.key_manager.save_keys(path)
            target = path or (Path("./keys") / "sdn_keys.json")
            print(f"Saved keys to {target}")

        elif args.key_action == "load":
            path = Path(args.file)
            self.key_manager.load_keys(path)
            print(f"Loaded {self.key_manager.node_count()} keys from {path}")

    def cmd_server(self, args):
        """Start the REST API server."""
        if not self.tm:
            print("No topology loaded. Use 'topology load' first.")
            return

        from controller.api import create_app

        app = create_app(
            topology_manager=self.tm,
            config_dir=Path(args.config_dir or "./configs"),
        )

        host = args.host or "0.0.0.0"
        port = args.port or 8080
        print(f"Starting SDN Controller API on {host}:{port}")
        print(f"Topology: {self.tm.name}")
        print(f"Endpoints:")
        print(f"  GET  /health")
        print(f"  GET  /api/v1/status")
        print(f"  GET  /api/v1/nodes")
        print(f"  POST /api/v1/nodes")
        print(f"  GET  /api/v1/tunnels")
        print(f"  POST /api/v1/tunnels")
        print(f"  GET  /api/v1/configs/generate")
        print(f"  ...")
        app.run(host=host, port=port, debug=args.debug)


def main():
    parser = argparse.ArgumentParser(
        description="sdnctl - SDN Controller CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--topology-file", "-t",
        help="Path to topology YAML file to load automatically",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── topology ─────────────────────────────────────────────────
    topo_parser = subparsers.add_parser("topology", help="Topology management")
    topo_sub = topo_parser.add_subparsers(dest="topology_action")
    topo_sub.add_parser("show", help="Show current topology")
    topo_sub.add_parser("summary", help="Show topology summary")
    load_parser = topo_sub.add_parser("load", help="Load topology from YAML")
    load_parser.add_argument("file", help="YAML topology file")
    save_parser = topo_sub.add_parser("save", help="Save topology to JSON")
    save_parser.add_argument("file", help="Output file")

    # ── node ─────────────────────────────────────────────────────
    node_parser = subparsers.add_parser("node", help="Node management")
    node_sub = node_parser.add_subparsers(dest="node_action")
    node_sub.add_parser("list", help="List all nodes")
    show_node = node_sub.add_parser("show", help="Show node details")
    show_node.add_argument("node_name", help="Node name")
    add_node = node_sub.add_parser("add", help="Add a node")
    add_node.add_argument("node_name", help="Node name")
    add_node.add_argument("--endpoint", help="Public endpoint (IP:port)")
    add_node.add_argument("--listen-port", type=int, help="Listen port")
    add_node.add_argument("--address", help="Tunnel IP address (CIDR)")
    add_node.add_argument("--allowed-ips", help="Comma-separated allowed IPs")
    remove_node = node_sub.add_parser("remove", help="Remove a node")
    remove_node.add_argument("node_name", help="Node name")

    # ── tunnel ───────────────────────────────────────────────────
    tun_parser = subparsers.add_parser("tunnel", help="Tunnel management")
    tun_sub = tun_parser.add_subparsers(dest="tunnel_action")
    tun_sub.add_parser("list", help="List all tunnels")
    create_tun = tun_sub.add_parser("create", help="Create a tunnel")
    create_tun.add_argument("source", help="Source node")
    create_tun.add_argument("target", help="Target node")
    create_tun.add_argument("--metric", type=int, help="Routing metric")
    remove_tun = tun_sub.add_parser("remove", help="Remove a tunnel")
    remove_tun.add_argument("source", help="Source node")
    remove_tun.add_argument("target", help="Target node")

    # ── policy ───────────────────────────────────────────────────
    pol_parser = subparsers.add_parser("policy", help="Policy management")
    pol_sub = pol_parser.add_subparsers(dest="policy_action")
    pol_sub.add_parser("list", help="List all policies")
    add_pol = pol_sub.add_parser("add", help="Add a policy")
    add_pol.add_argument("policy_name", help="Policy name")
    add_pol.add_argument("--source", required=True, help="Source CIDR/node")
    add_pol.add_argument("--destination", required=True, help="Destination CIDR/node")
    add_pol.add_argument("--action", choices=["allow", "deny"], default="allow")
    add_pol.add_argument("--port", type=int, help="Port number")
    add_pol.add_argument("--protocol", choices=["tcp", "udp", "icmp"], help="Protocol")
    add_pol.add_argument("--priority", type=int, default=100)
    remove_pol = pol_sub.add_parser("remove", help="Remove a policy")
    remove_pol.add_argument("policy_name", help="Policy name")
    eval_pol = pol_sub.add_parser("evaluate", help="Evaluate policy for a flow")
    eval_pol.add_argument("source", help="Source IP")
    eval_pol.add_argument("destination", help="Destination IP")
    eval_pol.add_argument("--protocol", help="Protocol (tcp/udp/icmp)")
    eval_pol.add_argument("--port", type=int, help="Port number")

    # ── config ───────────────────────────────────────────────────
    cfg_parser = subparsers.add_parser("config", help="Configuration generation")
    cfg_sub = cfg_parser.add_subparsers(dest="config_action")
    gen_cfg = cfg_sub.add_parser("generate", help="Generate all configs")
    gen_cfg.add_argument("--format", choices=["wg-quick", "amneziawg", "json"],
                         default="wg-quick")
    gen_cfg.add_argument("--output-dir", help="Output directory")
    show_cfg = cfg_sub.add_parser("show", help="Show node config")
    show_cfg.add_argument("node_name", help="Node name")
    show_cfg.add_argument("--format", choices=["wg-quick", "amneziawg", "json"],
                          default="wg-quick")
    export_cfg = cfg_sub.add_parser("export", help="Export all configs")
    export_cfg.add_argument("output_dir", help="Output directory")
    export_cfg.add_argument("--format", choices=["wg-quick", "amneziawg", "json"],
                            default="wg-quick")

    # ── key ──────────────────────────────────────────────────────
    key_parser = subparsers.add_parser("key", help="Key management")
    key_sub = key_parser.add_subparsers(dest="key_action")
    gen_key = key_sub.add_parser("generate", help="Generate keys for a node")
    gen_key.add_argument("node_name", help="Node name")
    key_sub.add_parser("list", help="List all public keys")
    rot_key = key_sub.add_parser("rotate", help="Rotate keys for a node")
    rot_key.add_argument("node_name", help="Node name")
    save_keys = key_sub.add_parser("save", help="Save keys to file")
    save_keys.add_argument("--file", help="Output file")
    load_keys = key_sub.add_parser("load", help="Load keys from file")
    load_keys.add_argument("file", help="Input file")

    # ── server ───────────────────────────────────────────────────
    srv_parser = subparsers.add_parser("server", help="Start API server")
    srv_parser.add_argument("--host", default="0.0.0.0")
    srv_parser.add_argument("--port", type=int, default=8080)
    srv_parser.add_argument("--config-dir", default="./configs")
    srv_parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    ctl = SdnCtl()

    # Pre-load topology if --topology-file is specified
    if hasattr(args, "topology_file") and args.topology_file:
        from pathlib import Path
        from common.config import load_topology
        from controller.topology import TopologyManager

        path = Path(args.topology_file)
        if not path.exists():
            print(f"Error: topology file not found: {path}")
            sys.exit(1)
        try:
            topo = load_topology(path)
            ctl.tm = TopologyManager(topo, ctl.key_manager)
        except Exception as e:
            print(f"Error loading topology: {e}")
            sys.exit(1)

    # Map command to handler
    handlers = {
        "topology": ctl.cmd_topology,
        "node": ctl.cmd_node,
        "tunnel": ctl.cmd_tunnel,
        "policy": ctl.cmd_policy,
        "config": ctl.cmd_config,
        "key": ctl.cmd_key,
        "server": ctl.cmd_server,
    }

    handler = handlers.get(args.command)
    if handler:
        result = handler(args)
        if result:
            sys.exit(result)


if __name__ == "__main__":
    main()
