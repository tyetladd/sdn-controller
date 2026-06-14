"""
REST API for the SDN Controller.

Provides HTTP endpoints for managing the SDN:
- Topology CRUD
- Node management
- Tunnel management
- Policy management
- Config generation and distribution
- Status and health checks

Uses Flask for the HTTP server with JSON request/response format.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify, Response

from controller.topology import TopologyManager
from controller.tunnel import TunnelConfigGenerator
from controller.policy import PolicyEngine


def create_app(
    topology_manager: TopologyManager,
    policy_engine: Optional[PolicyEngine] = None,
    config_dir: Optional[Path] = None,
) -> Flask:
    """Create and configure the Flask application.

    Args:
        topology_manager: The topology manager instance
        policy_engine: Optional policy engine instance
        config_dir: Directory for generated config files

    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    tm = topology_manager
    pe = policy_engine or PolicyEngine()
    cfg_dir = config_dir or Path("./configs")

    # ── Health & Status ──────────────────────────────────────────

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok", "controller": tm.name})

    @app.route("/api/v1/status", methods=["GET"])
    def status():
        """Get full controller status."""
        return jsonify(tm.get_topology_summary())

    # ── Topology ─────────────────────────────────────────────────

    @app.route("/api/v1/topology", methods=["GET"])
    def get_topology():
        """Get the full topology."""
        return jsonify(tm.export())

    @app.route("/api/v1/topology", methods=["PUT"])
    def update_topology():
        """Replace the entire topology."""
        data = request.get_json(force=True)
        try:
            tm.import_from_dict(data)
            return jsonify({"status": "ok", "version": tm.version})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # ── Nodes ────────────────────────────────────────────────────

    @app.route("/api/v1/nodes", methods=["GET"])
    def list_nodes():
        """List all nodes."""
        return jsonify(tm.list_nodes())

    @app.route("/api/v1/nodes/<name>", methods=["GET"])
    def get_node(name: str):
        """Get a specific node."""
        node = tm.get_node(name)
        if not node:
            return jsonify({"error": f"Node '{name}' not found"}), 404
        return jsonify(node.to_dict())

    @app.route("/api/v1/nodes", methods=["POST"])
    def add_node():
        """Add a new node."""
        data = request.get_json(force=True)
        try:
            node = tm.add_node(
                name=data["name"],
                endpoint=data.get("endpoint"),
                listen_port=data.get("listen_port", 51820),
                address=data.get("address"),
                allowed_ips=data.get("allowed_ips", []),
                tags=data.get("tags"),
            )
            return jsonify(node.to_dict()), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        except KeyError as e:
            return jsonify({"error": f"Missing field: {e}"}), 400

    @app.route("/api/v1/nodes/<name>", methods=["DELETE"])
    def delete_node(name: str):
        """Remove a node."""
        if tm.remove_node(name):
            return jsonify({"status": "deleted", "node": name})
        return jsonify({"error": f"Node '{name}' not found"}), 404

    # ── Tunnels ──────────────────────────────────────────────────

    @app.route("/api/v1/tunnels", methods=["GET"])
    def list_tunnels():
        """List all tunnels."""
        return jsonify(tm.list_tunnels())

    @app.route("/api/v1/tunnels", methods=["POST"])
    def create_tunnel():
        """Create a new tunnel."""
        data = request.get_json(force=True)
        try:
            tunnel = tm.create_tunnel(
                source_node=data["source"],
                target_node=data["target"],
                metric=data.get("metric", 1),
            )
            return jsonify(tunnel.to_dict()), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @app.route(
        "/api/v1/tunnels/<source>/<target>", methods=["DELETE"]
    )
    def delete_tunnel(source: str, target: str):
        """Remove a tunnel."""
        if tm.remove_tunnel(source, target):
            return jsonify(
                {"status": "deleted", "source": source, "target": target}
            )
        return jsonify({"error": "Tunnel not found"}), 404

    # ── Runtime Reconfiguration ──────────────────────────────────

    @app.route("/api/v1/nodes/<name>/allowed-ips", methods=["PUT"])
    def update_node_allowed_ips(name: str):
        """Update a node's AllowedIPs at runtime (live reconfiguration).

        Request body: {"allowed_ips": ["10.20.1.0/24", "10.99.0.0/24"]}

        Returns the diff and the list of peers that need updating.
        No tunnels are dropped — peers can be updated via `wg set`.
        """
        data = request.get_json(force=True)
        new_ips = data.get("allowed_ips", [])
        try:
            result = tm.update_node_allowed_ips(name, new_ips)
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @app.route("/api/v1/nodes/<name>/allowed-ips/add", methods=["POST"])
    def add_node_prefix(name: str):
        """Add a single prefix to a node's AllowedIPs (live).

        Request body: {"prefix": "10.99.0.0/24"}

        Example: a remote gateway starts advertising a new subnet.
        Call this and all peers get the new route without re-handshaking.
        """
        data = request.get_json(force=True)
        prefix = data.get("prefix", "")
        if not prefix:
            return jsonify({"error": "prefix is required"}), 400
        try:
            result = tm.add_node_prefix(name, prefix)
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @app.route("/api/v1/nodes/<name>/allowed-ips/remove", methods=["POST"])
    def remove_node_prefix(name: str):
        """Remove a single prefix from a node's AllowedIPs (live).

        Request body: {"prefix": "10.99.0.0/24"}
        """
        data = request.get_json(force=True)
        prefix = data.get("prefix", "")
        if not prefix:
            return jsonify({"error": "prefix is required"}), 400
        try:
            result = tm.remove_node_prefix(name, prefix)
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    # ── Policies ─────────────────────────────────────────────────

    @app.route("/api/v1/policies", methods=["GET"])
    def list_policies():
        """List all policies."""
        return jsonify(tm.list_policies())

    @app.route("/api/v1/policies", methods=["POST"])
    def add_policy():
        """Add a new policy."""
        data = request.get_json(force=True)
        try:
            policy = tm.add_policy(
                name=data["name"],
                source=data["source"],
                destination=data["destination"],
                action=data.get("action", "allow"),
                port=data.get("port"),
                protocol=data.get("protocol"),
                priority=data.get("priority", 100),
            )
            return jsonify(policy.to_dict()), 201
        except KeyError as e:
            return jsonify({"error": f"Missing field: {e}"}), 400

    @app.route("/api/v1/policies/<name>", methods=["DELETE"])
    def delete_policy(name: str):
        """Remove a policy."""
        if tm.remove_policy(name):
            return jsonify({"status": "deleted", "policy": name})
        return jsonify({"error": "Policy not found"}), 404

    # ── Config Generation ────────────────────────────────────────

    @app.route("/api/v1/configs", methods=["GET"])
    def list_configs():
        """List available generated configs."""
        if not cfg_dir.exists():
            return jsonify({"configs": {}})
        files = {}
        for f in cfg_dir.iterdir():
            if f.is_file():
                files[f.name] = str(f)
        return jsonify({"config_dir": str(cfg_dir), "configs": files})

    @app.route("/api/v1/configs/generate", methods=["POST"])
    def generate_configs():
        """Generate and write all node configs."""
        data = request.get_json(silent=True) or {}
        format_type = data.get("format", "wg-quick")

        generator = TunnelConfigGenerator(tm.to_config())
        written = generator.write_all_configs(cfg_dir, format=format_type)

        return jsonify({
            "status": "generated",
            "format": format_type,
            "files": {k: str(v) for k, v in written.items()},
        })

    @app.route(
        "/api/v1/configs/<node_name>", methods=["GET"]
    )
    def get_node_config(node_name: str):
        """Get the generated config for a specific node."""
        node = tm.get_node(node_name)
        if not node:
            return jsonify({"error": f"Node '{node_name}' not found"}), 404

        format_type = request.args.get("format", "wg-quick")
        generator = TunnelConfigGenerator(tm.to_config())
        node_config = generator.generate_node_config(node_name)

        if format_type == "amneziawg":
            content = generator.render_amneziawg_config(node_config)
        elif format_type == "json":
            content = json.dumps(
                generator.render_json_config(node_config), indent=2
            )
        else:
            content = generator.render_wg_quick_config(node_config)

        return Response(content, mimetype="text/plain")

    @app.route("/api/v1/configs/<node_name>/peers", methods=["GET"])
    def get_node_peers(node_name: str):
        """Get peer list for a specific node."""
        peers = tm.get_node_peers(node_name)
        return jsonify([
            {
                "name": p.name,
                "endpoint": p.endpoint,
                "public_key": p.public_key,
                "address": p.address,
            }
            for p in peers
        ])

    # ── Policy Evaluation ────────────────────────────────────────

    @app.route("/api/v1/evaluate", methods=["POST"])
    def evaluate_policy():
        """Evaluate a flow against the current policies.

        Request body: {"source_ip": "...", "dest_ip": "...", ...}
        """
        data = request.get_json(force=True)
        pe.load_policies(tm.policies)
        action, rule = pe.evaluate(
            source_ip=data["source_ip"],
            dest_ip=data["dest_ip"],
            protocol=data.get("protocol"),
            port=data.get("port"),
        )
        return jsonify({
            "action": action,
            "matched_rule": rule,
            "flow": data,
        })

    @app.route("/api/v1/policies/stats", methods=["GET"])
    def policy_stats():
        """Get policy evaluation statistics."""
        pe.load_policies(tm.policies)
        return jsonify(pe.get_stats())

    return app
