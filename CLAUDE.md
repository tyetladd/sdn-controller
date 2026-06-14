# CLAUDE.md — SDN Controller over AmneziaWG Tunnels

## Project Overview

A Software-Defined Networking (SDN) prototype that manages overlay networks using WireGuard and AmneziaWG tunnels. The controller handles topology definition, key management, tunnel configuration generation, policy-based access control, and per-node agent management.

**Status:** Prototype — generates deployable configs; does not require kernel modules to run the controller.

## Architecture

```
                 ┌──────────────────────────┐
                 │    REST API (Flask)       │
                 │    sdnctl CLI             │
                 ├──────────────────────────┤
                 │  Topology Manager         │
                 │  Tunnel Config Generator  │
                 │  Policy Engine            │
                 │  Key Manager              │
                 ├──────────────────────────┤
                 │  Node Agent (per-node)    │
                 │  Node Monitor             │
                 └──────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
      ┌─────────┐  ┌─────────┐  ┌─────────┐
      │ Node A  │  │ Node B  │  │ Node C  │
      │ wg-quick│  │ wg-quick│  │ wg-quick│
      └─────────┘  └─────────┘  └─────────┘
```

## Directory Structure

```
sdn-controller/
├── common/           # Shared foundation (no controller deps)
│   ├── config.py     # Topology YAML parsing, dataclasses, validation
│   ├── keys.py       # Curve25519 key generation, rotation, storage
│   └── net.py        # IP allocator, CIDR validation, Dijkstra routing
├── controller/       # Central control plane
│   ├── topology.py   # Node/tunnel/policy lifecycle
│   ├── tunnel.py     # WG + AmneziaWG config generator (3 formats)
│   ├── policy.py     # Zero-trust access control engine
│   └── api.py        # Flask REST API (15+ endpoints)
├── node/             # Per-node agent
│   ├── agent.py      # Config application, controller comms
│   └── monitor.py    # Health checks, traffic stats, alerts
├── cli/
│   └── sdnctl.py     # CLI management tool
├── examples/         # Deployable topology definitions
│   ├── mesh.yaml     # Full mesh (4 nodes, 6 tunnels, AmneziaWG)
│   ├── hub_spoke.yaml
│   ├── site_to_site.yaml
│   └── simple_pair.yaml
├── demo.py           # Comprehensive end-to-end demo
└── requirements.txt
```

## Key Design Decisions

1. **TunnelConfig uses `source_node`/`target_node` internally** but serializes as `source`/`target` for YAML readability. The `_parse_tunnel_dict` static method handles the mapping.

2. **TopologyManager auto-generates keys** for nodes loaded from YAML that don't have them (via `_auto_assign_keys()` in `__init__`).

3. **Policy engine is zero-trust by default** — unmatched flows get `DENY`. Rules are evaluated in priority order (lower number = higher priority).

4. **Three config output formats:**
   - `wg-quick`: Standard WireGuard INI format
   - `amneziawg`: WG config + AmneziaWG obfuscation params (Jc, Jmin, Jmax, S1, S2)
   - `json`: Machine-readable for API consumption

5. **Node agent operates in two modes:**
   - Managed: fetches config from controller API, reports status
   - Standalone: reads local topology/config files

## Common Commands

```bash
# Run the full demo
python3 demo.py

# CLI with topology file
python3 cli/sdnctl.py -t examples/mesh.yaml node list
python3 cli/sdnctl.py -t examples/mesh.yaml config generate --format amneziawg
python3 cli/sdnctl.py -t examples/hub_spoke.yaml policy list

# Start API server
python3 cli/sdnctl.py -t examples/simple_pair.yaml server --port 8080

# Test API endpoints
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/nodes
```

## Dependencies

- Python 3.9+
- PyYAML (topology parsing)
- Flask (REST API)
- requests (node agent → controller comms)
- WireGuard tools (`wg`, `wg-quick`) — for key gen and config application on real nodes
- wireguard-go — userspace fallback when kernel module unavailable

## AmneziaWG Obfuscation Parameters

AmneziaWG extends WireGuard with DPI evasion. Configurable per-node or per-topology:

| Param | Meaning | Default |
|-------|---------|---------|
| `Jc` | Junk packet count before real data | 5 |
| `Jmin` | Min junk packet size (bytes) | 40 |
| `Jmax` | Max junk packet size (bytes) | 80 |
| `S1` | Init packet obfuscation string | — |
| `S2` | Response packet obfuscation string | — |
| `H` | Header obfuscation keys | — |
