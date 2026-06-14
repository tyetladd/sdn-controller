"""
Policy engine for SDN access control.

Evaluates and enforces network access policies between nodes and subnets.
Supports:
- Allow/deny actions
- Protocol and port filtering
- Priority-based rule ordering
- Subnet-level rules
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set, Tuple

from common.config import PolicyRule, TopologyConfig, NodeConfig


class PolicyEngine:
    """Evaluates access control policies for the SDN.

    Policies are evaluated in priority order (lower number = higher priority).
    The first matching rule determines the action. If no rule matches,
    the default action is 'deny' (zero-trust model).
    """

    DEFAULT_ACTION = "deny"  # Zero-trust: deny by default

    def __init__(self, default_action: str = "deny"):
        self._rules: List[PolicyRule] = []
        self._default_action = default_action
        self._hit_counts: Dict[str, int] = {}

    def load_policies(self, rules: List[PolicyRule]) -> None:
        """Load and sort policies by priority."""
        self._rules = sorted(rules, key=lambda r: r.priority)
        self._hit_counts = {r.name: 0 for r in rules}

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule and re-sort by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        self._hit_counts[rule.name] = 0

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        initial = len(self._rules)
        self._rules = [r for r in self._rules if r.name != rule_name]
        self._hit_counts.pop(rule_name, None)
        return len(self._rules) < initial

    def evaluate(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Tuple[str, Optional[str]]:
        """Evaluate policies for a given flow.

        Returns:
            Tuple of (action, matched_rule_name).
            If no rule matches, returns (default_action, None).
        """
        try:
            src = ipaddress.ip_address(source_ip)
            dst = ipaddress.ip_address(dest_ip)
        except ValueError:
            return (self._default_action, None)

        for rule in self._rules:
            # Check source match
            if not self._ip_matches_rule(src, rule.source):
                continue

            # Check destination match
            if not self._ip_matches_rule(dst, rule.destination):
                continue

            # Check protocol
            if rule.protocol and protocol:
                if rule.protocol.lower() != protocol.lower():
                    continue

            # Check port
            if rule.port and port:
                if rule.port != port:
                    continue

            # Rule matched
            self._hit_counts[rule.name] = self._hit_counts.get(rule.name, 0) + 1
            return (rule.action, rule.name)

        # No rule matched — apply default
        return (self._default_action, None)

    def evaluate_bulk(
        self, flows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Evaluate multiple flows at once.

        Each flow dict should have: source_ip, dest_ip, [protocol], [port].
        Returns the same list with 'action' and 'matched_rule' added.
        """
        results = []
        for flow in flows:
            action, rule_name = self.evaluate(
                source_ip=flow["source_ip"],
                dest_ip=flow["dest_ip"],
                protocol=flow.get("protocol"),
                port=flow.get("port"),
            )
            result = {**flow, "action": action, "matched_rule": rule_name}
            results.append(result)
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        return {
            "total_rules": len(self._rules),
            "default_action": self._default_action,
            "hit_counts": dict(self._hit_counts),
            "rules": [
                {
                    "name": r.name,
                    "action": r.action,
                    "priority": r.priority,
                    "hits": self._hit_counts.get(r.name, 0),
                }
                for r in self._rules
            ],
        }

    def _ip_matches_rule(
        self, ip: ipaddress.IPv4Address, rule_target: str
    ) -> bool:
        """Check if an IP matches a rule target (CIDR or exact IP)."""
        try:
            network = ipaddress.ip_network(rule_target, strict=False)
            return ip in network
        except ValueError:
            # Not a valid CIDR — could be a node name, we skip
            return False

    def to_firewall_rules(
        self, interface: str = "wg0"
    ) -> List[str]:
        """Export all policies as iptables commands."""
        commands = []
        for rule in self._rules:
            chain = "FORWARD"
            action = "ACCEPT" if rule.action == "allow" else "DROP"

            cmd = f"iptables -A {chain} -i {interface} -o {interface}"
            if rule.source:
                cmd += f" -s {rule.source}"
            if rule.destination:
                cmd += f" -d {rule.destination}"
            if rule.protocol:
                cmd += f" -p {rule.protocol}"
            if rule.port is not None:
                cmd += f" --dport {rule.port}"
            cmd += f" -j {action}"
            cmd += f' -m comment --comment "sdn:{rule.name}"'
            commands.append(cmd)

        return commands
