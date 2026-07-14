"""
firewall.py
Core engine for the Firewall Simulator project.

Contains the Rule, Packet and Firewall classes. The Firewall class
matches incoming packets against a prioritized rule list, applies a
default policy when nothing matches, and layers a simple rate-limiter
on top to simulate DoS protection.
"""

import ipaddress
import json
import time
from datetime import datetime
from collections import defaultdict, deque


class Rule:
    """A single firewall rule."""

    def __init__(self, rule_id, action, protocol="ANY", src_ip="any", dst_ip="any",
                 src_port="any", dst_port="any", priority=100, description=""):
        self.rule_id = rule_id
        self.action = action.upper()          # ALLOW or DENY
        self.protocol = protocol.upper()       # TCP / UDP / ICMP / ANY
        self.src_ip = src_ip                   # "any", exact IP, or CIDR
        self.dst_ip = dst_ip
        self.src_port = src_port               # "any", exact port, or "low-high" range
        self.dst_port = dst_port
        self.priority = priority               # lower number = evaluated first
        self.description = description

    def to_dict(self):
        return self.__dict__

    @staticmethod
    def from_dict(d):
        return Rule(**d)

    def __str__(self):
        return (f"[{self.rule_id}] priority={self.priority:<3} {self.action:<5} "
                f"{self.protocol:<4} {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port}   ({self.description})")


def _ip_match(rule_value, packet_ip):
    """Check whether a packet IP matches a rule's IP field (supports CIDR)."""
    if rule_value == "any":
        return True
    try:
        if "/" in rule_value:
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_value, strict=False)
        return rule_value == packet_ip
    except ValueError:
        return False


def _port_match(rule_value, packet_port):
    """Check whether a packet port matches a rule's port field (supports ranges)."""
    if rule_value == "any":
        return True
    rule_value = str(rule_value)
    if "-" in rule_value:
        lo, hi = rule_value.split("-")
        return int(lo) <= packet_port <= int(hi)
    return int(rule_value) == packet_port


class Packet:
    """A simulated network packet."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, size=64, flags=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        self.size = size
        self.flags = flags
        self.timestamp = datetime.now()

    def __str__(self):
        return (f"{self.protocol} {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} ({self.size}B)")


class Firewall:
    """
    Rule-based packet filter with a basic rate-limiter.

    default_policy: what to do when no rule matches ("ALLOW" or "DENY")
    rate_limit / rate_window: max packets allowed from one source IP within
        the window (seconds) before that IP is auto-blocked - simulates
        simple DoS / port-scan protection.
    """

    def __init__(self, default_policy="DENY", rate_limit=15, rate_window=5):
        self.rules = []
        self.default_policy = default_policy.upper()
        self.logs = []
        self.blocked_ips = set()
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self._traffic_window = defaultdict(deque)
        self.stats = {"total": 0, "allowed": 0, "denied": 0, "rate_blocked": 0}

    # ---------------- rule management ----------------
    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id):
        self.rules = [r for r in self.rules if r.rule_id != rule_id]

    def load_rules(self, path):
        with open(path) as f:
            data = json.load(f)
        self.default_policy = data.get("default_policy", self.default_policy).upper()
        self.rules = [Rule.from_dict(r) for r in data.get("rules", [])]
        self.rules.sort(key=lambda r: r.priority)

    def save_rules(self, path):
        data = {
            "default_policy": self.default_policy,
            "rules": [r.to_dict() for r in self.rules],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    # ---------------- rate limiting ----------------
    def _check_rate_limit(self, src_ip):
        now = time.time()
        window = self._traffic_window[src_ip]
        window.append(now)
        while window and now - window[0] > self.rate_window:
            window.popleft()
        if len(window) > self.rate_limit:
            self.blocked_ips.add(src_ip)
            return False
        return True

    # ---------------- core matching ----------------
    def match_packet(self, packet: Packet):
        for rule in self.rules:
            if rule.protocol != "ANY" and rule.protocol != packet.protocol:
                continue
            if not _ip_match(rule.src_ip, packet.src_ip):
                continue
            if not _ip_match(rule.dst_ip, packet.dst_ip):
                continue
            if not _port_match(rule.src_port, packet.src_port):
                continue
            if not _port_match(rule.dst_port, packet.dst_port):
                continue
            return rule
        return None

    def process_packet(self, packet: Packet):
        self.stats["total"] += 1
        result = {
            "packet": str(packet),
            "timestamp": packet.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }

        if packet.src_ip in self.blocked_ips:
            result.update(action="DENY", reason="Source IP already blocked (rate limit)")
            self.stats["denied"] += 1
            self.logs.append(result)
            return result

        if not self._check_rate_limit(packet.src_ip):
            result.update(action="DENY", reason="Rate limit exceeded - possible DoS/port scan")
            self.stats["denied"] += 1
            self.stats["rate_blocked"] += 1
            self.logs.append(result)
            return result

        matched = self.match_packet(packet)
        if matched:
            action = matched.action
            reason = f"Matched rule [{matched.rule_id}] {matched.description}"
        else:
            action = self.default_policy
            reason = "No matching rule - default policy applied"

        result.update(action=action, reason=reason)
        if action == "ALLOW":
            self.stats["allowed"] += 1
        else:
            self.stats["denied"] += 1
        self.logs.append(result)
        return result

    # ---------------- reporting ----------------
    def export_log(self, path):
        with open(path, "w") as f:
            json.dump(self.logs, f, indent=2)

    def summary(self):
        return self.stats
