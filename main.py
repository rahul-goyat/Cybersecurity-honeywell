"""
main.py
Interactive command-line interface for the Firewall Simulator.
Run this file to load the rule set, simulate traffic, launch attack
scenarios, and inspect logs/statistics.
"""

import os
from firewall import Firewall, Rule, Packet
import packet_generator as pg

RULES_FILE = "rules.json"
LOG_FILE = "logs/firewall_log.json"


def banner():
    print("=" * 55)
    print("     FIREWALL SIMULATOR - CYBERSECURITY PROJECT")
    print("=" * 55)


def print_rules(fw):
    if not fw.rules:
        print("No rules configured.")
    for r in fw.rules:
        print(r)
    print(f"Default policy: {fw.default_policy}")


def add_rule_interactive(fw):
    rule_id = input("Rule ID: ")
    action = input("Action (ALLOW/DENY): ")
    protocol = input("Protocol (TCP/UDP/ICMP/ANY) [ANY]: ") or "ANY"
    src_ip = input("Source IP / CIDR / any [any]: ") or "any"
    dst_ip = input("Destination IP / CIDR / any [any]: ") or "any"
    src_port = input("Source port / range / any [any]: ") or "any"
    dst_port = input("Destination port / range / any [any]: ") or "any"
    priority = int(input("Priority (lower = checked first) [100]: ") or 100)
    desc = input("Description: ")
    fw.add_rule(Rule(rule_id, action, protocol, src_ip, dst_ip, src_port, dst_port, priority, desc))
    print("Rule added.\n")


def simulate(fw, count):
    packets = pg.generate_mixed_traffic(count)
    for p in packets:
        res = fw.process_packet(p)
        tag = "ALLOW" if res["action"] == "ALLOW" else "DENY "
        print(f"[{tag}] {res['packet']:<48} | {res['reason']}")


def simulate_attack(fw, kind):
    packets = pg.port_scan_burst() if kind == "portscan" else pg.dos_burst()
    for p in packets:
        res = fw.process_packet(p)
        tag = "ALLOW" if res["action"] == "ALLOW" else "DENY "
        print(f"[{tag}] {res['packet']:<48} | {res['reason']}")


def main():
    banner()
    fw = Firewall(default_policy="DENY", rate_limit=15, rate_window=5)
    if os.path.exists(RULES_FILE):
        fw.load_rules(RULES_FILE)
        print(f"Loaded rules from {RULES_FILE}\n")

    menu = """
1. View rules
2. Add rule
3. Delete rule
4. Save rules
5. Simulate normal/mixed traffic
6. Simulate port scan attack
7. Simulate DoS burst attack
8. Test a custom packet
9. View statistics
10. View blocked IPs
11. Export logs
0. Exit
"""
    while True:
        print(menu)
        choice = input("Select option: ").strip()

        if choice == "1":
            print_rules(fw)
        elif choice == "2":
            add_rule_interactive(fw)
        elif choice == "3":
            rid = input("Rule ID to delete: ")
            fw.remove_rule(rid)
        elif choice == "4":
            fw.save_rules(RULES_FILE)
            print("Rules saved.")
        elif choice == "5":
            n = int(input("How many packets? [20]: ") or 20)
            simulate(fw, n)
        elif choice == "6":
            simulate_attack(fw, "portscan")
        elif choice == "7":
            simulate_attack(fw, "dos")
        elif choice == "8":
            src_ip = input("Source IP: ")
            dst_ip = input("Destination IP: ")
            src_port = int(input("Source port: "))
            dst_port = int(input("Destination port: "))
            protocol = input("Protocol: ")
            res = fw.process_packet(Packet(src_ip, dst_ip, src_port, dst_port, protocol))
            print(res)
        elif choice == "9":
            print(fw.summary())
        elif choice == "10":
            print(fw.blocked_ips or "None blocked yet.")
        elif choice == "11":
            os.makedirs("logs", exist_ok=True)
            fw.export_log(LOG_FILE)
            print(f"Logs exported to {LOG_FILE}")
        elif choice == "0":
            print("Exiting. Stay secure!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
