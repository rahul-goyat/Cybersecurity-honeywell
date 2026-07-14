"""
packet_generator.py
Generates simulated network traffic (normal + suspicious) so the
firewall can be tested without needing a real network.
"""

import random
from firewall import Packet

NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"]
SERVER_IPS = ["192.168.1.100"]
SUSPICIOUS_IPS = ["203.0.113.5", "198.51.100.23", "45.33.32.156"]
COMMON_PORTS = [80, 443, 22, 21, 3306, 53]


def normal_packet():
    return Packet(
        src_ip=random.choice(NORMAL_IPS),
        dst_ip=random.choice(SERVER_IPS),
        src_port=random.randint(1024, 65535),
        dst_port=random.choice(COMMON_PORTS),
        protocol=random.choice(["TCP", "UDP"]),
        size=random.randint(64, 1500),
    )


def suspicious_packet():
    return Packet(
        src_ip=random.choice(SUSPICIOUS_IPS),
        dst_ip=random.choice(SERVER_IPS),
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([23, 3389, 445, 4444, 8080]),
        protocol="TCP",
        size=random.randint(40, 100),
    )


def port_scan_burst(target_ip=SERVER_IPS[0], attacker_ip="198.51.100.23", n=20):
    """Simulate an attacker sweeping many destination ports quickly."""
    ports = random.sample(range(1, 65000), n)
    return [Packet(attacker_ip, target_ip, random.randint(1024, 65535), p, "TCP", size=40)
            for p in ports]


def dos_burst(target_ip=SERVER_IPS[0], attacker_ip="45.33.32.156", n=30):
    """Simulate a flood of packets from a single source (basic DoS pattern)."""
    return [Packet(attacker_ip, target_ip, random.randint(1024, 65535), 80, "TCP", size=64)
            for _ in range(n)]


def generate_mixed_traffic(n=40):
    """Generate a shuffled mix of mostly normal traffic with some suspicious packets."""
    packets = []
    for _ in range(n):
        packets.append(normal_packet() if random.random() < 0.7 else suspicious_packet())
    random.shuffle(packets)
    return packets
