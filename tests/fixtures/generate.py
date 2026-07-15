"""Regenerate the committed demo pcaps.

Run from the repo root:  uv run python tests/fixtures/generate.py

The captures are synthetic (scapy-crafted, RFC1918/documentation addresses
only) so they are safe to commit and replay anywhere.
"""

from __future__ import annotations

import random
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

HERE = Path(__file__).parent
START = 1_700_000_000.0  # fixed epoch so replays are deterministic


def pkt_tcp(src, dst, dport, ts, sport=40123, flags="S"):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = ts
    return p


def pkt_udp(src, dst, dport, ts, sport=40123):
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    p.time = ts
    return p


def browsing(client: str, ts: float, dport: int = 443) -> list:
    sport = random.randint(45000, 65000)
    server = f"203.0.113.{random.randint(1, 50)}"
    return [
        pkt_tcp(client, server, dport, ts, sport, "S"),
        pkt_tcp(server, client, sport, ts + 0.01, dport, "SA"),
        pkt_tcp(client, server, dport, ts + 0.02, sport, "A"),
        pkt_tcp(client, server, dport, ts + 0.30, sport, "PA"),
        pkt_tcp(server, client, sport, ts + 0.35, dport, "PA"),
        pkt_tcp(client, server, dport, ts + 1.50, sport, "FA"),
    ]


def pkt_arp_reply(sender_ip, sender_mac, target_ip, target_mac, ts):
    p = Ether(src=sender_mac, dst=target_mac) / ARP(
        op=2, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip
    )
    p.time = ts
    return p


def main() -> None:
    random.seed(1337)

    # -- portscan.pcap: background browsing + a SYN scan + one 4444 hit ------
    packets = []
    ts = START
    for i in range(6):  # a minute of ordinary traffic first
        packets += browsing(f"192.168.1.{20 + i % 3}", ts)
        packets.append(pkt_udp(f"192.168.1.{20 + i % 3}", "192.168.1.1", 53, ts + 0.005))
        ts += 8.0

    scan_start = ts
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9100]
    for i, port in enumerate(common_ports):
        packets.append(
            pkt_tcp("192.168.1.66", "192.168.1.10", port, scan_start + i * 0.12,
                    sport=54321)
        )
    ts = scan_start + 5.0

    packets += browsing("192.168.1.21", ts)  # life goes on
    packets.append(pkt_tcp("192.168.1.66", "192.168.1.10", 4444, ts + 3.0, flags="S"))

    packets.sort(key=lambda p: p.time)
    wrpcap(str(HERE / "portscan.pcap"), packets)
    print(f"portscan.pcap: {len(packets)} packets")

    # -- benign.pcap: nothing but ordinary traffic ---------------------------
    packets = []
    ts = START
    for i in range(10):
        packets += browsing(f"192.168.1.{20 + i % 4}", ts, dport=443 if i % 2 else 80)
        packets.append(pkt_udp(f"192.168.1.{20 + i % 4}", "192.168.1.1", 53, ts + 0.005))
        ts += 5.0
    wrpcap(str(HERE / "benign.pcap"), packets)
    print(f"benign.pcap: {len(packets)} packets")

    # -- arpspoof.pcap: gateway impersonation mid-browsing --------------------
    gateway_ip = "192.168.1.1"
    gateway_mac = "52:54:00:aa:00:01"
    attacker_mac = "52:54:00:ee:66:66"
    victim_mac = "52:54:00:bb:00:20"

    packets = []
    ts = START
    for i in range(4):  # normal ARP refreshes from the real gateway
        packets += browsing("192.168.1.20", ts)
        packets.append(
            pkt_arp_reply(gateway_ip, gateway_mac, "192.168.1.20", victim_mac, ts + 0.002)
        )
        ts += 10.0
    # attacker claims the gateway IP, then keeps re-poisoning the cache
    for i in range(6):
        packets.append(
            pkt_arp_reply(gateway_ip, attacker_mac, "192.168.1.20", victim_mac, ts + i * 2.0)
        )
    packets.sort(key=lambda p: p.time)
    wrpcap(str(HERE / "arpspoof.pcap"), packets)
    print(f"arpspoof.pcap: {len(packets)} packets")


if __name__ == "__main__":
    main()
