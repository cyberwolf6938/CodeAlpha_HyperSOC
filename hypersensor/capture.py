# hypersensor/capture.py

from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from hypersensor.pcap import save_packet
from hypersensor.ids import analyze_packet, analyze_arp
from hypersensor.stats import record_packet
from hypersensor.dashboard import dashboard_loop
from scapy.layers.l2 import ARP
from hypersensor.stats import (
    record_packet,
    print_stats
)
from hypersensor.stats import record_live_packet
import threading
import time

# Start statistics printing thread
def process_packet(packet):

    if packet.haslayer(ARP):

        analyze_arp(
            packet[ARP].psrc,
            packet[ARP].hwsrc
        )

        return

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
    
    elif packet.haslayer(UDP):

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):

        protocol = "ICMP"
    packet_size = len(packet)
    DEBUG_PACKETS = False
    if DEBUG_PACKETS:
     print(
        f"{src_ip}:{src_port} -> "
        f"{dst_ip}:{dst_port} | "
        f"{protocol} | "
        f"{packet_size} bytes"
    )

    record_packet(protocol, src_ip)
    record_live_packet(src_ip, dst_ip, protocol, packet_size)

    alert_type = "SUSPICIOUS"
    is_suspicious = analyze_packet(
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size,
        tcp_flags if protocol == "TCP" else None
    )

    if is_suspicious:
        save_packet(
            packet,
            alert_type
        )


def start_capture():

    print("[*] HyperSOC Started")
    
    threading.Thread(
    target=dashboard_loop,
    daemon=True
).start()


    sniff(
        prn=process_packet,
        store=False
    )