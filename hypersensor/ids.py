# hypersensor/ids.py

from collections import defaultdict, deque
import time

from hypersensor.config import *
from hypersensor.logger import write_alert
from hypersensor.stats import (
    record_alert,
    record_attacker
)
from hypersensor.severity import SEVERITY
from hypersensor.reputation import is_trusted
from hypersensor.threatintel import is_malicious
# ===================================

# Runtime Storage
# ===================================

packet_times = defaultdict(deque)
port_tracker = defaultdict(set)
last_alert = defaultdict(float)
dns_tracker = defaultdict(deque)
syn_tracker = defaultdict(deque)
brute_tracker = defaultdict(deque)
icmp_tracker = defaultdict(deque)

def alert(message, alert_type, src_ip=None):

    severity = SEVERITY.get(
        alert_type,
        "LOW"
    )

    print(
        f"\n[{severity}] "
        f"{alert_type} | "
        f"{message}"
    )

    write_alert(
        f"[{severity}] "
        f"{alert_type} | "
        f"{message}"
    )

    record_alert(
        alert_type,
        severity,
        message,
        src_ip
    )


def analyze_packet(
    src_ip,
    dst_ip,
    protocol,
    src_port,
    dst_port,
    packet_size,
    tcp_flags=None
):

    suspicious = False
    alert_type = None
    
    now = time.time()

    # ------------------
    # Ignore Whitelist
    # ------------------

    # Ignore packets where either source or destination is whitelisted/trusted
    if (
        src_ip in WHITELIST
        or dst_ip in WHITELIST
        or is_trusted(src_ip)
        or is_trusted(dst_ip)
    ):
        return False, alert_type
    # ------------------
    # Threat Intel Check
    # ------------------

    if is_malicious(src_ip):

        key = f"intel_{src_ip}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Known Malicious IP Detected: {src_ip}",
                "ThreatIntel",
                src_ip
            )

            if not is_trusted(src_ip):
                record_attacker(src_ip)

            suspicious = True
            last_alert[key] = now
    # ------------------
    # DNS Flood Detection
    # ------------------

    if dst_port == 53:

        dns_tracker[src_ip].append(now)

    while (
        dns_tracker[src_ip]
        and now - dns_tracker[src_ip][0] > 5
    ):
        dns_tracker[src_ip].popleft()

    dns_rate = len(dns_tracker[src_ip])

    if dns_rate >= DNS_FLOOD_THRESHOLD:

        key = f"dns_{src_ip}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Possible DNS Flood From {src_ip} ({dns_rate} queries)",
                "DNSFlood",
                src_ip
            )

            if not is_trusted(src_ip):
                record_attacker(src_ip)

            suspicious = True

            last_alert[key] = now
    
    # Ignore local LAN traffic
    #if src_ip.startswith("192.168."):
     #   return False

    # ------------------
    # Ignore QUIC Only
    # ------------------

    if protocol == "UDP":

        if src_port == 443 or dst_port == 443:
            return False, alert_type

    # ------------------
    # SYN Flood Detection
    # ------------------

    if protocol == "TCP" and tcp_flags:

        syn = tcp_flags & 0x02
        ack = tcp_flags & 0x10

        # Count only SYN packets, not SYN+ACK
        if syn and not ack:
            syn_tracker[src_ip].append(now)

            while (
                syn_tracker[src_ip]
                and now - syn_tracker[src_ip][0] > SYN_WINDOW
            ):
                syn_tracker[src_ip].popleft()

            syn_count = len(syn_tracker[src_ip])

            if syn_count >= SYN_FLOOD_THRESHOLD:

                key = f"syn_{src_ip}"

                if now - last_alert[key] > ALERT_COOLDOWN:

                    alert(
                        f"Possible SYN Flood From {src_ip} ({syn_count} SYN packets)",
                        "SYNFlood",
                        src_ip
                    )

                    if not is_trusted(src_ip):
                        record_attacker(src_ip)

                    suspicious = True
                    last_alert[key] = now
    
    # ------------------
    # ICMP Flood Detection
    # ------------------

    if protocol == "ICMP":

        icmp_tracker[src_ip].append(now)

        while (
            icmp_tracker[src_ip]
            and now - icmp_tracker[src_ip][0] > ICMP_WINDOW
        ):
            icmp_tracker[src_ip].popleft()

        icmp_count = len(icmp_tracker[src_ip])

        if icmp_count >= ICMP_FLOOD_THRESHOLD:

            key = f"icmp_{src_ip}"

            if now - last_alert[key] > ALERT_COOLDOWN:

                alert(
                    f"Possible ICMP Flood From {src_ip} ({icmp_count} packets)",
                    "ICMPFlood",
                    src_ip
                )

                if not is_trusted(src_ip):
                    record_attacker(src_ip)

                suspicious = True

                last_alert[key] = now
    
    # ------------------
    # Flood Detection
    # ------------------

    timestamps = packet_times[src_ip]

    timestamps.append(now)

    while timestamps and now - timestamps[0] > WINDOW_SECONDS:
        timestamps.popleft()

    pps = len(timestamps)

    if pps >= FLOOD_THRESHOLD:

        key = f"flood_{src_ip}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Possible Flood Attack From {src_ip} ({pps} pkt/sec)",
                "Flood",
                 src_ip
            )
            if not is_trusted(src_ip):
              record_attacker(src_ip)

            suspicious = True
            alert_type = "Flood"

            last_alert[key] = now

    # ------------------
    # Port Scan Detection
    # ------------------

    port_tracker[src_ip].add(dst_port)

    if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:

        key = f"scan_{src_ip}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Possible Port Scan From {src_ip}",
                "PortScan",
                src_ip
            )
            if not is_trusted(src_ip):
             record_attacker(src_ip)
            suspicious = True
            alert_type = "PortScan"

            last_alert[key] = now

    # ------------------
    # Suspicious Ports
    # ------------------

    if dst_port in SUSPICIOUS_PORTS:

        key = f"sport_{src_ip}_{dst_port}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Suspicious Port Access {src_ip} -> {dst_port}",
                "SuspiciousPort",
                src_ip
            )
            if not is_trusted(src_ip):
             record_attacker(src_ip)
            suspicious = True
            alert_type = "SuspiciousPort"
            last_alert[key] = now
    # ------------------
    # Brute Force Detection
    # ------------------       
    key_attack = f"{src_ip}:{dst_port}"
    if dst_port in {21, 22, 23, 3389}:

        brute_tracker[key_attack].append(now)

    while (
        brute_tracker[key_attack]
        and now - brute_tracker[key_attack][0] > BRUTE_FORCE_WINDOW
    ):
        brute_tracker[key_attack].popleft()

    attempts = len(brute_tracker[key_attack])

    if attempts >= BRUTE_FORCE_THRESHOLD:

        key = f"brute_{src_ip}_{dst_port}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
                f"Possible Brute Force From {src_ip} "
                f"Against Port {dst_port} "
                f"({attempts} attempts)",
                "BruteForce",
                src_ip
            )

            if not is_trusted(src_ip):
                record_attacker(src_ip)

            suspicious = True
            alert_type = "BruteForce"
            last_alert[key] = now
            
    # ------------------
    # Large Packet Detection
    # ------------------

    if packet_size > 1000:

        key = f"large_{src_ip}"

        if now - last_alert[key] > ALERT_COOLDOWN:

            alert(
    f"Large Packet From {src_ip} ({packet_size} bytes)",
    "LargePacket",
    src_ip
)
            if not is_trusted(src_ip):
             record_attacker(src_ip)

            suspicious = True
            alert_type = "LargePacket"
            last_alert[key] = now

    return suspicious, alert_type

arp_table = {}
def analyze_arp(ip, mac):

    if ip not in arp_table:

        arp_table[ip] = mac
        return

    if arp_table[ip] != mac:

        alert(
            f"Possible ARP Spoofing: {ip} changed "
            f"from {arp_table[ip]} to {mac}",
            "ARPSpoof",
            ip
        )

        arp_table[ip] = mac
