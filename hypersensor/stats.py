# hypersensor/stats.py

from collections import defaultdict, deque
from email.mime import message
import time
from collections import deque

from hypersensor import severity
# Trusted IP Prefixes

trusted_prefixes = [
    "140.82.",      # GitHub
    "142.250.",     # Google
    "142.251.",     # Google
    "172.217.",     # Google
    "104.16.",      # Cloudflare
    "104.17.",      # Cloudflare
    "1.1.1.",       # Cloudflare DNS
    "8.8.8.",       # Google DNS
]
MITRE_MAP = {

    "PortScan": {
        "id": "T1046",
        "name": "Network Service Discovery"
    },

    "DNSFlood": {
        "id": "T1498",
        "name": "Network Denial of Service"
    },

    "LargePacket": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel"
    }

}

import os

evidence_count = 0

if os.path.exists("pcaps"):

    for root, dirs, files in os.walk("pcaps"):

        evidence_count += len(files)
        
start_time = time.time()

total_packets = 0

protocol_stats = defaultdict(int)
ip_stats = defaultdict(int)

alert_stats = defaultdict(int)
severity_stats = defaultdict(int)

recent_alerts = deque(maxlen=10)

threat_score = 0

attacker_stats = defaultdict(int)

external_hosts = set()
# Unique hosts seen
unique_ips = set()

# External IPs seen
external_ips = set()

attacker_scores = defaultdict(int)

port_scan_tracker = defaultdict(set)

pcap_packets = 0


live_packets = deque(maxlen=100)
def record_live_packet(
    src_ip,
    dst_ip,
    protocol,
    size
):

    live_packets.appendleft({

        "src": src_ip,
        "dst": dst_ip,
        "proto": protocol,
        "size": size

    })

def record_pcap():
    global pcap_packets
    pcap_packets += 1
    
# =====================
# Packet Tracking
# =====================

def record_packet(protocol, src_ip):

    global total_packets

    total_packets += 1

    protocol_stats[protocol] += 1

    ip_stats[src_ip] += 1

    unique_ips.add(src_ip)

    if not src_ip.startswith("192.168."):
        external_hosts.add(src_ip)
        external_ips.add(src_ip)
# =====================
# Alert Tracking
# =====================

def record_alert(
    alert_type,
    severity,
    message=None,
    src_ip=None
):

    global threat_score

    alert_stats[alert_type] += 1

    severity_stats[severity] += 1

    weights = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 10
    }

    threat_score += weights.get(severity, 1)

    if src_ip:
        trusted = False

        for prefix in trusted_prefixes:
            if src_ip.startswith(prefix):
                trusted = True
                break

        if not trusted:
            if severity == "LOW":
                attacker_scores[src_ip] += 1

            elif severity == "MEDIUM":
                attacker_scores[src_ip] += 5

            elif severity == "HIGH":
                attacker_scores[src_ip] += 10

            elif severity == "CRITICAL":
                attacker_scores[src_ip] += 20

    if message:
        recent_alerts.appendleft(
            f"[{severity}] {alert_type} | {message}"
        )
def record_attacker(ip):

    attacker_scores[ip] += 1

# =====================
# Statistics Screen
# =====================

def print_stats():

    uptime = int(time.time() - start_time)

    print("\n" + "=" * 40)
    print(" HyperSOC Statistics ")
    print("=" * 40)

    print(f"Uptime: {uptime} sec")
    print(f"Total Packets: {total_packets}")

    print("\nProtocols:")

    for proto, count in protocol_stats.items():
        print(f"  {proto}: {count}")

    print("\nAlert Types:")

    if alert_stats:

        for attack, count in alert_stats.items():
            print(f"  {attack}: {count}")

    else:
        print("  No alerts")

    print("\nSeverity:")

    print(f"  LOW: {severity_stats['LOW']}")
    print(f"  MEDIUM: {severity_stats['MEDIUM']}")
    print(f"  HIGH: {severity_stats['HIGH']}")
    print(f"  CRITICAL: {severity_stats['CRITICAL']}")

    print("\nTop Talkers:")

    top_ips = sorted(
        ip_stats.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    for ip, count in top_ips:
        print(f"  {ip} -> {count}")

    print("=" * 40)

def get_dashboard_data():
    mitre_results = []

    for threat, count in alert_stats.items():

        if count > 0 and threat in MITRE_MAP:

            mitre_results.append({

                "technique":
                MITRE_MAP[threat]["id"],

                "name":
                MITRE_MAP[threat]["name"],

                "count":
                count

            })

    return {
        "packets": total_packets,
        "protocols": dict(protocol_stats),
        "threat_score": threat_score,
        "alerts": sum(alert_stats.values()),
        "attackers": dict(attacker_scores),
        "recent_alerts": list(recent_alerts),
        "severity": dict(severity_stats),
        "live_packets": list(live_packets),
        "threat_categories": dict(alert_stats),
        "mitre": mitre_results,
        "top_talkers": dict(
            sorted(
                ip_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        )
    }

