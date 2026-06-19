# hypersensor/dashboard.py

import os
import time
from hypersensor.geoip import get_country
from hypersensor import stats
from hypersensor.reputation import is_trusted
from hypersensor.stats import (
    total_packets,
    protocol_stats,
    alert_stats,
    ip_stats
)


def clear():

    os.system("cls" if os.name == "nt" else "clear")


def show_dashboard():

    clear()

    print("=" * 40)
    print("        HyperSOC Dashboard")
    print("=" * 40)

    print(f"\nPackets: {stats.total_packets}")

    # -------------------------
    # Protocol Statistics
    # -------------------------

    print("\nProtocols:")

    for proto, count in stats.protocol_stats.items():
        print(f"  ► {proto}: {count}")

    # -------------------------
    # Threat Score
    # -------------------------

    threat = stats.threat_score

    if threat >= 100:
        risk = "CRITICAL"
    elif threat >= 50:
        risk = "HIGH"
    elif threat >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    print(f"\nRisk Level: {risk}")
    print(f"Threat Score: {threat}")

    # -------------------------
    # Alerts
    # -------------------------

    total_alerts = sum(stats.alert_stats.values())

    print(f"\nAlerts: {total_alerts}")

    # -------------------------
    # Severity Breakdown
    # -------------------------

    print("\nSeverity:")

    print(f"  ► LOW: {stats.severity_stats['LOW']}")
    print(f"  ► MEDIUM: {stats.severity_stats['MEDIUM']}")
    print(f"  ► HIGH: {stats.severity_stats['HIGH']}")
    print(f"  ► CRITICAL: {stats.severity_stats['CRITICAL']}")

    # -------------------------
    # Threat Categories
    # -------------------------

    print("\nThreat Categories:")

    found = False

    if stats.alert_stats.get("DNSFlood", 0):
        print(
            f"  ► DNS Flood Detected: "
            f"{stats.alert_stats['DNSFlood']}"
        )
        found = True

    if stats.alert_stats.get("Flood", 0):
        print(
            f"  ► Network Flood Detected: "
            f"{stats.alert_stats['Flood']}"
        )
        found = True

    if stats.alert_stats.get("PortScan", 0):
        print(
            f"  ► Port Scans Detected: "
            f"{stats.alert_stats['PortScan']}"
        )
        found = True

    if stats.alert_stats.get("LargePacket", 0):
        print(
            f"  ► Large Packets Detected: "
            f"{stats.alert_stats['LargePacket']}"
        )
        found = True

    if stats.alert_stats.get("SuspiciousPort", 0):
        print(
            f"  ► Suspicious Port Access: "
            f"{stats.alert_stats['SuspiciousPort']}"
        )
        found = True
        
    if stats.alert_stats.get("SYNFlood", 0):
        print(
        f"  ► SYN Flood Detected: "
        f"{stats.alert_stats['SYNFlood']}"
        )
        found = True
        
    if stats.alert_stats.get("BruteForce", 0):
        print(
        f"  ► Brute Force Detected: "
        f"{stats.alert_stats['BruteForce']}"
        )
        found = True
    
    if stats.alert_stats.get("ICMPFlood", 0):
        print(
        f"  ► ICMP Flood Detected: "
        f"{stats.alert_stats['ICMPFlood']}"
    )
    found = True
    
    if stats.alert_stats.get("ARPSpoof", 0):
        print(
        f"  ► ARP Spoofing Detected: "
        f"{stats.alert_stats['ARPSpoof']}"
    )
    found = True
    
    if stats.alert_stats.get("ThreatIntel", 0):
        print(
        f"  ► Threat Intel Hits: "
        f"{stats.alert_stats['ThreatIntel']}"
    )
    found = True
    
    if not found:
        print("  ► No threats detected")

    # -------------------------
    # Top Talkers
    # -------------------------

    print("\nTop Talkers:")

    top_ips = sorted(
        stats.ip_stats.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    if top_ips:
        for ip, count in top_ips:
            print(f"  ► {ip} -> {count}")
    else:
        print("  No traffic yet")

    # -------------------------
    # Top Attackers
    # -------------------------

    print("\nTop Attackers:")

    top_attackers = sorted(
        stats.attacker_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    if top_attackers:
        for ip, score in top_attackers:
            country = get_country(ip)
            print(
                f"  ► {ip} | "
                f"{country} | "
                f"score={score}"
            )
    else:
        print("  No attackers yet")
    # -------------------------
    # Uptime
    # -------------------------

    uptime = int(time.time() - stats.start_time)

    print(f"\nUptime: {uptime} sec")

    # -------------------------
    # SOC Summary
    # -------------------------

    print("\nSOC Summary:")

    print(
        f"  ► Devices Seen: "
        f"{len(stats.unique_ips)}"
    )

    print(
        f"  ► External IPs: "
        f"{len(stats.external_ips)}"
    )

    print(
        f"  ► Attackers Seen: "
        f"{len(stats.attacker_scores)}"
    )

    # -------------------------
    # Trusted Hosts
    # -------------------------

    print("\nTrusted Hosts:")

    trusted_count = 0

    for ip in stats.external_ips:
        if is_trusted(ip):
            print(f"  ► {ip}")
            trusted_count += 1

            if trusted_count >= 5:
                break

    # -------------------------
    # Status
    # -------------------------

    print("\nStatus: MONITORING")

    print("=" * 40)

    # -------------------------
    # Recent Alerts
    # -------------------------

    print("\nRecent Alerts:")

    if stats.recent_alerts:

        for alert in list(stats.recent_alerts)[:5]:
            print(f"  ► {alert}")

    else:
        print("  No recent alerts")

    print("=" * 40)
    
    print("\nEvidence:")

    print(
    f"  ► PCAP Packets Saved: "
    f"{stats.pcap_packets}"
    )

def dashboard_loop():

    while True:

        show_dashboard()

        time.sleep(5)