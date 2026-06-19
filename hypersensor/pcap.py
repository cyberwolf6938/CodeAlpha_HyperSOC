# hypersensor/pcap.py

import os
from datetime import datetime
from scapy.all import wrpcap

saved_pcaps = 0


def save_packet(packet, alert_type):

    global saved_pcaps

    folder = os.path.join(
        "pcaps",
        alert_type
    )

    os.makedirs(
        folder,
        exist_ok=True
    )

    filename = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S.pcap"
    )

    filepath = os.path.join(
        folder,
        filename
    )

    wrpcap(
        filepath,
        [packet]
    )

    saved_pcaps += 1