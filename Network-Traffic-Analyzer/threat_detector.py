from collections import defaultdict
from scapy.layers.inet6 import IPv6 as IPv6Layer
from scapy.layers.inet import IP as IPLayer
from scapy.layers.inet import TCP as TCPLayer
from datetime import datetime

def detect_port_scanning(packets, threshold=10):

    port_attempts = defaultdict(set)

    for packet in packets:

        if packet.haslayer(IPLayer) and packet.haslayer(TCPLayer):

            source_ip = packet[IPLayer].src
            destination_port = packet[TCPLayer].dport

            port_attempts[source_ip].add(destination_port)

    suspicious_ips = {}

    for ip, ports in port_attempts.items():

        if len(ports) >= threshold:

            suspicious_ips[ip] = len(ports)
    return(suspicious_ips)

def detect_syn_flood(packets, threshold=20):

    syn_counts = defaultdict(int)

    for packet in packets:
        if packet.haslayer(IPLayer) and packet.haslayer(TCPLayer):

            source_ip = packet[IPLayer].src
            tcp_flags = int(packet[TCPLayer].flags)

            syn_set = tcp_flags & 0x02
            ack_set = tcp_flags & 0x10

            if syn_set and not ack_set:
                syn_counts[source_ip] += 1

    suspicious_ips = {}

    for ip,count in syn_counts.items():

        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips

from collections import Counter

def detect_high_traffic(packets, threshold=100):

    source_counts = Counter()

    for packet in packets:
        if packet.haslayer(IPLayer):
            source_ip = packet[IPLayer].src
            source_counts[source_ip] += 1

    suspicious_ips = {}

    for ip, count in source_counts.items():
        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips


def detect_traffic_rate(packets, threshold=20, window_seconds=10):

    traffic_windows = defaultdict(lambda: defaultdict(int))

    if not packets:
        return{}

    start_time = min(float(packet.time)for packet in packets)

   # Group packets by source IP and time window
    for packet in packets:

        if packet.haslayer(IPLayer):
            source_ip = packet[IPLayer].src
            packet_time = float(packet.time)

            window_index = int((packet_time - start_time) // window_seconds)
            traffic_windows[source_ip][window_index] += 1



    suspicious_ips = {}

    for ip, windows in traffic_windows.items():
        highest_window = max(windows, key=windows.get)
        highest_count = windows[highest_window]

        if highest_count >= threshold:
           window_start = start_time + ( highest_window * window_seconds )
           window_end = window_start + window_seconds

           suspicious_ips[ip] = {
        "packet_count" : highest_count,
        "window_start" : datetime.fromtimestamp(window_start).strftime("%H:%M:%S"),
        "window_end" : datetime.fromtimestamp(window_end).strftime("%H:%M:%S")
    }

    return suspicious_ips

def count_ip_versions(packets):
    ipv4_count = 0
    ipv6_count = 0

    for packets in packets:
        if packets.haslayer(IPLayer):
            ipv4_count +=1

        elif packets.haslayer(IPv6Layer):
            ipv6_count += 1

    return{
        "IPv4" : ipv4_count,
        "IPv6" : ipv6_count
    }

def detect_high_traffic_all_ip(packets, threshold=100):

    source_counts = Counter()

    for packet in packets:
        if packet.haslayer(IPLayer):
            source_ip = packet[IPLayer].src

        elif packet.haslayer(IPv6Layer):
            source_ip = packet[IPv6Layer].src

        else:
            continue

        source_counts[source_ip] += 1

    suspicious_ips = {}

    for ip, count in source_counts.items():

        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips