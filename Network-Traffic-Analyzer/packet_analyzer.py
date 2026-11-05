
from collections import Counter

from scapy.layers.inet import IP as IPLayer
from scapy.layers.inet import TCP as TCPLayer
from scapy.layers.inet import UDP as UDPLayer
from scapy.layers.inet import ICMP as ICMPLayer
from scapy.layers.inet6 import IPv6 as IPv6Layer
from scapy.layers.l2 import ARP as ARPLayer


def analyze_packets(packets):
    """
    Analyze an existing collection of network packets.

    Args:
        packets: Scapy packet collection.

    Returns:
        Dictionary containing packet statistics,
        source IPs, destination IPs and destination ports.
    """

    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    destination_ports = Counter()

    total_packets = len(packets)

    for packet in packets:

        if packet.haslayer(IPLayer):

            ip_layer = packet[IPLayer]

            source_ips[ip_layer.src] += 1
            destination_ips[ip_layer.dst] += 1

        elif packet.haslayer(IPv6Layer):

            ip_layer = packet[IPv6Layer]

            source_ips[ip_layer.src] += 1
            destination_ips[ip_layer.dst] += 1

        elif packet.haslayer(ARPLayer):

            protocols["ARP"] += 1
            continue

        else:

            protocols["Other / Non-IP"] += 1
            continue

        if packet.haslayer(TCPLayer):

            protocols["TCP"] += 1
            destination_ports[packet[TCPLayer].dport] += 1

        elif packet.haslayer(UDPLayer):

            protocols["UDP"] += 1
            destination_ports[packet[UDPLayer].dport] += 1

        elif packet.haslayer(ICMPLayer):

            protocols["ICMP"] += 1

        else:

            protocols["Other IP"] += 1

    return {
        "total_packets": total_packets,
        "protocols": protocols,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "destination_ports": destination_ports
    }
