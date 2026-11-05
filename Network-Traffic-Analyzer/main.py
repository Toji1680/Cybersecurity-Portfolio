from pathlib import Path
from scapy.error import Scapy_Exception
from datetime import datetime
from scapy.utils import rdpcap
from report_generator import(
generate_json_report,
generate_text_report,
generate_executive_summary,
generate_recommendations
)

from threat_detector import (detect_port_scanning,
                             detect_syn_flood,
                             detect_high_traffic,
                             detect_traffic_rate,
                             count_ip_versions,
                             detect_high_traffic_all_ip)

from packet_analyzer import analyze_packets

def main():
    BASE_DIR = Path(__file__).resolve().parent

    capture_path = BASE_DIR / "captures" / "sample.pcap"

    if not capture_path.is_file():
        print(f"Error: Capture file not found: {capture_path}")
        return

    try:
        packets = rdpcap(str(capture_path))

    except (OSError, Scapy_Exception, ValueError) as error:
        print(f"Error: Unable to read capture file: {error}")
        return

    if not packets:
        print("Error: The capture file contains no packets.")
        return

    file_path = str(capture_path)

    packets = rdpcap(file_path)

    capture_duration = 0

    if packets:
        first_packet_time = float(packets[0].time)
        last_packet_time = float(packets[-1].time)

        capture_duration = round(
            last_packet_time - first_packet_time, 2
        )

        print("First packet timestamp:", first_packet_time)
        print("Last packet timestamp:", last_packet_time)
    else:
        print("The capture file contains no packets.")

    report_generated = datetime.now().isoformat(
        timespec="seconds"
    )
    scan_results = detect_port_scanning(packets)

    print("Packets loaded:", len(packets))


    print("\n ---- PORT SCAN DETECTION ----")

    if scan_results:
        for ip, count in scan_results.items():
            print(f"Possible port scanning: {ip} - {count} unique ports")

    else:
        print("No possible port scanning detected.")

    syn_results = detect_syn_flood(packets)
    print("\n ---- SYN FLOOD DETECTION ----")

    if syn_results:
        for ip, count in syn_results.items():
            print(f"Possible SYN flood activity: {ip} - {count} SYN packets")

    else:
        print("No possible SYN flood activity detected.")


    traffic_results = detect_high_traffic(packets)
    print("\n ---- TRAFFIC DETECTION ----")

    if traffic_results:
        for ip, count in traffic_results.items():
            print(f"High traffic detected: {ip} - {count} packets")
    else:
        print("No high traffic detected.")


    rate_results = detect_traffic_rate(packets)
    print("\n ---- TIME-WINDOW TRAFFIC DETECTION ----")

    if rate_results:
        for ip, details in rate_results.items():
          print(f" Source IP: {ip}")
          print(f"Packets: {details['packet_count']}")
          print(
              f"Time window: {details['window_start']}"
              f" to {details['window_end']}"
          )
          print("-------------------------------------")


    else:

        print("No unusually high traffic rates detected.")

    ip_versions = count_ip_versions(packets)

    print("\n---- IP VERSION STATISTICS ----")
    print("IPv4 packets:", ip_versions["IPv4"])
    print("IPv6 packets:", ip_versions["IPv6"])

    all_ip_traffic = detect_high_traffic_all_ip(packets)

    print("\n ---- IPv4 AND IPv6 HIGH TRAFFIC DETECTION ----")

    for ip, count in all_ip_traffic.items():
        print(f"High traffic detected: {ip} - {count} packets")

    if not all_ip_traffic:
        print("No high traffic detected.")



    results = analyze_packets(packets)
    print("\n==================================")
    print("        NETWORK TRAFFIC ANALYZER    ")
    print("\n==================================")

    print(f"\nTotal packets:{results['total_packets']}")
    print("\n---- Protocol Statistics ----")

    for protocol, count in results["protocols"].most_common(10):
        print(f"{protocol}: {count}")

    print("\n--- TOP 10 Source IPs ---")

    for ip, count in results["source_ips"].most_common(10):
        print(f"{ip}: {count}")

    print("\n--- TOP 10 Destination IPs ---")
    for ip, count in results["destination_ips"].most_common(10):
        print(f"{ip} : {count}")


    #Prepare report data

    report_data = {

        "report_generated" : report_generated,
        "capture_file" : file_path,
        "capture_duration_seconds" : capture_duration,
        "total_packets": results["total_packets"],
        "protocol_statistics" : dict(results["protocols"]),
        "top_source_ips" : dict(results["source_ips"].most_common(10)),
        "top_destination_ips" : dict(results["destination_ips"].most_common(10)),
        "ip_version_statistics" : ip_versions,
        "port_scan_detection" : scan_results,
        "syn_flood_detection" : syn_results,
        "high_traffic_detection" : traffic_results,
        "time_window_detection" : rate_results,
        "ipv4_ipv6_high_traffic": all_ip_traffic,
        "detection_notes": [
            "Detection results depend on the configured thresholds.",
            "No alert does not guarantee that the network is free of threats.",
            "High traffic is an indicator for investigation, not proof of malicious activity.",
            "The analyzer only examines packets available in the supplied capture."
        ]
    }

    report_data = {
        "executive_summary": generate_executive_summary(report_data),
        **report_data
    }

    report_data["recommendations"] = generate_recommendations(
        report_data
    )

    #Generate reports

    generate_json_report(report_data)
    generate_text_report(report_data)

    print("\n==================================")
    print("        ANALYSIS COMPLETE    ")
    print("\n==================================")

if __name__ == "__main__":
    main()


'''
from scapy.all import rdpcap

file_path = "captures/sample.pcap"
packets = rdpcap(file_path)

print("\n========= PACKET INSPECTION =========")

for packet in packets[:10]:

    print("\nPacket:", packet.summary())

    layers = [
        layer.__name__
        for layer in packet.layers()
    ]

    print("Layers:", layers)

'''