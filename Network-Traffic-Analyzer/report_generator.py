import json
import os


import json
import os


def generate_json_report(report_data):

    os.makedirs("reports", exist_ok=True)

    file_path = "reports/network_report.json"

    with open(file_path, "w") as file:
        json.dump(report_data, file, indent=4)

    print("JSON report generated successfully.")

def generate_executive_summary(report_data):

    summary = []

    total_packets = report_data.get("total_packets",0)
    duration = report_data.get("capture_duration_seconds", 0)

    summary.append(
        f"Analyzed {total_packets} packets over {duration} seconds."
    )

    # Port scan findings
    port_scan = report_data.get("port_scan_detection", {})

    if port_scan:
        summary.append(
            f"Possible port scanning indicators detected "
            f"from {len(port_scan)} source IP(s)."
        )
    else:
        summary.append(
            " No possible port scanning indicators were detected"
        )

        # SYN flood findings
        syn_flood = report_data.get("syn_flood_detection", {})

        if syn_flood:
            summary.append(
                f"Possible SYN flood indicators detected "
                f"from {len(syn_flood)} source IP(s)"
            )
        else:
            summary.append(
                "No possible SYN flood indicators were detected"
            )

        # High traffic findings
        high_traffic = report_data.get("high_traffic_detection", {})

        if high_traffic:
            for ip, count in high_traffic.items():
                summary.append(
                    f"High traffic detected from {ip}: {count} packets."
                )
        else:
            summary.append(
                "No sources exceeded the high-traffic threshold."
            )

            # Time-window findings
        rate_results = report_data.get("time_window_detection", {})

        if rate_results:
            summary.append(
                f"{len(rate_results)} source IP address(es) "
                "exceeded the time-window threshold."
            )
        else:
            summary.append(
                "No sources exceeded the time-window threshold."
            )

        summary.append(
            "Further investigation is recommended for identified "
            "high-traffic sources."
        )

        return summary




def generate_text_report(report_data):
        os.makedirs("reports", exist_ok=True)

        file_path = "reports/network_report.txt"

        section_titles = {
            "report_generated": "REPORT INFORMATION",
            "capture_file": "CAPTURE FILE",
            "capture_duration_seconds": "CAPTURE DURATION",
            "total_packets": "TOTAL PACKETS",
            "protocol_statistics": "PROTOCOL STATISTICS",
            "top_source_ips": "TOP SOURCE IP ADDRESSES",
            "top_destination_ips": "TOP DESTINATION IP ADDRESSES",
            "ip_version_statistics": "IP VERSION STATISTICS",
            "port_scan_detection": "PORT SCAN DETECTION",
            "syn_flood_detection": "SYN FLOOD DETECTION",
            "high_traffic_detection": "HIGH TRAFFIC DETECTION",
            "time_window_detection": "TIME WINDOW DETECTION",
            "ipv4_ipv6_high_traffic": "IPv4 AND IPv6 HIGH TRAFFIC",
            "detection_notes": "DETECTION LIMITATIONS"
        }

        with open(file_path, "w") as file:

            file.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
            file.write("=" * 50 + "\n")

            for section, data in report_data.items():

                title = section_titles.get(
                    section,
                    section.upper().replace("_", " ")
                )

                file.write(f"\n{title}\n")
                file.write("-" * 50 + "\n")

                if isinstance(data, dict):

                    if not data:
                        file.write("No suspicious activity detected.\n")

                    else:
                        for key, value in data.items():

                            if isinstance(value, dict):
                                file.write(f"\n{key}\n")

                                for detail, result in value.items():
                                    file.write(
                                        f"  {detail}: {result}\n"
                                    )

                            else:
                                file.write(f"{key}: {value}\n")

                elif isinstance(data, list):

                    for item in data:
                        file.write(f"- {item}\n")

                elif section == "capture_duration_seconds":
                    file.write(f"{data} seconds\n")

                else:
                    file.write(f"{data}\n")

        print("Text report generated successfully.")
def generate_recommendations(report_data):

    recommendations = []

    port_scan = report_data.get("port_scan_detection", {})
    syn_flood = report_data.get("syn_flood_detection", {})
    high_traffic = report_data.get("high_traffic_detection", {})
    rate_results = report_data.get("time_window_detection", {})

    # Port scan recommendations
    if port_scan:
        recommendations.append(
            "Investigate possible port scanning sources "
            "and review their connection attempts."
        )

    # SYN flood recommendations
    if syn_flood:
        recommendations.append(
            "Investigate possible SYN flood activity "
            "and review TCP connection patterns."
        )

    # Overall high traffic recommendations
    if high_traffic:
        for ip, count in high_traffic.items():
            recommendations.append(
                f"Investigate high traffic from {ip}: "
                f"{count} packets."
            )

    # Time-window recommendations
    if rate_results:
        for ip, details in rate_results.items():
            recommendations.append(
                f"Review traffic from {ip}: "
                f"{details['packet_count']} packets within "
                f"the detected time window."
            )

    # No findings fallback
    if not port_scan and not syn_flood and not high_traffic and not rate_results:
        recommendations.append(
            "No configured detection rules generated alerts. "
            "Continue monitoring network activity."
        )

    recommendations.append(
        "Review detection thresholds and investigate findings "
        "using additional network evidence."
    )

    return recommendations