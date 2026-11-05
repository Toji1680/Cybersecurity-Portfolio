# Network Traffic Analyzer

A Python-based network traffic analysis tool built with Scapy. This project analyzes packet capture (PCAP) files, identifies unusual network traffic patterns, performs basic threat detection, and generates security reports in JSON and TXT formats.

## Features

- **Packet Analysis:** Analyzes network packets and identifies TCP and UDP traffic.
- **IP Analysis:** Extracts source and destination IP addresses and identifies IPv4 and IPv6 packets.
- **Protocol Statistics:** Calculates protocol distribution and total packet counts.
- **Top IP Addresses:** Identifies the most frequently occurring source and destination IP addresses.
- **Port Scan Detection:** Identifies sources communicating with multiple TCP destination ports.
- **SYN Flood Detection:** Identifies unusually high numbers of initial SYN packets.
- **High Traffic Detection:** Identifies sources exceeding configured packet-count thresholds.
- **Time-Window Analysis:** Identifies unusually high traffic rates within configured time windows.
- **Security Reporting:** Generates JSON and TXT reports containing analysis results, findings, summaries and recommendations.

## Technologies Used

- Python 3.13.3
- Scapy 2.8.0
- Wireshark
- Npcap
- Python unittest

## Project Structure

```text
Network-Traffic-Analyzer/
│
├── captures/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── screenshots/
│   └── .gitkeep
│
├── main.py
├── packet_analyzer.py
├── threat_detector.py
├── report_generator.py
│
├── test_threat_detector.py
├── test_report_generator.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Toji1680/Cybersecurity-Portfolio.git
```

### 2. Navigate into the project directory

If the Network Traffic Analyzer is the repository root:

```bash
cd Cybersecurity-Portfolio
```

If it is inside a subfolder:

```bash
cd Cybersecurity-Portfolio/Network-Traffic-Analyzer
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

Windows:

```bash
.venv\Scripts\activate
```

### 5. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

1. Place an authorized PCAP or PCAPNG capture file in the `captures/` directory.
2. Ensure that `main.py` points to the correct capture file.
3. Run the analyzer:

```bash
python main.py
```

4. Review the analysis results in the terminal.
5. Open the generated reports in the `reports/` directory.

## Testing

The project uses Python's built-in `unittest` framework.

Run the detection tests:

```bash
python -m unittest test_threat_detector -v
```

Run the reporting tests:

```bash
python -m unittest test_report_generator -v
```

Run all tests:

```bash
python -m unittest discover -v
```

## Detection Limitations

This project implements basic, rule-based network traffic detection.

- High packet counts do not automatically indicate malicious activity.
- Port scan detection uses configured destination-port thresholds.
- SYN flood detection uses initial SYN packet counts.
- Time-window detection uses configured packet-rate thresholds.
- Detection results depend on capture completeness, traffic characteristics and configured thresholds.
- The analyzer does not replace a professional intrusion detection system or a full security investigation.

Alerts should be investigated using additional network evidence before classifying traffic as malicious.

## Security and Responsible Use

Use this tool only on network traffic that you own or have explicit permission to analyze.

Do not upload packet captures containing private information, credentials, session tokens or other sensitive data to a public repository.

## Future Improvements

Potential future enhancements include:

- More advanced intrusion detection rules.
- Improved detection accuracy and false-positive handling.
- Graphical traffic visualizations.
- Additional protocol analysis.
- More comprehensive automated testing.
- Improved command-line configuration.

## Author

Developed as a cybersecurity learning and portfolio project.

**Project:** Network Traffic Analyzer  
**Language:** Python  
**Focus:** Network Security and Traffic Analysis