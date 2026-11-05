import unittest

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from threat_detector import (
    detect_port_scanning,
    detect_syn_flood,
    detect_high_traffic,
    detect_traffic_rate,
    count_ip_versions,
    detect_high_traffic_all_ip
)


def create_tcp_packet(source_ip, destination_port, timestamp, flags="A"):
    packet = IP(src=source_ip, dst="192.168.1.1") / TCP(
        dport=destination_port,
        flags=flags
    )
    packet.time = timestamp
    return packet


class TestThreatDetector(unittest.TestCase):

    def test_high_traffic_below_threshold(self):
        packets = []

        for i in range(99):
            packets.append(
                create_tcp_packet(
                    "192.168.1.10",
                    80,
                    1000 + i
                )
            )

        result = detect_high_traffic(packets, threshold=100)

        self.assertEqual(result, {})

    def test_high_traffic_at_threshold(self):
            packets = []

            for i in range(100):
                packets.append(
                    create_tcp_packet(
                        "192.168.1.10",
                        80,
                        1000 + i
                    )
                )

            result = detect_high_traffic(packets, threshold=100)

            self.assertEqual(result["192.168.1.10"], 100)

    def test_syn_ack_not_counted(self):
                packets = []

                for i in range(25):
                    packets.append(
                        create_tcp_packet(
                            "192.168.1.10",
                            80,
                            1000 + i,
                            flags="SA"
                        )
                    )

                result = detect_syn_flood(packets, threshold=20)

                self.assertEqual(result, {})

    def test_port_scanning_below_threshold(self):
                    packets = []

                    for port in range(1, 10):
                        packets.append(
                            create_tcp_packet(
                                "192.168.1.10",
                                port,
                                1000 + port
                            )
                        )

                    result = detect_port_scanning(packets, threshold=10)

                    self.assertEqual(result, {})

    def test_empty_capture(self):
        packets = []

        self.assertEqual(detect_port_scanning(packets), {})
        self.assertEqual(detect_syn_flood(packets), {})
        self.assertEqual(detect_high_traffic(packets), {})
        self.assertEqual(detect_traffic_rate(packets), {})
        self.assertEqual(detect_high_traffic_all_ip(packets), {})

    def test_normal_traffic(self):
        packets = [
            create_tcp_packet(
                "192.168.1.10",
                80,
                1000 + i,
                flags="A"
            )
            for i in range(5)
        ]

        self.assertEqual(detect_port_scanning(packets), {})
        self.assertEqual(detect_syn_flood(packets), {})
        self.assertEqual(detect_high_traffic(packets), {})

    def test_port_scanning(self):
        packets = [
            create_tcp_packet(
                "192.168.1.50",
                port,
                1000 + i
            )
            for i, port in enumerate(range(1, 12))
        ]

        result = detect_port_scanning(packets)

        self.assertIn("192.168.1.50", result)
        self.assertEqual(result["192.168.1.50"], 11)

    def test_syn_flood(self):
        packets = [
            create_tcp_packet(
                "192.168.1.60",
                80,
                1000 + i,
                flags="S"
            )
            for i in range(21)
        ]

        result = detect_syn_flood(packets)

        self.assertIn("192.168.1.60", result)
        self.assertEqual(result["192.168.1.60"], 21)

    def test_high_traffic(self):
        packets = [
            create_tcp_packet(
                "192.168.1.70",
                80,
                1000 + i
            )
            for i in range(101)
        ]

        result = detect_high_traffic(packets)

        self.assertIn("192.168.1.70", result)
        self.assertEqual(result["192.168.1.70"], 101)

    def test_time_window_detection(self):
        packets = [
            create_tcp_packet(
                "192.168.1.80",
                80,
                1000 + (i * 0.1)
            )
            for i in range(21)
        ]

        result = detect_traffic_rate(packets)

        self.assertIn("192.168.1.80", result)
        self.assertEqual(
            result["192.168.1.80"]["packet_count"],
            21
        )

    def test_ip_versions(self):
        packets = [
            IP(src="192.168.1.10", dst="192.168.1.1"),
            IPv6(src="2001:db8::1", dst="2001:db8::2")
        ]

        result = count_ip_versions(packets)

        self.assertEqual(result["IPv4"], 1)
        self.assertEqual(result["IPv6"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)