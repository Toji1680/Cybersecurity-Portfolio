import unittest
import json
import os
import tempfile

from report_generator import (
    generate_executive_summary,
    generate_recommendations,
    generate_json_report,
    generate_text_report
)


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.report_data = {
            "total_packets": 614,
            "capture_duration_seconds": 16.45,
            "port_scan_detection": {},
            "syn_flood_detection": {},
            "high_traffic_detection": {
                "10.0.0.6": 269
            },
            "time_window_detection": {
                "10.0.0.6": {
                    "packet_count": 214,
                    "window_start": "10:04:28",
                    "window_end": "10:04:38"
                }
            }
        }

    def test_executive_summary(self):
        summary = generate_executive_summary(self.report_data)

        self.assertTrue(any(
            "614 packets" in item for item in summary
        ))

    def test_recommendations(self):
        recommendations = generate_recommendations(
            self.report_data
        )

        self.assertTrue(any(
            "10.0.0.6" in item for item in recommendations
        ))

    def test_empty_findings(self):
        empty_data = {
            "port_scan_detection": {},
            "syn_flood_detection": {},
            "high_traffic_detection": {},
            "time_window_detection": {}
        }

        recommendations = generate_recommendations(empty_data)

        self.assertTrue(any(
            "Continue monitoring" in item
            for item in recommendations
        ))

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            original_directory = os.getcwd()

            try:
                os.chdir(temp_dir)

                generate_json_report(self.report_data)

                file_path = "reports/network_report.json"

                self.assertTrue(os.path.exists(file_path))

                with open(file_path, "r") as file:
                    saved_data = json.load(file)

                self.assertEqual(
                    saved_data["total_packets"], 614
                )

            finally:
                os.chdir(original_directory)

    def test_text_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            original_directory = os.getcwd()

            try:
                os.chdir(temp_dir)

                generate_text_report(self.report_data)

                file_path = "reports/network_report.txt"

                self.assertTrue(os.path.exists(file_path))

                with open(file_path, "r") as file:
                    content = file.read()

                self.assertIn(
                    "NETWORK TRAFFIC ANALYSIS REPORT",
                    content
                )

                self.assertIn("10.0.0.6", content)

            finally:
                os.chdir(original_directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)