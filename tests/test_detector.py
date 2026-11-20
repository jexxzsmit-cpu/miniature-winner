import unittest

from metasploitscapy.detector import PortFanoutDetector


class PortFanoutDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 0.0
        self.detector = PortFanoutDetector(
            threshold=3,
            window_seconds=10,
            clock=lambda: self.now,
        )

    def test_alerts_at_threshold_once_per_window(self) -> None:
        self.assertIsNone(self.detector.observe("192.0.2.1", "192.0.2.2", 80))
        self.assertIsNone(self.detector.observe("192.0.2.1", "192.0.2.2", 80))
        alert = self.detector.observe("192.0.2.1", "192.0.2.2", 443)
        self.assertIsNone(alert)
        alert = self.detector.observe("192.0.2.1", "192.0.2.2", 22)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.unique_ports, 3)
        self.assertIsNone(self.detector.observe("192.0.2.1", "192.0.2.2", 8080))

    def test_separates_destinations_and_resets_after_window(self) -> None:
        for port in (80, 443):
            self.detector.observe("192.0.2.1", "192.0.2.2", port)
        self.assertIsNone(self.detector.observe("192.0.2.1", "192.0.2.3", 22))

        self.now = 10.0
        self.assertIsNone(self.detector.observe("192.0.2.1", "192.0.2.2", 22))

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            self.detector.observe("192.0.2.1", "192.0.2.2", 0)


if __name__ == "__main__":
    unittest.main()
