import unittest
from argparse import ArgumentTypeError

from metasploitscapy.zap_baseline import local_target


class LocalTargetTests(unittest.TestCase):
    def test_accepts_loopback_ipv4_url(self) -> None:
        target = "https://127.0.0.1:8443/app"
        self.assertEqual(local_target(target), target)

    def test_rejects_non_loopback_hosts(self) -> None:
        for target in (
            "https://example.com",
            "http://192.0.2.10:8080",
            "http://localhost:8080",
        ):
            with self.subTest(target=target), self.assertRaises(ArgumentTypeError):
                local_target(target)

    def test_rejects_credentials_and_query_parameters(self) -> None:
        for target in (
            "http://user:password@127.0.0.1:8080",
            "http://127.0.0.1:8080/?token=secret",
            "http://127.0.0.1:8080/#fragment",
        ):
            with self.subTest(target=target), self.assertRaises(ArgumentTypeError):
                local_target(target)


if __name__ == "__main__":
    unittest.main()
