import argparse

from .detector import PortFanoutDetector


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Passively alert on a source contacting many TCP/UDP ports."
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="network interface to monitor (use only on an authorized network)",
    )
    parser.add_argument(
        "--threshold",
        type=_positive_int,
        default=20,
        help="number of distinct destination ports that triggers an alert (default: 20)",
    )
    parser.add_argument(
        "--window",
        type=_positive_float,
        default=60.0,
        help="observation window in seconds (default: 60)",
    )
    args = parser.parse_args()

    try:
        from scapy.all import IP, TCP, UDP, sniff
        from scapy.packet import Packet
    except ImportError as exc:
        raise SystemExit(
            "Scapy is required; install dependencies with "
            "'python3 -m pip install -r requirements.txt'."
        ) from exc

    detector = PortFanoutDetector(args.threshold, args.window)

    def inspect_packet(packet: Packet) -> None:
        ip_packet = packet.getlayer(IP)
        if ip_packet is None:
            return

        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        if transport is None:
            return

        destination_port = int(transport.dport)
        if not 1 <= destination_port <= 65535:
            return

        alert = detector.observe(
            ip_packet.src,
            ip_packet.dst,
            destination_port,
        )
        if alert is not None:
            print(
                f"[ALERTA] Posible escaneo: {alert.source_ip} -> "
                f"{alert.destination_ip} ({alert.unique_ports} puertos distintos)"
            )

    print(
        f"Supervisión pasiva en {args.interface}; pulsa Ctrl+C para detener."
    )
    try:
        sniff(iface=args.interface, prn=inspect_packet, store=False)
    except KeyboardInterrupt:
        print("\nSupervisión detenida.")


if __name__ == "__main__":
    main()
