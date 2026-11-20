import argparse
import ipaddress
import shutil
import subprocess
from urllib.parse import urlsplit


def local_target(value: str) -> str:
    try:
        target = urlsplit(value)
        hostname = target.hostname
        target.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid target URL") from exc

    if target.scheme not in {"http", "https"} or hostname is None:
        raise argparse.ArgumentTypeError(
            "target must be an HTTP or HTTPS URL with a loopback IPv4 address"
        )
    if target.username is not None or target.password is not None:
        raise argparse.ArgumentTypeError("target URL must not include credentials")
    if target.query or target.fragment:
        raise argparse.ArgumentTypeError(
            "target URL must not include a query or fragment"
        )

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "target must use a loopback IPv4 address, such as 127.0.0.1"
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
        raise argparse.ArgumentTypeError(
            "target must use a loopback IPv4 address, such as 127.0.0.1"
        )

    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run OWASP ZAP's passive baseline scan against a local web app."
    )
    parser.add_argument(
        "target",
        type=local_target,
        help="local app URL, for example http://127.0.0.1:8080",
    )
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        parser.error("Docker is required to run the OWASP ZAP container")

    result = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "host",
            "-t",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t",
            args.target,
        ],
        check=False,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
