# Agent instructions

- Reassess the repository before each task. The current project is a Python CLI under `metasploitscapy/`, with tests under `tests/`; it does not host a web application.
- Keep changes focused and follow conventions established by code and tooling that are actually present. Avoid introducing dependencies or tooling unless the task requires them.
- Add focused tests for behavior changes and run `python3 -m unittest discover -s tests`.
- Keep network monitoring passive. Keep the OWASP ZAP baseline launcher restricted to local loopback targets; do not add active scans or broaden target scope without explicit authorization.
- Keep `README.md` accurate as setup, usage, and validation commands change.
- Preserve the Boost Software License terms in `LICENSE` and include required notices in copies or derivative works.
