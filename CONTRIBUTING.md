# Contributing to Lantern

Thanks for your interest in contributing.

## Before opening an issue

- Search existing issues to avoid duplicates.
- For bugs, include your Linux distribution, Python version, terminal, and relevant command output. Remove public IPs, MAC addresses, hostnames, and other network details first.
- Do not publish packet captures, device inventories, credentials, or private network details in an issue.
- For suspected security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Development setup

Lantern's tests use Python's standard library and fake sockets; they do not require root, network access, Nmap, or `iproute2`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --editable .
.venv/bin/python -m unittest discover -s tests -v
```

## Pull requests

- Keep changes focused and explain the user-visible behavior or bug addressed.
- Add or update deterministic tests for behavior changes.
- Do not add runtime dependencies without a concrete need; document OS-level tools separately from Python packages.
- Never include real network inventories, device identifiers, packet captures, or secrets in code, tests, or screenshots.
- Describe manual verification and any platform-specific limitations in the pull request.
