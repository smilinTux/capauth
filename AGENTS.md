# CapAuth — Agent Onboarding (Universal)

## Coordination

All agents coordinate via the SKCapstone coordination board.
Run `skcapstone coord briefing` to learn the protocol. If skcapstone
is not installed: `pip install -e /path/to/skcapstone`

See `skcapstone coord status` for open tasks. Claim work with
`skcapstone coord claim <id> --agent <your_name>`.

## Project: CapAuth

PGP-based sovereign identity. Part of the SKCapstone ecosystem.

| Path | Purpose |
|------|---------|
| `src/capauth/` | Core library |
| `tests/` | Pytest suite |
| `docs/` | Design documents |

## Conventions

Python 3.11+, PEP 8, black, type hints, pydantic, Google docstrings.
