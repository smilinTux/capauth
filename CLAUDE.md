# CapAuth — Agent Instructions (Claude Code)

You are working on **CapAuth**, the PGP-based sovereign identity and
authentication layer. Part of the SKCapstone ecosystem.

## Multi-Agent Coordination

Run this at the START of every session:

```bash
skcapstone coord briefing
```

This prints the full coordination protocol, schemas, and live task board.
If `skcapstone` isn't installed, install it:

```bash
pip install -e /home/cbrd21/Nextcloud/p/smilintux-org/skcapstone
```

Quick reference:
  skcapstone coord status              # See open tasks
  skcapstone coord claim <id> --agent <you>
  skcapstone coord complete <id> --agent <you>
  skcapstone coord create --title "..." --by <you>

## Code Style

- Python 3.11+, PEP 8, black formatting, type hints
- Pydantic for data validation
- Google-style docstrings
- Pytest tests in /tests (happy path + edge + failure)
- Max 500 lines per file
