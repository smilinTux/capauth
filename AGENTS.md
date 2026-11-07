# AGENTS.md (capauth)

CapAuth: PGP-based sovereign identity and authentication for the SK stack (Python library, `capauth`
CLI and FastAPI verification service). Overview: [README.md](./README.md). Operations:
[SOP.md](./SOP.md). Architecture: [ARCHITECTURE.md](./ARCHITECTURE.md). This file follows
[AGENT_INSTRUCTIONS_STANDARD](https://github.com/smilinTux/sk-standards/blob/main/standards/AGENT_INSTRUCTIONS_STANDARD.md).
There is no `CLAUDE.md` or `.cursorrules`: every agent reads this file.

## Source of truth and invariants

- **CapAuth owns the one canonical agent identity resolver**, `resolve_agent_identity` in
  `src/capauth/agent_identity.py` (re-exported from `capauth`). skchat, skcomms, skmemory and
  skcapstone delegate to it; never reimplement identity logic elsewhere. It returns a dual URI:
  `capauth_uri` (`capauth:<agent>@<domain>`, the wire identity, always derivable) and `fqid`
  (`<agent>@<operator>.<realm>`, read from `~/.skcapstone/cluster.json`).
- **Operator vs agents:** the shared `~/.skcapstone/identity/identity.json` holds the operator
  identity (`role: operator`); each agent's wire identity resolves per agent. No identity carries an
  `@capauth.local` placeholder (`skcapstone doctor` `identity:*` checks).
- **DID documents, three tiers** (`src/capauth/did.py`): `did:key` (self-contained), mesh-private
  `did:web`, and public `did:web` (minimal: key, name, org). `from_profile()` reads only
  `public_key_armor`; a private key is never touched; no tailnet IPs and no `memory`, `journal` or
  detailed `soul` fields appear in any document; the public tier respects
  `publish_to_skworld: false` in `~/.capauth/config.yaml`.
- **Crypto goes through a backend**, never hand-rolled primitives: `src/capauth/crypto/`
  (`pgpy_backend.py`, `gnupg_backend.py`, `sequoia_backend.py`). Only `sequoia_backend.py` (the `sq`
  CLI) can sign post-quantum; GnuPG is signing-disqualified for PQC. Hybrid combiners are HKDF over
  both shared secrets, never XOR and never pure PQ.
- **The live root identity is still classical.** PQC root migration is additive-first and
  reversible, gated on a root-rotation ceremony (epic `PQC-MIGRATION`). Do not claim a PQC root.
  Per-surface status: [docs/CRYPTO_SPEC.md](./docs/CRYPTO_SPEC.md).

## Commands

CI: `.github/workflows/ci.yml` (test on 3.10 to 3.12, lint, build), `pytest.yml`, `secret-scan.yml`,
`docs-check.yml` (sk-standards gate, tiers 1 to 3).

```bash
pip install -e ".[dev,service]"
python -m pytest tests/ -v --tb=short --cov=capauth             # CI test
pip install "ruff==0.15.4"
ruff format --check src/ tests/                                  # CI lint, step 1
ruff check src/                                                  # CI lint, step 2
python -m build && twine check dist/*                            # CI build
scripts/gitleaks-scope.sh full                                   # CI secret scan
```

On 3.11+ CI also installs `skcapstone` and `skcoord` from git with `--no-deps` so
`tests/test_integration.py` runs instead of skipping; skcapstone is an optional backbone, never a
dependency (skcapstone depends on capauth, not the other way round). Ruff config is in
`pyproject.toml` (line length 99, rules `E,F,I,N,W`, `E501` ignored).

## Start here

1. `src/capauth/cli.py`: every `capauth` command.
2. `src/capauth/agent_identity.py`: the unified identity resolver.
3. `src/capauth/identity.py` and `src/capauth/did.py`: challenge-response and DID generation.
4. `src/capauth/crypto/`: the crypto backends.
5. `src/capauth/service/`: the FastAPI service (`app.py`, `server.py`, `keystore.py`).

## Rules

- **Writing style:** no em dashes (U+2014) and no en dashes (U+2013) anywhere: code, comments,
  docs, commits, PR bodies. Use commas, parentheses, colons or a new sentence. Hyphens are fine.
- **Branch and commit:** never commit to `main`. Branch, commit as soon as a fast check passes and
  before the full suite, then open a PR. Add an `## [Unreleased]` entry to
  [CHANGELOG.md](./CHANGELOG.md) for any user-visible change.
- **Attribution:** a `Co-Authored-By` trailer names the agent that actually did the work, or is
  left out. Never one you cannot evidence.
- **Code style:** Python 3.11+ for new code (the package still supports 3.10), type hints, pydantic
  models, Google-style docstrings, at most 500 lines per file. Tests in `tests/` cover happy path,
  edge case and failure.
- **Coordination:** run `skcapstone coord briefing` at the start of a session; claim work with
  `skcapstone coord claim <id> --agent <you>`. SK packages install into `~/.skenv/`.
- **Generated files:** none checked in; build artefacts come from `python -m build`.

## Privacy

This repo is public. Never put host names, LAN or tailnet IPs, estate names, personal names or data,
real key fingerprints, private keys or credentials in code, docs, tests, fixtures or commits.
Enforced by `secret-scan.yml` (`scripts/gitleaks-scope.sh`) and, for
DID output, by the invariants in `did.py`; the rest is on review.

## Hazards

- **Environment-gated tests:** `pytest.yml` ignores `tests/test_integration.py` and deselects a few
  Sequoia and QR-login tests that need tools CI lacks. A green `pytest.yml` is not the full suite;
  `ci.yml` is.
- **No `capauth did` CLI group:** the identity card is a library and MCP surface (see SOP section 7).
- **Stray tracked files:** `ruff-0.15.4-*.whl` and `urllib.error` at the repo root are accidental
  commits, not inputs; do not depend on them or add more like them.

## See also

- [skcapstone](https://github.com/smilinTux/skcapstone): agent framework, coordination board,
  `skcapstone doctor`.
- [skcomms](https://github.com/smilinTux/skcomms) and [skchat](https://github.com/smilinTux/skchat):
  consumers of the identity resolver.
- [sk-standards](https://github.com/smilinTux/sk-standards): `CRYPTOGRAPHY_STANDARD`,
  `SK_REPO_DOC_STANDARD`, `AGENT_INSTRUCTIONS_STANDARD`.
