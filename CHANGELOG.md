# Changelog

All notable changes to `capauth` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`tokens.prune_expired_tokens(home)` GC for the token store.** `_store_token`
  writes one file per issued token and nothing reaped them, so the per-request
  operator-audience mint path flooded `home/security/tokens` (observed: 38k files /
  153MB of expired 12h-TTL tokens, none read). The GC deletes proven-expired token
  files, keeps valid and non-expiring ones, and leaves an unreadable/mid-write file
  alone so it can never race a concurrent mint into loss. A trailing `Z` UTC suffix
  is normalized before parsing so GC works on Python 3.10 (whose `fromisoformat`
  predates `Z` support).

### Fixed

- **Docs described a CLI that does not exist.** `SOP.md` and `README.md` told
  operators to run `capauth did generate` and `capauth did identity-card`. **There
  is no `did` command group**; `capauth.cli:main` has exactly 16 top-level commands
  and `did` is not one of them, so both invocations exit non-zero. Replaced with the
  real surfaces: the `capauth.did.DIDDocumentGenerator` library API, and skcapstone's
  `did_show` / `did_publish` / `did_identity_card` MCP tools. `docs/ARCHITECTURE.md`
  corrected too.
- **SOP section 5 documented the wrong deployment.** It described a single Tier 2
  SKStacks/Traefik cluster workload behind a Cloudflare Tunnel. What a fleet node
  actually runs is a loopback console script under `capauth-authz.service`
  (`capauth-service --host 127.0.0.1 --port 8420`), with no ingress at all. Section 5
  now separates three scenarios and labels which one is live here. It also corrects
  the claim that the standalone default bind is `0.0.0.0`: the code default is
  `127.0.0.1`, and `0.0.0.0` triggers a startup warning.
- **SOP quoted `SemVer: 0.2.3`**, a number that matched nothing. `pyproject.toml` is
  `dynamic = ["version"]` via setuptools-scm, the newest release tag is `v0.2.20`,
  and `src/capauth/__init__.py` hardcodes `0.2.15`. Section 9 now says where the
  version comes from and flags the hardcoded literal as an open **code** follow-up.
- **SOP named a test gate CI does not run** (`black --check`). Section 4 now cites
  `ci.yml` verbatim and explains why the narrower `pytest.yml` is not a substitute.
- Documented that there is **no `/health` route**; `/capauth/v1/status` is the probe.

### Added

- **`docs-evidence` block + `.github/workflows/docs-check.yml`** (tiers 1,2). Nine
  executable checks pin the documented entry points, the `127.0.0.1:8420` defaults,
  the two named routes, the setuptools-scm version source, the CI gate, and the
  **absence** of both `/health` and a `did` CLI group. All nine were negative-tested
  by breaking the underlying fact (16 mutations, all correctly non-zero).

- **sk-standards doc set** — `SOP.md` (9 sections + mermaid architecture &
  challenge-response diagrams), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this `CHANGELOG.md`; README cross-link block + stated
  maturity tier + CRYPTOGRAPHY_STANDARD compliance line. Per the sk-standards
  `SK_REPO_DOC_STANDARD` (coord `237f38a1`).

- **`docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md`**: cold-machine bootstrap +
  disaster-recovery runbook. Codifies the **restore-not-regenerate** identity
  rule, the fixed chicken-and-egg restore order (offline root key into gpg, prime
  gpg-agent, unseal skvault, restore `~/.capauth/` home, restore per-agent
  profiles + `identity.json`, restore the service keystore, start + verify
  `capauth-service`, re-pair bunker devices, restore the `.13` edge), the DR /
  rotation paths (root compromise vs single-agent compromise vs key-loss), and a
  top-to-bottom operator checklist with `REQUIRES CHEF` markers on every step that
  touches secret key material. No secret is written into the doc. Coord `d7dca00c`.

- **`scripts/provision_agent_profiles.py` `--allow-new-keys` guard**: the
  provisioner now **refuses to mint a fresh keypair** for a missing agent profile
  unless `--allow-new-keys` is passed explicitly, preventing an accidental
  identity fork on a restore (minting over an agent that already had a key breaks
  every consumer enrolled against its real fingerprint). A no-flag run only reads
  existing fingerprints and rewrites the non-key `identity.json` dual-URI fields
  (`capauth_uri`, `fqid`), and prints a loud identity-forking warning when a
  profile is missing. Coord `d7dca00c`.

- **Vendored `tools/build-sq.sh`**: the Sequoia PQC (`sq`) build script now lives
  in-repo (pinned `sq 1.4.0-pqc.1` / `sequoia-openpgp 2.2.0-pqc.1`), autodetecting
  the OpenSSL prefix (with an OpenSSL >= 3.5 gate), autodetecting `libclang`
  (llvm18/20/21) to dodge the `bindgen` layout bug, and patching the binary rpath.
  The PQC signing backend now builds without an external script. Commit `f1846a4`.

- **DID `capabilityInvocation` / `capabilityDelegation`**: both verification
  relationships are now declared in all three DID tiers (`did:key`, mesh
  `did:web`, public `did:web`). Commit `bc7ada2`.

- **T3 composite root-identity path — additive + GATED** (`pqc_root_identity.py`).
  A clearly feature-flagged path that signs/verifies a composite **ML-DSA-87 + Ed448**
  (FIPS 204 + RFC 8032) identity attestation via the Sequoia backend. The signing
  side is **gated closed by default** (`t3_gate_open()` ⇒ `False`;
  `sign_identity_attestation()` raises `RootRotationGateError` before touching any
  key material); it opens only via explicit opt-in
  (`CAPAUTH_ALLOW_T3_COMPOSITE_ROOT=1` or `allow_gated=True`), reserved for the
  Chef-driven rotation ceremony. The classical Ed25519/RSA root path is untouched
  (PGPy stays the default). Hybrid = **either-leg** → quantum-resistant, never
  "quantum-proof"; pre-RFC `draft-ietf-openpgp-pqc-17` (sig code point 31). Tier:
  live root **T0 classical**, this path **proven-but-gated**. TDD:
  `tests/test_pqc_t3_gate.py` (gate-default-closed + classical-untouched without
  `sq`; composite sign→verify roundtrip + tamper/wrong-key reject with `sq`).
  Docs: `docs/PQC_ROOT_MIGRATION.md` §5a. Epic `PQC-MIGRATION` (coord `7b1bcaee`).

### Security

- **Revoked / expired signing-key rejection**: the `pgpy` and `gnupg` verify
  paths now reject a signing key that carries a revocation signature or is expired
  **before** the signature check (`KeyRevokedError` / `KeyExpiredError`), closing
  the gap where the default PGPy path silently accepted a revoked or expired
  signer. Also fixes a `gnupg` `sign()` `ImportResult.ok` crash. 14 new tests.
  Commit `f1846a4`. (Scope note: this rejects keys whose own material shows
  revocation/expiry; full external revocation-certificate enforcement in the
  default verify path is still an open item, tracked in the DR runbook as G1.)

- **`verify_challenge` TTL + replay guard**: challenge verification enforces a
  default max challenge age of 5 minutes (`DEFAULT_MAX_CHALLENGE_AGE_SECONDS = 300`,
  with clock-skew tolerance; older challenges raise `ChallengeExpiredError`) and
  accepts an optional single-use `replay_guard`. The bare primitive stays
  replayable within the TTL unless a guard is supplied; `InMemoryReplayGuard` is
  the single-process reference (`ChallengeReplayError` on reuse), and the
  verification service uses a durable nonce store. 25 new tests. Commit `f1846a4`.

### Crypto / PQC (recent, pre-changelog history)

- **Honest PQC representation for v6 roots** — no false `RSA` label on a v6 PQC root.
- **PQC root proven end-to-end through capauth** — Sequoia (`sq`) backend signs and
  verifies ML-DSA-87 + Ed448 (FIPS 204) / ML-KEM-1024 + X448 (FIPS 203) composite v6
  keys (RFC 9580). The **live root remains classical** until the gated root-rotation
  ceremony; migration is additive + reversible. Epic `PQC-MIGRATION` (coord `e1d6ba2a`).

## [0.2.3]

Current published line. Highlights from the working tree:

### Added

- **Unified agent-identity resolver** (`resolve_agent_identity()`, `agent_identity.py`)
  — the single canonical dual-URI (`capauth:<a>@skworld.io`) + FQID
  (`<a>@<op>.<realm>`) resolver every SK package delegates to; operator-vs-agent
  separation; `skcapstone doctor` `identity:*` invariants.
- **Bunker remote-signer** — phone holds the key and signs logins; relay E2E-encrypted
  (X25519 + HKDF + AES-GCM); proven with Chef's real root key.
- **Authentik custom stage** (`authentik-capauth` image) — passwordless PGP login to
  OIDC apps; cap7 deploy LIVE; the four build/migrate gotchas documented.
- **DID three tiers** (`did:key` / `did:web` mesh / `did:web` public) with the
  private-key-never-touched, no-`100.x`-IP, and tier-3 publish-gate invariants.
- **Per-agent signing-key fix** — agents sign with their own capauth/identity key, not
  the operator's.

### Security

- Honest-claim posture: the live identity root is **classical** (Ed25519 / RSA-4096,
  Shor-breakable) — documented, not overclaimed. PQC signing is available + proven but
  not yet the live default.

[Unreleased]: https://github.com/smilinTux/capauth/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/smilinTux/capauth/releases/tag/v0.2.3
