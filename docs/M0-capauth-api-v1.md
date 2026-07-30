# M0: capauth API v1 Contract Freeze

**Status:** FROZEN (M0 deliverable, card R0.1).
**Date:** 2026-07-30.
**Parent spec:** `~/clawd/docs/superpowers/specs/2026-07-30-skworld-platform-reconciled-design.md`
(layer model section 2.1, contract section 2.3, pairing fold 3.4, authz fold 3.5,
manifest 3.1, roadmap M0-M5 in 5.2).
**Companion:** `docs/M0-capauth-importer-inventory.md` (the blast-radius map).

---

## 0. What this document is

This is the CONTRACT FREEZE that unblocks the M1-M3 code extraction. capauth is
L0 of the SKWorld platform: the identity, pairing, authz, trust, and tokens
kernel every layer above codes against. Today capauth ships identity plus the
PGP/PQC/DID crypto surface; trust and tokens live in skcapstone, and pairing and
authz live scattered across skchat and skcomms. This doc freezes the v1 PUBLIC
surface across all five domains plus audience-token minting so that:

- M1 can move `trust_graph` / `trust_calibration` / `tokens` from skcapstone into
  `capauth.trust` / `capauth.tokens` behind shims, and
- M2 can build `capauth.pairing`, and
- M3 can build `capauth.authz.decide`,

each landing exactly the signature frozen here, so callers can be shimmed safely.

### Marker convention

Every interface below is tagged:

- **CURRENT (shipped):** the real, already-shipped code. Signatures are recorded
  verbatim with a `file:line` citation. This is the frozen v1 contract for that
  surface; M1-M5 must preserve it byte-for-byte behind any move.
- **TARGET (not yet implemented):** the stable signature the extraction MUST land.
  It does not exist in capauth today. It is frozen here so downstream code can be
  written against it (with a stand-in in CI) before the body ships. Where a TARGET
  is grounded in an existing implementation elsewhere (skcapstone, skchat), the
  `file:line` cites the code the extraction promotes.

Nothing in this doc is a code change. It is the shape M1-M3 build to.

---

## 1. Domain: IDENTITY (CURRENT, shipped)

capauth already owns the single canonical identity resolver. This whole domain is
CURRENT and frozen as-is; M1-M5 do not touch it.

### 1.1 The resolver (the source of truth)

CURRENT: `src/capauth/agent_identity.py:246`

```python
def resolve_agent_identity(agent: Optional[str] = None) -> AgentIdentity
```

Resolution order (docstring `agent_identity.py:254-259`): explicit `agent` arg,
then `SKAGENT`, then `SKCAPSTONE_AGENT` / `SKMEMORY_AGENT`, then
`skmemory.agents.get_active_agent()`, then the `"local"` floor. Re-exported from
the package root as `capauth.resolve_agent_identity` (`src/capauth/__init__.py:12`,
`__all__` at `:14-18`).

CURRENT: `AgentIdentity` dataclass (`src/capauth/agent_identity.py:79-131`). Frozen
fields and members:

```python
@dataclass
class AgentIdentity:
    agent: str                          # short name, e.g. "lumina"
    capauth_uri: str                    # "capauth:<agent>@skworld.io" (always present)
    fqid: Optional[str] = None          # "<agent>@<operator>.<realm>" (None w/o cluster.json)
    fingerprint: Optional[str] = None   # 40 (v4) or 64 (v6) hex PGP fp (None if placeholder)

    @property
    def uri(self) -> str                # alias for capauth_uri              (:100)
    def to_dict(self) -> dict           # identity.json-shaped dict          (:105)
    def hybrid_prekey_available(self) -> bool   # PQ prekey capability probe (:114)
    def confidentiality_suite(self) -> str      # negotiated suite label     (:127)
```

FROZEN v1 guarantees (these are load-bearing for every consumer in the inventory):
`capauth_uri` is ALWAYS populated and always `capauth:<agent>@skworld.io`
(`agent_identity.py:286`); `fqid` is `None` unless `~/.skcapstone/cluster.json`
supplies `realm` and `operator` (`_build_fqid` at `:154`); `fingerprint` is `None`
for placeholder identities (never synthesized).

### 1.2 Home resolution

CURRENT: `src/capauth/__init__.py:27`

```python
def resolve_capauth_home(base_dir: Path | None = None) -> Path
```

Priority: explicit `base_dir`, `CAPAUTH_HOME` env, `~/.skcapstone/capauth` if
present, legacy `~/.capauth` if present, else the new default
(`__init__.py:30-48`). Module constants `DEFAULT_CAPAUTH_DIR` (`:23`),
`LEGACY_CAPAUTH_DIR` (`:24`). This is the trust-boundary anchor used by
`fleet/signing.py` (section 6).

### 1.3 Challenge-response (identity proof primitive)

CURRENT: `src/capauth/identity.py`

```python
def create_challenge(from_fingerprint: str, to_fingerprint: str) -> ChallengeRequest   # :91
def respond_to_challenge(challenge, private_key_armor, passphrase,
                         backend_type=CryptoBackendType.PGPY) -> ChallengeResponse       # :112
def verify_challenge(challenge, response, public_key_armor,
                     backend_type=CryptoBackendType.PGPY, *,
                     max_age_seconds=DEFAULT_MAX_CHALLENGE_AGE_SECONDS,
                     replay_guard=None, _now=None) -> bool                                # :153
class InMemoryReplayGuard                                                                 # :60
ReplayGuard = Callable[[str, datetime], bool]                                             # :50
DEFAULT_MAX_CHALLENGE_AGE_SECONDS = 300                                                   # :41
```

Frozen replay contract (docstring `identity.py:12-24`): `verify_challenge`
enforces a 5-minute TTL by default; within the TTL the primitive is REPLAYABLE
unless a `replay_guard` is supplied. The durable reference guard is
`capauth.authentik.nonce_store.NonceStore`. This contract is what `capauth.authz`
(section 3) and `capauth.pairing` (section 2) build on; do not weaken it.

### 1.4 Models (data contract)

CURRENT: `src/capauth/models.py`. Frozen public models: `EntityType` (`:13`),
`Algorithm` (`:21`), `CryptoBackendType` (`:88`), `KeyInfo` (`:97`, carries the
`fingerprint` 40/64 hex invariant at `:100`), `EntityInfo` (`:107`),
`StorageConfig` (`:116`), `SovereignProfile` (`:122`), `ChallengeRequest` (`:138`),
`ChallengeResponse` (`:148`, with hybrid PQ fields `sig_suite`/`hybrid_signature`/
`hybrid_mldsa_pub` at `:167-181`).

### 1.5 DID and PMA (identity-adjacent, CURRENT, frozen)

CURRENT: `src/capauth/did.py`: `DIDTier` (`:38`), `DIDContext` (`:47`),
`DIDDocumentGenerator` (`:210`) with `from_profile` (`:227`), `generate` (`:352`),
`generate_all` (`:391`), `generate_identity_card` (`:421`). Consumed by
skcapstone `mcp_tools/did_tools.py` and skcomms `did_router.py` (inventory CAT1).

CURRENT: `src/capauth/pma.py`: `create_request` (`:126`), `approve_request`
(`:167`), `verify_claim` (`:220`), `revoke_claim` (`:268`), `get_membership_status`
(`:300`), models `PMACapability`/`MembershipRequest`/`MembershipClaim` (`:34/:55/:78`).

### 1.6 Crypto backend accessor (used everywhere as capauth.crypto)

CURRENT: `capauth.crypto.get_backend(...)` is the single crypto entry point every
signing/verifying consumer imports (skcapstone `fleet/signing.py:91`,
`operator_link.py`, `sync_engine.py`, `sync/vault.py`; skchat
`spaces/federation/assertion.py`; inventory CAT1). Backends:
`pgpy_backend`, `gnupg_backend`, `sequoia_backend` (the only PQC signing backend).
FROZEN: `get_backend()` returns an object exposing `sign(data, armor, passphrase)`
and `verify(data, signature, armor)`; this pair is the crypto contract the whole
platform depends on.

---

## 2. Domain: PAIRING (TARGET, does not exist in capauth today)

Ground truth: `capauth.pairing` DOES NOT EXIST (spec 1.5). Trust bootstrap lives in
skchat (`pairing_gate.py`, `guest_accept.py`, `join_routes.py`, `pq_invites.py`)
and skcomms (`pairing.py`, `public_pairing.py`), none of which consult capauth for
the pairing decision. M2 (spec 3.4) creates the package below. The signatures here
are FROZEN as the M2 landing target; the existing skchat code is the semantics they
promote.

### 2.1 TARGET package: `capauth.pairing`

TARGET: `src/capauth/pairing/` (new package, card R2.1). Frozen v1 surface:

```python
# Enrollment modes (RATIFIED by Chef, spec 3.4 step 2 + section 9 item 4)
EnrollmentMode = Literal["tofu", "attested", "verified"]
#   "verified" = capauth challenge-response (section 1.3)
#   "attested" = operator signature over the key (guest_accept Mode B)
#   "tofu"     = pin-on-first-use (guest_accept Mode C)

def enroll_device(pubkey: str, requested_scopes: list[str], *,
                  mode: EnrollmentMode) -> Enrollment
def approve(enrollment_id: str, approver_ident: AgentIdentity) -> DeviceRecord
def revoke(device_id: str, reason: str) -> None
def list_devices(subject: str | None = None) -> list[DeviceRecord]

# PairingGate semantics promoted (time-boxed window, nonce, max_accepts, rate limit)
def open_window(*, ttl_seconds: int, max_accepts: int,
                rate_limit_per_min: int) -> PairingWindow
```

TARGET records: `Enrollment` (carries `enrollment_id`, `pubkey`,
`requested_scopes`, `mode`, `created_at`, `status`); `DeviceRecord` (carries
`device_id`, `subject`, `pubkey`, `mode`, `approved_scopes`, `approved_at`,
`approved_by`). The DeviceRecord MUST carry its `mode` so downstream authz can
require a minimum mode per capability (spec 3.4 step 2).

### 2.2 Grounding (what the TARGET promotes)

The TARGET signatures are not invented; they promote shipped skchat semantics:

- `open_window(...)` promotes `PairingGate` (`skchat/src/skchat/pairing_gate.py:27`),
  specifically `PairingGate.open_window` (`:50`), `check(nonce)` (`:65`),
  `consume()` (`:80`), `_throttled()` (`:87`). The window/nonce/rate logic is the
  frozen behavior.
- `enroll_device(mode="attested")` promotes `guest_accept` operator attestation:
  `operator_attestation_payload` (`skchat/src/skchat/guest_accept.py:135`),
  `sign_operator_attestation` (`:145`), `verify_operator_attestation` (`:150`).
- `enroll_device(mode="tofu")` and `list_devices` promote the SQLite pin store on
  `ConsumedNonces`: `trust_operator(operator_id, operator_pubkey)` (`:511`),
  `is_operator_trusted(operator_id)` (`:542`), `list_trusted_operators()` (`:546`),
  `record_admission` (`:446`), `is_admitted(peer_fp)` (`:495`). Under M2 the SQLite
  `trusted_operators` table becomes a local READ CACHE of capauth DeviceRecords,
  not a source of truth (spec 3.4 step 3).

### 2.3 Storage contract (FROZEN by spine M2 rule)

The on-disk peer registry `~/.skcapstone/peers/` format v1 is the CURRENT shape
VERBATIM (spec 3.4 step 3). Enrollment/mode metadata rides a versioned sidecar
field, never a breaking change to peers-v1. Any M2 store adapter is injected so
peers-v1 fixtures replay unchanged.

### 2.4 Two front doors, one kernel

skcode-hostd's `/pair/*` routes (card R2.4) proxy onto this SAME module; skchat's
`pairing_gate`/`guest_accept`/`join_routes`/`pq_invites` and skcomms `pairing.py`
convert to thin delegates (spec 3.4 steps 4-5). Behavior must stay byte-identical,
proven by replaying skchat's existing pairing/guest test fixtures.

---

## 3. Domain: AUTHZ (TARGET, does not exist in capauth today)

Ground truth: `capauth.authz` DOES NOT EXIST (spec 1.5). skchat authz is its own
validator, `dataplane_auth.py`, which conflates authentication and the allow
decision. M3 (spec 3.5) creates the PDP below. FROZEN as the M3 landing target.

### 3.1 TARGET module: `capauth.authz`

TARGET: `src/capauth/authz.py` (new module, card R3.1). Frozen v1 surface:

```python
def decide(subject: str, capability: str,
           resource: dict, context: dict) -> Decision
```

TARGET `Decision` dataclass: `{allow: bool, reason: str, obligations: list}`
(spec 3.5 step 1). FROZEN semantics:

- The decision is DETERMINISTIC from cryptographic facts only: enrollment mode
  (from `capauth.pairing` DeviceRecord, section 2), scopes, and capability chains
  from the M1-moved `capauth.tokens` (section 5). No I/O in the core.
- Every decision writes its audit obligation to the existing security audit
  surface (the obligation is returned, the PEP fulfills it).
- FEB / emotional state NEVER gates allow (spec 3.5 step 1, spine 4.2). The
  TrustSignalProvider stays advisory; trust scoring (section 4) informs, it does
  not authorize.

### 3.2 Grounding (what the TARGET replaces)

- The current single-step validator: `CapAuthValidator.validate(token)`
  (`skchat/src/skchat/dataplane_auth.py:64`) and
  `_verify_capauth_credential(token)` (`:75`), gated by `dataplane_auth_enabled()`
  (`:39`, reads `SKCHAT_DATAPLANE_AUTH`), enforced via `enforce_dataplane_auth`
  (`:143`). Under M3 this splits: `_verify_capauth_credential` keeps AUTHENTICATION
  (yield a subject fqid), then calls `capauth.authz.decide(subject, cap, resource,
  ctx)` with `cap in {"skchat.send", "skchat.inbox", "skchat.prekey"}` (spec 3.5
  step 2). The PEP pattern later serves skcode-hostd and sk-access.

### 3.3 Rollout contract (FROZEN)

New env `SKCHAT_AUTHZ_PDP = off | shadow | enforce` (default off, spec 3.5 step 3).
Shadow computes the PDP decision, compares with the legacy outcome, logs
divergences, and returns the LEGACY outcome. The flip to enforce is gated on zero
divergence over a 7-day window on .158 plus fixture replay (skchat's current rule
table re-expressed as PDP fixtures). `SKCHAT_DATAPLANE_AUTH` keeps its meaning (the
gate on/off); the new flag selects WHO decides. capauth ships `decide` plus a
fixture-replay harness that ingests skchat's current rule table (card R3.1).

---

## 4. Domain: TRUST (CURRENT in skcapstone, TARGET move into capauth)

Ground truth: trust code lives in `skcapstone/src/skcapstone/`; `capauth.trust`
does not exist (spec 1.5). M1 (card R1.1, HANDS-OFF) moves the modules verbatim
with their tests, leaving 3-line re-export shims in skcapstone (card R1.2). The
signatures are CURRENT (shipped, in skcapstone) and FROZEN as the exact surface
`capauth.trust` must expose after the move.

### 4.1 TARGET module: `capauth.trust` (moved from skcapstone.trust_graph)

CURRENT source: `skcapstone/src/skcapstone/trust_graph.py`. Frozen surface:

```python
class TrustNode                                              # :27
class TrustEdge                                              # :46
class TrustGraph                                             # :67
    def add_node(self, node: TrustNode) -> None              # :80
    def add_edge(self, edge: TrustEdge) -> None              # :85
def build_trust_graph(home: Path) -> TrustGraph              # :90
def format_dot(graph: TrustGraph) -> str                     # :374
def format_json(graph: TrustGraph) -> str                    # :425
def format_table(graph: TrustGraph) -> str                   # :467
```

### 4.2 TARGET: calibration (moved from skcapstone.trust_calibration)

CURRENT source: `skcapstone/src/skcapstone/trust_calibration.py`. Frozen surface:

```python
class TrustThresholds(BaseModel)                                       # :31
def load_calibration(home: Path) -> TrustThresholds                    # :62
def save_calibration(home: Path, thresholds: TrustThresholds) -> Path  # :83
def recommend_thresholds(home: Path) -> dict[str, Any]                 # :100
def apply_setting(home: Path, key: str, value: str) -> TrustThresholds # :175
```

### 4.3 Move contract (FROZEN)

Every current caller is skcapstone-INTERNAL (inventory CAT5: zero cross-repo
importers). The move keeps `skcapstone.trust_graph` and
`skcapstone.trust_calibration` as re-export shims so `shell.py`, `dashboard.py`,
`cli/trust.py`, `mcp_tools/trust_tools.py`, `mcp_server.py`, and `pillars/trust.py`
stay byte-identical. The MCP tools (`trust_calibrate`, `trust_graph`,
`trust_rehydrate`, `trust_status`, `trust_febs`) route through the shims
unchanged. `home` stays `~/.skcapstone` (not a capauth home) because trust reads
coordination/FEB/sync state that lives there; do NOT re-root it during the move.

---

## 5. Domain: TOKENS (CURRENT in skcapstone, TARGET move into capauth)

Ground truth: `skcapstone/src/skcapstone/tokens.py`; `capauth.tokens` is already
REFERENCED (`skcapstone/src/skcapstone/mcp_tools/capauth_tools.py:165` does
`from capauth.tokens import verify_token`) but the module does not yet live in
capauth. M1 (card R1.1) moves it. Signatures are CURRENT (shipped in skcapstone),
FROZEN as the `capauth.tokens` surface.

### 5.1 TARGET module: `capauth.tokens` (moved from skcapstone.tokens)

CURRENT source: `skcapstone/src/skcapstone/tokens.py`. Frozen surface:

```python
class TokenType(str, Enum)          # AGENT | CAPABILITY | DELEGATION      # :34
class Capability(str, Enum)         # memory:read ... token:issue | "*"    # :42
class TokenPayload(BaseModel)                                             # :60
    token_id: str; token_type: TokenType; issuer: str; subject: str
    capabilities: list[str]; issued_at: datetime
    expires_at: datetime|None; not_before: datetime|None; metadata: dict
    @property is_expired / is_active                                      # :86 / :93
    def has_capability(self, cap: str) -> bool                           # :102
class SignedToken(BaseModel)        # payload + signature + verified       # :114

def issue_token(home: Path, subject: str, capabilities: list[str],
                token_type=TokenType.CAPABILITY, ttl_hours=24,
                metadata=None, sign=True) -> SignedToken                  # :124
def verify_token(token: SignedToken, home: Optional[Path] = None) -> bool # :176
def revoke_token(home: Path, token_id: str) -> bool                      # :201
def is_revoked(home: Path, token_id: str) -> bool                        # :231
def list_tokens(home: Path) -> list[SignedToken]                         # :246
def export_token(token: SignedToken) -> str                             # :275
def import_token(token_json: str) -> SignedToken                        # :295
```

### 5.2 Move contract (FROZEN)

All callers are skcapstone-internal (inventory CAT5): `api.py`, `daemon.py`,
`_cli_monolith.py`, `cli/token.py`, plus `capauth_tools.py:165` which ALREADY
imports the capauth path. M1 moves the module and leaves a `skcapstone.tokens`
shim; the `capauth.tokens.verify_token` reference then resolves for real instead
of importing a not-yet-present module. `home` semantics are unchanged
(`~/.skcapstone`), signing continues over the agent CapAuth PGP key.

---

## 6. Audience-token minting (TARGET, roadmap gap G6)

Ground truth: the shell (spec 2.3 point 2, card R4.2) mints "short-lived
audience-scoped tokens" per pane, keyed by the manifest's
`auth = {audience, scopes}` block (spec 3.1). No such mint exists yet; the closest
CURRENT primitives are the capability `issue_token` (section 5) and the OIDC login
flow. This freezes the mint shape M2+ builds.

### 6.1 TARGET: `capauth.tokens.mint_audience_token`

TARGET (lands with or after M1's `capauth.tokens`, enabled for the shell at R4.2):

```python
def mint_audience_token(subject: str, audience: str, scopes: list[str], *,
                        ttl_seconds: int, home: Path | None = None) -> SignedToken
```

FROZEN semantics: `audience` is the subapp id from the manifest
(`auth.audience`, e.g. `"skchat"`, `"skcode"`); `scopes` is a subset of the
manifest's declared `auth.scopes` (e.g. `["chat.read","chat.send"]`); the token is
short-lived (seconds, not hours) so a compromised pane is contained (spec 2.3
point 2). It reuses `TokenPayload` with `audience` carried as a first-class field
(v1 adds `audience: str | None` to `TokenPayload`, an additive, default-`None`
field so existing tokens stay valid) and `subject` = the human session identity.
Verification is `verify_token` plus an audience match.

### 6.2 Grounding (CURRENT primitives it extends)

- Capability token issuance: `issue_token` / `verify_token`
  (`skcapstone/src/skcapstone/tokens.py:124` / `:176`), section 5.
- Session bearer + OIDC access token: `do_login`
  (`capauth/src/capauth/login.py:154`) performs the challenge-response login and
  caches an OIDC `access_token` (`login.py:281-296`); the shell's audience token is
  the app-local analogue (no OIDC round trip, minted locally by the paired
  session), extending `operator_session_service` per card R4.2.

---

## 7. Manifest signing / verification path (spec 3.1)

The `skworld.module.json` manifest is capauth-signed. The signing/verification
CONTRACT is frozen here even though the SCHEMA lands in sk-standards (card R0.2).

- **Schema home (TARGET):** the manifest schema v1.1 (v1 shape plus the `operator`
  block, spec 2.3) lands in the `smilinTux/sk-standards` repo under `standards/`
  as card R0.2. It does NOT exist there yet (only a README reference in
  `sk-standards`); until R0.2 the shape lives in spec 3.1 / 2.3. The two facet
  validators are `skworld_module_api` (Dart, UI facet) and
  `operator_seat/adapter.py` (Python, operator facet).
- **Signing key (TARGET):** the operator approval key decided by ceremony in card
  R0.3 (gap G7). capauth already anchors the local key material via
  `resolve_capauth_home()` and `<home>/identity/private.asc` /
  `<home>/identity/public.asc` (section 1.2, 1.6).
- **Verification path (CURRENT, reused not reimplemented):** manifest signature
  verification reuses `fleet/signing.py::verify_payload` semantics
  (`skcapstone/src/skcapstone/fleet/signing.py:45`), which classifies a payload as
  `verified | unsigned | invalid` over `canonical_bytes` (`:31`) using a
  `verifier: Callable[[bytes, str], bool]`. The verifier is built from the local
  capauth trust roster: `capauth_verifier()` (`signing.py:134`) over `load_roster()`
  (`:112`, reads `<capauth_home>/identity/public.asc` plus `<home>/fleet-trust/*.asc`),
  and the signer is `capauth_signer()` (`:76`) over `capauth.crypto.get_backend()`.
  The manifest `.sig` is a detached signature verified through this same path
  (spec 3.1). FROZEN: manifest verification MUST NOT introduce a second crypto or
  roster path; it reuses this one.

---

## 8. Frozen surface summary (CURRENT vs TARGET)

| Domain | CURRENT (shipped, frozen as-is) | TARGET (extraction must land) | M-phase |
|---|---|---|---|
| identity | 6 surfaces: `resolve_agent_identity`, `AgentIdentity`, `resolve_capauth_home`, challenge-response (`identity.py`), models, DID+PMA+crypto | 0 (complete) | done |
| pairing | 0 in capauth (semantics in skchat `pairing_gate`/`guest_accept`) | `capauth.pairing`: `enroll_device`, `approve`, `revoke`, `list_devices`, `open_window` + modes tofu/attested/verified (5 fns + 3 records) | M2 |
| authz | 0 in capauth (validator in skchat `dataplane_auth`) | `capauth.authz.decide` + `Decision` + `SKCHAT_AUTHZ_PDP` shadow/enforce (1 fn) | M3 |
| trust | 2 modules in skcapstone (`trust_graph`, `trust_calibration`): 11 public fns/classes | `capauth.trust` (verbatim move, shim behind) | M1 |
| tokens | 1 module in skcapstone (`tokens.py`): 8 fns + 4 models | `capauth.tokens` (verbatim move, shim behind) | M1 |
| audience-mint | 0 (nearest: `issue_token`, `do_login` OIDC access_token) | `capauth.tokens.mint_audience_token` + additive `TokenPayload.audience` | M1+/R4.2 |

Counts: identity is fully CURRENT (0 TARGET). trust and tokens are CURRENT code
that MOVES (M1, mechanical, zero cross-repo callers). pairing (M2) and authz (M3)
are net-new TARGET surfaces grounded in shipped skchat semantics. audience-mint is
a small TARGET extension of the tokens surface.

---

## 9. Extraction risks (top 3, see companion inventory for the full map)

1. **Two undeclared-but-importing consumers, `skchat` and `skmemory`.** Both
   `import capauth` at runtime but neither declares it in packaging (inventory:
   skchat imports capauth in 8+ modules, skmemory in `context_loader.py:480`;
   neither `pyproject.toml` lists capauth). When M1 changes what capauth exports,
   an undeclared dep can break silently in a clean venv. Declare capauth in both
   before the M1 `~/.skenv` upgrade.

2. **skchat holds the LIVE pairing and authz behavior the folds replace.** The
   pairing fold (M2) and authz fold (M3) touch code that is in production
   (`SKCHAT_DATAPLANE_AUTH` has been ON since 07-20; guest flows are live). The
   frozen contract mitigates this with modes that preserve TOFU/SAS/attestation
   semantics, peers-v1 frozen, `SKCHAT_PAIRING_KERNEL` / `SKCHAT_AUTHZ_PDP` shadow
   stages, and fixture replay, but the blast radius is real user traffic, so the
   shadow-then-enforce discipline in sections 2.4 and 3.3 is mandatory, not
   optional.

3. **capauth becomes the single security-review bottleneck (intended, but real).**
   The carve-out routes every kernel diff (`capauth: ["**"]`) to a human, and the
   M1/M2/M3 waves (R1.1, R2.1, R3.1) all land in capauth. Budget Chef review time.
   Secondary: the `capauth.tokens.verify_token` reference already exists in
   skcapstone (`capauth_tools.py:165`) against a module that is not there yet, so
   that MCP tool path is latently broken until M1 lands; verify it after R1.1.
