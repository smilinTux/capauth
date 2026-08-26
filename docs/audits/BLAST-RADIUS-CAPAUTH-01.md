# BLAST-RADIUS-CAPAUTH-01 — record parsing audit

Audit date: 2026-08-26  
Repository revision audited: `fa829b4f2583aeb9669fc6458a203ef513d876c7`  
Scope: production Python under `src/`, plus the production provisioning script. Tests, vendored code, and loops that merely transform already-validated objects are excluded.

## Classification rule

- **RECORD_SCOPED** — the parse/validation failure is handled inside the record loop and iteration can continue with the next record.
- **COLLECTION_SCOPED** — one malformed member terminates or rejects the collection operation, but the enclosing process remains available (the exception is converted to a return, domain error, denial, or other operation-level result).
- **PROCESS_SCOPED** — a member parse failure escapes the operation without a local operation boundary; a top-level caller may terminate. This label describes propagation in this repository, not a claim that every embedding process necessarily exits.

Line ranges below are exact for the audited revision. `sha256` values for every cited source are in the adjacent `BLAST-RADIUS-CAPAUTH-01.sha256` evidence manifest.

## Inventory and findings

| ID | Classification | Exact evidence | Finding |
|---|---|---|---|
| CA-01 | COLLECTION_SCOPED | `src/capauth/estate.py:84-119` | The manifest JSON is parsed once, then every identity is validated in one loop. Any malformed identity raises `ValueError` and rejects the entire manifest. |
| CA-02 | RECORD_SCOPED | `src/capauth/registry.py:183-192` | Each YAML registry file is read, parsed, and model-validated inside its own `try`; failure logs and the next file is attempted. |
| CA-03 | RECORD_SCOPED | `src/capauth/pma.py:284-297` | Claim revocation parses each file inside the loop; malformed files are skipped. |
| CA-04 | RECORD_SCOPED | `src/capauth/pma.py:317-322` | Membership status loads each claim under a per-file handler and continues after failure. |
| CA-05 | RECORD_SCOPED | `src/capauth/pma.py:362-367` | `load_claims` isolates parse/model failures per claim file. |
| CA-06 | RECORD_SCOPED | `src/capauth/pma.py:388-393` | `load_requests` isolates parse/model failures per request file. |
| CA-07 | RECORD_SCOPED | `src/capauth/tokens.py:685-700` | Token listing catches parse/schema failures per token file, warns, and continues. |
| CA-08 | RECORD_SCOPED | `src/capauth/tokens.py:1002-1027` | Token GC handles JSON and timestamp parse failures per file and conservatively leaves that record untouched. |
| CA-09 | PROCESS_SCOPED | `src/capauth/key_transparency.py:250-255` | `_iter_entries` directly yields `LogEntry.from_json(line)` with no local handler; one malformed line raises from the iterator and stops its caller. This is intentionally fail-closed for a hash chain. |
| CA-10 | COLLECTION_SCOPED | `src/capauth/service/bunker.py:240-266` | Outer store JSON failure starts empty, while malformed session members are caught per record. The member loop itself is RECORD_SCOPED, but a non-iterable/non-list `sessions` value fails outside the member handler; therefore the collection contract as a whole is COLLECTION_SCOPED. |
| CA-11 | COLLECTION_SCOPED | `src/capauth/mesh.py:269-283` | Registry JSON and the complete peer loop share one outer `try`; one invalid peer aborts the remaining collection and is converted to a warning. |
| CA-12 | RECORD_SCOPED | `src/capauth/discovery/file_discovery.py:101-114` | Presence-file stat, JSON parse, and model validation share a per-file handler; discovery continues. |
| CA-13 | RECORD_SCOPED | `src/capauth/discovery/syncthing.py:114-122` | Coordination agent JSON is parsed under a per-file handler and malformed files are skipped. |
| CA-14 | RECORD_SCOPED | `src/capauth/trust/graph.py:275-315` | Token edge input failures are caught per token file. |
| CA-15 | RECORD_SCOPED | `src/capauth/trust/graph.py:349-371` | FEB records are parsed and handled independently. |
| CA-16 | RECORD_SCOPED | `src/capauth/trust/graph.py:382-410` | Sync seed records are parsed under a per-seed handler. |
| CA-17 | RECORD_SCOPED | `src/capauth/trust/graph.py:497-514` | Coordination projections count and sample per-file parse failures, then continue; the source health separately exposes undercount/corruption. |
| CA-18 | RECORD_SCOPED | `src/capauth/pairing/store.py:193-207,332-345,352-365` | Peer-file parsing returns `None` per file; all peer-file scans continue past malformed records. |
| CA-19 | RECORD_SCOPED | `src/capauth/pairing/store.py:340-347,360-368` | Device sidecar entries are type-checked and `_device_from_entry` converts key/value failures to `None`; malformed entries do not stop sibling devices. |
| CA-20 | RECORD_SCOPED | `src/capauth/pairing/canonicalize.py:189-224` | Planning skips malformed peer files and malformed device members, continuing the scan. |
| CA-21 | COLLECTION_SCOPED | `src/capauth/pairing/canonicalize.py:404-438` | Apply-time malformed peer collections are skipped per file, but `_rewrite_device_entry` and the `next(...)` lookup are not member-local guarded; a malformed matching entry can abort the rewrite operation. |
| CA-22 | COLLECTION_SCOPED | `src/capauth/delegated.py:840-849,1224-1236` | Credential chains are parsed by tuple comprehensions and any member failure is converted into one operation-level malformed-credential denial. |
| CA-23 | PROCESS_SCOPED | `src/capauth/delegated.py:1618-1672` | `_validate_chain` and `_validate_chain_time` iterate parsed objects but perform unguarded member field/UTC validation; malformed typed state can raise out of the validation operation. Wire parsing normally prevents this, so this is a defense-in-depth boundary. |
| CA-24 | RECORD_SCOPED | `src/capauth/manifest.py:634-641` together with `574-611` | Every module is annotated independently and `_verify_entry_signature` promises/implements a non-raising verdict, so a broken module cannot hide siblings. |
| CA-25 | RECORD_SCOPED | `src/capauth/pqc_confidentiality.py:58-74` | Candidate public-key files are independently attempted; peer-bundle failure returns a local false capability result. |
| CA-26 | RECORD_SCOPED | `src/capauth/agent_identity.py:145-151` and `scripts/provision_agent_profiles.py:81-87` | Ordered cluster-file candidates are independently parsed; failure falls through to the next candidate. |

## Risk summary

Counts: **18 RECORD_SCOPED**, **6 COLLECTION_SCOPED**, **2 PROCESS_SCOPED**.

The two PROCESS_SCOPED paths are not equivalent vulnerabilities. CA-09 is desirable integrity behavior for an append-only hash chain: skipping a corrupt line would falsely heal history. CA-23 is residual hardening debt at an internal typed-object boundary; normal wire parsing rejects malformed credentials before it. The clearest accidental broad-blast path is CA-11, where a single bad peer terminates the rest of mesh-registry loading. CA-21 is the mutation-side concern: planning is tolerant, but apply-time malformed matching entries can terminate a multi-record rewrite after earlier writes.

Recommended follow-ups, without changing behavior in this audit card:

1. Make CA-11 per-record tolerant while reporting explicit partial-load health.
2. Prevalidate all CA-21 rewrites before the first write, preserving all-or-nothing mutation semantics.
3. Keep CA-09 fail-closed and add an explicit caller-level `KeyTransparencyError` test/diagnostic rather than skipping lines.
4. Add defensive exception-to-denial conversion around CA-23 if typed backends can ever be supplied by plugins.

## Acceptance mapping

- **Exact hashed evidence:** this report gives exact file/line evidence; `BLAST-RADIUS-CAPAUTH-01.sha256` hashes this report and every cited source, and records the audited Git tree/commit.
- **Structural versus evidence truth:** completion/kanban/link events are structural only. The audit verdict and classifications live in this evidence document and its digest manifest; no lifecycle state or link is treated as a verdict.
- **Append-only/prohibited boundaries:** the audit made no runtime, credential, deployment, gateway, canary, merge, push, or source-code behavior change. Board completion and evidence attachment use supported `skcapstone coord` append-only commands only.
