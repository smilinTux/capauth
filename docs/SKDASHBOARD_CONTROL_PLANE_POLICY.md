# SKDashboard control-plane authorization policy

Status: implementation contract for SKCapstone card `94cbf19a`, SKCP-02.

## Ownership and identities

CapAuth owns authentication facts, capability issuance, delegated-capability
verification, replay reservation, revocation state, and the CapAuth policy
decision. SKDashboard is the policy enforcement point. The service that owns a
resource owns its resource-policy decision and operation. SKDashboard does not
become either policy owner and does not edit an owner store directly.

The fixed logical service identities are:

| Identity | Responsibility | Explicit ceiling |
|---|---|---|
| `skdashboard-api` | Enforce request, CapAuth, and owner-policy gates | Cannot issue a capability or decide owner policy |
| `capauth-issuer` | Issue capabilities under trusted issuer policy | Cannot decide or execute an invocation |
| `capauth-pdp` | Decide exact presented capabilities | Cannot issue, decide an owner resource, or execute its operation |
| `owner-policy-gateway` | Decide the exact owner resource and policy revision | Cannot issue a CapAuth capability or execute through SKDashboard |

Human clients and approved agents are authenticated principals, not service
identities. A browser or native client binds a human principal. An agent client
binds both its authenticated agent principal and explicit `agent_id`. A service
principal cannot use a human or agent capability.

## Closed capability matrix

The code-level source of truth is `capauth.control_plane.CAPABILITY_MATRIX`.

| Family | Capability | Class | Eligible principal |
|---|---|---|---|
| Anonymous discovery | none | discovery | none |
| Read projections | `skdashboard.read` | read | human or approved agent |
| Event streams | `skdashboard.events.read` | read | human or approved agent |
| Report snapshots | `skdashboard.reports.read` | read | human or approved agent |
| Insight proposals | `skdashboard.insights.query` | propose | human or approved agent |
| Action previews | `skdashboard.actions.preview` | propose | human or approved agent |
| Exact action authorization | `skdashboard.actions.authorize` | mutate | eligible human |
| Coordination commands | `skdashboard.commands.coordination` | mutate | human or approved agent |
| CMDB commands | `skdashboard.commands.cmdb` | mutate | human or approved agent |
| Service operations | `skdashboard.commands.service_operations` | mutate | human or approved agent |
| Report delivery | `skdashboard.reports.deliver` | mutate | eligible human |

Anonymous discovery is limited to the declared health contract. It is not a
fallback for a protected route. `skdashboard.read` is the only default audience
scope. Proposal and mutation capabilities must be minted explicitly.

CapAuth enrollment floors are TOFU for reads, attested for proposals, and
verified for mutations. Enrollment is only one gate. A valid capability does not
replace owner policy, exact-version Approval, or a domain state machine.

## Exact authorization binding

Every protected decision binds these facts:

- authenticated subject and principal ID
- explicit agent ID for an agent principal
- originating node ID and bounded purpose
- audience `skdashboard` and exact capability
- owner target operation
- resource type and optional exact resource ID
- UTC expiry of no more than five minutes
- exact owning-policy SHA-256 revision

Node, purpose, agent ID, expiry, and owner-policy revision are signed scope
constraints. Audience, operation, capability, target, and resource are native
signed scope fields. CapAuth verifies the exact signed scope and reserves its
leaf credential atomically for one use.

The PEP joins two sanitized decisions. CapAuth must allow the exact scope, and
the owner policy must allow the same resource at the exact requested revision.
Only two resolved allows produce an allow. A CapAuth denial and an owner denial
remain `deny`. Insufficient owner evidence remains `unknown`. An unreachable
CapAuth or owner policy remains `unavailable`. All three are non-allow outcomes.

## Typed authorizer composition

`capauth.control_plane_authorizer.ControlPlaneDecisionAuthorizer` is the
published dependency-injected composition for this boundary. It accepts only a
canonical padded URL-safe base64 encoding of the delegated authorization
transport, bounded to 64 KiB. Raw JSON, missing padding, whitespace, alternate
alphabets, malformed UTF-8, duplicate members, and oversized input fail closed
without echoing the input.

The caller supplies trusted invocation facts and a `RequestBoundary`; identity,
owner revision, and expiry come only from the signed delegated capability. The
authorizer reconstructs the exact `ControlPlaneBinding`, validates the boundary
before consuming the one-use capability, calls the existing injected
`CapabilityAuthorizer`, and then asks an injected `OwnerPolicyProvider` twice.
An initial allow also returns an opaque, HMAC-bound, one-use currentness receipt.
The authorizer reads owner policy once, uses
`CapabilityAuthorizer.revalidate_current` with that receipt to recheck the same
already-verified chain against current issuer, principal, revocation, and time
state without another replay reservation or signature pass, then reads owner
policy again. The receipt is process-local, bounded, expiry-pruned, redacted,
nonserializable, and invalid after one use or an authorizer restart. Only two
identical owner decisions bracketing that revalidation and the still-current
delegated allow produce
`SanitizedControlPlaneDecisionV1`. The context contains the binding, boundary,
sanitized delegated and joined decisions, UTC issue and expiry times, and a
domain-separated authenticated identity reference. It omits the raw owner
decision and its provider-controlled reason text, as well as the bearer, raw
token, signature, and capability chain.

Callers that must perform a protected owner read after authorization use
`authorize_with_currentness`. It returns the same sanitized result plus an
opaque request-local `ControlPlaneCurrentnessVerifier`. The caller must pass the
exact context object to `check_before_owner_read`, keep the owner result private,
then pass the same object to `check_after_owner_read` before releasing output.
The locked verifier enforces that order, consumes two distinct authorizer-bound
receipts, and returns `allow`, `deny`, or `unavailable` without policy detail.
Any wrong order, copied context, current-state failure, or close invalidates its
unused receipt and releases the privately held capability chain. Middleware must
call `close` in `finally`. This brackets but does not replace the owner system's
own atomic policy-revision read boundary.

Every non-allow result contains only `allow`, broad truth state, broad decision
code, and a null context. Owner reason text, resource identity, principal,
policy revision, and credential details are not returned on denial, Unknown, or
unavailability. The composition stores no latest request or decision and adds
no default backend. Production callers must inject durable issuer, principal,
revocation, replay, audit, signature-verification, and owner-policy
implementations. The included in-memory backends remain test and isolated
development tools only.

## Request boundary and browser controls

Origin, CSRF, TTL, client kind, and mutation idempotency checks run before
one-use bearer verification. This prevents a rejected browser request from
consuming an otherwise valid credential.

- CORS uses an explicit set of exact tailnet or approved local-LAN origins.
- Wildcard and public-origin fallback are forbidden.
- A browser request must present an exact allowed `Origin`.
- Every browser mutation requires a verified CSRF proof.
- Every mutation requires a bounded idempotency key in addition to the one-use
  CapAuth replay reservation.
- Native and agent clients do not receive a browser-origin exemption from
  identity, capability, purpose, owner policy, or replay controls.

## Capability handling and issuance environments

Capability material is accepted only at the authorization boundary. It is never
placed in URLs, API response bodies, event streams, prompts, logs, traces,
errors, or committed fixtures. Sanitized decisions may contain decision IDs,
credential digests, capability names, and policy revisions. They never contain
the bearer, detached signature, token payload, or capability chain.

Local development and production are separate issuance profiles:

| Property | Local development | Production |
|---|---|---|
| Trusted issuer policy | required, isolated development trust | required, approved production trust |
| Maximum TTL | five minutes | five minutes |
| Direct browser handout | development-only, explicit | forbidden unless a later qualification approves it |
| Bearer persistence | forbidden | forbidden |

Development browser handout remains in process memory only. It is not stored in
local storage, session storage, IndexedDB, cookies, a service-worker cache, or a
fixture. Development issuers and roots are never accepted by production.
Production browsers terminate capability use at the server-side PEP. Changing
that boundary requires its own qualification and rollout gate.

## Rotation, revocation, delegation, and break glass

Principal or issuer rotation updates the current policy snapshot. A credential
bound to a previous principal subject or removed issuer fails closed. Revocation
of a leaf or any ancestor is effective before use and is rechecked immediately
before allow. Replay reservation is atomic. A delegated child keeps the same
audience, target, capability, operation, and resource type; it may only narrow
resource ID, constraints, TTL, and remaining delegation depth.

Break glass is not a bypass and does not use `*`. It requires a separately
enrolled verified human, a named emergency purpose, the exact resource and
owner operation, a short one-use capability, the current owner-policy decision,
all existing domain approvals, and successful immutable audit. If identity,
revocation, replay, audit, owner policy, or policy revision is unavailable, the
request is denied. Production issuance remains outside SKDashboard.
