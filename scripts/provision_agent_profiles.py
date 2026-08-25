#!/usr/bin/env python3
"""T4: Provision real per-agent capauth PGP profiles + canonical identity.json.

Coord task 8350c9e7.

For each active agent:
1. If a real CapAuth profile (``capauth/identity/profile.json``) already
   exists: reads fingerprint from it.
2. If not: generates a fresh Ed25519 keypair via ``capauth.profile.init_profile``
   and writes it to ``~/.skcapstone/agents/<agent>/capauth/`` -- **but only when
   ``--allow-new-keys`` is passed** (see the identity-forking guard below).
3. Writes / updates ``identity.json`` with the canonical dual-URI fields:
   ``capauth_uri``, ``fqid``, ``fingerprint``.

Usage::

    python scripts/provision_agent_profiles.py [--dry-run] [--agent AGENT ...]
    python scripts/provision_agent_profiles.py --allow-new-keys   # first-time mint

Dry-run prints what *would* change without writing anything.

Identity-forking guard (coord d7dca00c)
---------------------------------------
Generating a keypair for an agent that *already has* a sovereign identity forks
that identity: every consumer enrolled against the old fingerprint breaks with a
new one, silently. This is exactly the wrong thing to do on a cold / wiped
machine, where the correct action is to **restore** the existing profiles from
the sovereign backup, not mint new ones. See
``docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md``.

So key generation is **refused by default**. When a profile is missing the
script warns loudly and leaves the identity untouched (it still writes the
non-key ``identity.json`` fields, which is harmless). Pass ``--allow-new-keys``
only when you deliberately intend to mint a *brand new* identity (genuine
first-time provisioning of a never-before-enrolled agent), never as part of a
restore.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SKCAPSTONE_HOME = Path.home() / ".skcapstone"
AGENTS_DIR = SKCAPSTONE_HOME / "agents"

# Known active agents.  Extend as the registry grows.
DEFAULT_AGENTS = [
    "lumina",
    "opus",
    "jarvis",
    "ava",
    "artisan",
    "herald",
    "sentinel",
    "architect",
    "scholar",
    "steward",
    "coder",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_cluster() -> dict | None:
    """Return cluster.json contents, or None when absent/unreadable.

    No fabricated default: inventing an operator/realm here once wrote
    ``<agent>@chef.skworld`` FQIDs into identity.json on hosts that were
    never part of that cluster. Callers must tolerate None (fqid omitted).
    """
    for p in [Path("/etc/skcapstone/cluster.json"), SKCAPSTONE_HOME / "cluster.json"]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return None


def _build_fqid(agent: str, cluster: dict | None) -> str | None:
    """Build ``<agent>@<operator>.<realm>``, or None without cluster data."""
    if not cluster:
        return None
    realm = cluster.get("realm")
    operator = cluster.get("operator")
    if not realm or not operator:
        return None
    return f"{agent}@{operator}.{realm}"


def _load_existing_fingerprint(capauth_dir: Path) -> str | None:
    """Read fingerprint from an existing profile.json."""
    profile_path = capauth_dir / "identity" / "profile.json"
    if not profile_path.exists():
        return None
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        fp = data.get("key_info", {}).get("fingerprint")
        if isinstance(fp, str) and len(fp) in (40, 64):
            return fp
    except Exception:
        pass
    return None


def _generate_profile(agent: str, capauth_dir: Path) -> str | None:
    """Generate a new CapAuth profile for *agent* into *capauth_dir*.

    Returns the fingerprint string, or None on failure.
    """
    try:
        from capauth.models import EntityType
        from capauth.profile import init_profile

        profile = init_profile(
            name=agent.capitalize(),
            email=f"{agent}@skworld.io",
            passphrase="",
            entity_type=EntityType.AI,
            base_dir=capauth_dir,
        )
        return profile.key_info.fingerprint
    except Exception as exc:
        print(f"  [WARN] Could not generate profile for {agent}: {exc}", file=sys.stderr)
        return None


def _update_identity_json(
    identity_path: Path,
    agent: str,
    capauth_uri: str,
    fqid: str | None,
    fingerprint: str | None,
    dry_run: bool,
) -> None:
    """Write or merge dual-URI fields into identity.json.

    ``fqid`` is written only when resolvable from cluster.json; when the
    cluster is unknown it is left untouched rather than overwritten with a
    fabricated or null value.
    """
    existing: dict = {}
    if identity_path.exists():
        try:
            existing = json.loads(identity_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    updated = dict(existing)
    # Always set these canonical fields
    updated["capauth_uri"] = capauth_uri
    if fqid is not None:
        updated["fqid"] = fqid
    if fingerprint:
        updated["fingerprint"] = fingerprint
    # Ensure core fields are present
    if "name" not in updated:
        updated["name"] = agent.capitalize()
    if "email" not in updated:
        updated["email"] = f"{agent}@skworld.io"
    if "capauth_managed" not in updated:
        updated["capauth_managed"] = bool(fingerprint)
    if "created_at" not in updated:
        updated["created_at"] = datetime.now(timezone.utc).isoformat()

    changed = updated != existing

    if dry_run:
        status = "CHANGE" if changed else "no-op"
        print(f"  [{status}] {identity_path}")
        if changed:
            for k in ("capauth_uri", "fqid", "fingerprint"):
                old = existing.get(k, "<missing>")
                new = updated.get(k)
                if old != new:
                    print(f"         {k}: {old!r} → {new!r}")
        return

    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    action = "updated" if changed else "unchanged"
    print(f"  [{action}] {identity_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing.")
    parser.add_argument(
        "--agent",
        nargs="*",
        default=DEFAULT_AGENTS,
        help="Agents to provision (default: all known agents).",
    )
    parser.add_argument(
        "--allow-new-keys",
        action="store_true",
        help=(
            "Permit minting a FRESH keypair when an agent has no profile. OFF by "
            "default: generating a key for an agent that already had one forks its "
            "identity and breaks every enrolled consumer. On a restore/cold machine, "
            "restore profiles from backup instead (see COLD_MACHINE_BOOTSTRAP_AND_DR.md)."
        ),
    )
    args = parser.parse_args()

    cluster = _load_cluster()
    agents = args.agent
    dry_run = args.dry_run
    allow_new_keys = args.allow_new_keys

    if dry_run:
        print("DRY RUN - no files will be written.\n")
    if allow_new_keys:
        print(
            "[!] --allow-new-keys is SET: missing profiles WILL be minted as fresh\n"
            "    keypairs. Do NOT use this on a restore/cold machine - it forks agent\n"
            "    identities. Confirm this is genuine first-time provisioning.\n"
        )

    for agent in agents:
        agent_dir = AGENTS_DIR / agent
        if not agent_dir.exists():
            print(f"[SKIP] {agent} - agent directory not found")
            continue

        capauth_dir = agent_dir / "capauth"
        identity_path = agent_dir / "identity" / "identity.json"
        capauth_uri = f"capauth:{agent}@skworld.io"
        fqid = _build_fqid(agent, cluster)

        print(f"\n[{agent}]")
        print(f"  capauth_uri : {capauth_uri}")
        print(f"  fqid        : {fqid}")

        # Step 1: Try to load existing fingerprint
        fingerprint = _load_existing_fingerprint(capauth_dir)

        # Step 2: Generate new profile if missing -- GUARDED (coord d7dca00c).
        # Refuse to mint a fresh keypair unless --allow-new-keys is explicit,
        # because minting over an agent that already had an identity forks it and
        # breaks every enrolled consumer. On a cold/wiped machine the right move
        # is to RESTORE the profile from the sovereign backup, not regenerate.
        if fingerprint is None:
            if not allow_new_keys:
                print(
                    f"  [REFUSED] No profile found at {capauth_dir}.\n"
                    f"            NOT generating a key: doing so would FORK {agent}'s\n"
                    f"            identity and break every consumer enrolled against its\n"
                    f"            real fingerprint. If this is a restore, recover the\n"
                    f"            profile from the sovereign backup instead (see\n"
                    f"            docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md). If this really is\n"
                    f"            a brand-new agent, re-run with --allow-new-keys.",
                    file=sys.stderr,
                )
                # identity.json still gets its non-key fields; fingerprint stays None.
            elif not dry_run:
                print(f"  No profile found at {capauth_dir} - generating (--allow-new-keys)...")
                fingerprint = _generate_profile(agent, capauth_dir)
                if fingerprint:
                    print(f"  Generated fingerprint: {fingerprint}")
                else:
                    print(
                        "  [WARN] Could not generate profile; identity.json will lack fingerprint"
                    )
            else:
                print("  [dry-run] Would generate new Ed25519 keypair (--allow-new-keys)")
                fingerprint = None
        else:
            print(f"  fingerprint : {fingerprint}")

        # Step 3: Update identity.json
        _update_identity_json(
            identity_path=identity_path,
            agent=agent,
            capauth_uri=capauth_uri,
            fqid=fqid,
            fingerprint=fingerprint,
            dry_run=dry_run,
        )

    print("\nDone." if not dry_run else "\nDone (dry-run).")


if __name__ == "__main__":
    main()
