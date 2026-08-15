#!/usr/bin/env python3
"""N5: One-shot rewrite of the live pairing store to canonical subjects.

Coord task 754265a7. Companion to card N2 (``capauth.subject.canonical_subject``,
the normalizer) and card N3 (``enroll_device`` refuses a non-canonical subject
on new enrollments, commit a1fab497). This script fixes the records that
predate N3: right now the live store accumulated non-canonical subjects for
months before either card existed (roughly 141 legacy ``operator:<fp>``
device seats plus a handful of ``capauth:``-prefixed / missing-TLD legacy
agent-identity spellings; see ``skcapstone.doctor._scan_pairing_subjects``,
the oracle this script drives to zero).

Correctness constraint this script exists to satisfy: ``capauth.authz.decide``
correlates a device record and a capability token by EXACT subject string.
Rewriting only one side (say, devices) while leaving the other (tokens) on
the old spelling silently breaks authorization -- a device rewritten to
``device:<fp>`` whose token still says ``operator:<fp>`` grants nothing. This
script rewrites BOTH, in one pass, from one plan. See
``capauth.pairing.canonicalize`` for why the two are rewritten by completely
different mechanisms (device records edited in place; tokens re-issued and
the original revoked, never edited in place, because a token's signature
covers its whole payload -- see that module's docstring for the full
rationale).

Usage::

    # Default: DRY RUN. Prints the full plan, writes nothing.
    python scripts/migrate_canonical_subjects.py

    # Apply the plan.
    python scripts/migrate_canonical_subjects.py --execute

    # Point at a non-default store (tests, a second node, ...).
    python scripts/migrate_canonical_subjects.py --base-dir /path/to/.skcapstone

Re-runnable and idempotent: run it again (dry-run or ``--execute``) after a
successful apply and the plan is empty -- every rewritten subject is now
exactly what ``canonical_subject`` returns for it, and that function is
idempotent on its own output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from capauth.pairing import (
    apply_canonical_rewrite,
    default_base_dir,
    format_rewrite_plan,
    scan_canonical_rewrite,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help="Storage root (default: ~/.skcapstone, same root the pairing "
        "store and token store both use).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Apply the plan. Without this flag the script only prints what "
        "it WOULD do and writes nothing (the default, and deliberately so).",
    )
    parser.add_argument(
        "--no-sign-reissued-tokens",
        action="store_true",
        help="Store re-issued tokens unsigned (capauth.tokens.issue_token's "
        "own sign=False escape hatch). Only ever useful for tests against a "
        "hermetic store with no real signing key; a live re-issued token "
        "left unsigned authorizes nothing (capauth.authz.decide denies an "
        "unsigned token by default). Never pass this against a real store.",
    )
    args = parser.parse_args(argv)

    base_dir = args.base_dir.expanduser() if args.base_dir else default_base_dir()

    plan = scan_canonical_rewrite(base_dir)
    print(format_rewrite_plan(plan))

    if not args.execute:
        if not plan.is_empty:
            print("\nDRY RUN: no changes made. Re-run with --execute to apply this plan.")
        return 0

    if plan.is_empty:
        print("\nNothing to apply.")
        return 0

    report = apply_canonical_rewrite(plan, sign_reissued_tokens=not args.no_sign_reissued_tokens)
    print(
        f"\nAPPLIED: rewrote {len(report.devices_rewritten)} device subject(s), "
        f"re-issued {len(report.tokens_reissued)} token(s) and revoked their "
        f"{len(report.tokens_revoked)} predecessor(s)."
    )

    verify_plan = scan_canonical_rewrite(base_dir)
    if verify_plan.is_empty:
        print("Verified: re-scanning the store now finds nothing left to rewrite.")
    else:
        print(
            "WARNING: re-scanning after apply still finds "
            f"{len(verify_plan.devices)} device(s) and {len(verify_plan.tokens)} token(s) "
            "non-canonical. Investigate before re-running.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
