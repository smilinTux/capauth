# Passphrase rotation and custody-bundle rewrap

Use `capauth passphrase rotate` only in an approved local maintenance window. The command does not restart services or edit live service configuration. It replaces only the exact local files declared in the plan.

## Plan

Create an owner-readable version 1 JSON file. Do not put either passphrase in it.

```json
{
  "version": 1,
  "operator": "operator-name",
  "private_key": "/approved/capauth/identity/private.asc",
  "public_key": "/approved/capauth/identity/public.asc",
  "credential_consumers": [
    "/approved/local/service/credentials/capauth-private.asc"
  ],
  "custody_bundles": [
    {
      "path": "/approved/local/custody/active.tar.gpg",
      "checksum_path": "/approved/local/custody/active.tar.gpg.sha256"
    }
  ],
  "rollback_root": "/approved/local/capauth-rotation-rollback",
  "proton_pass_entry": "CapAuth operator custody"
}
```

Every credential consumer must initially contain the exact same protected private-key bytes as `private_key`. Every private artifact and encrypted bundle must be a regular, non-symlink file with owner-only permissions. Checksum files contain SHA-256 in standard `sha256sum` format.

## Ceremony

1. Stop consumers through the separately approved operational procedure. This command does not stop, deploy, or restart anything.
2. Confirm the plan names every approved local consumer and every active custody bundle.
3. Run `capauth passphrase rotate --plan PLAN.json --approve` from an interactive terminal.
4. Approve the confirmation prompt. Enter the old passphrase and the new passphrase only at hidden prompts. Never use shell arguments, environment variables, redirected standard input, transcripts, or debug tracing for passphrases.
5. Retain the printed rollback journal path. The workflow verifies the old passphrase, key correspondence, and sign plus verify before writing. It rewraps the key and bundles in memory, validates new-passphrase unlock and decrypt, atomically replaces each declared file, regenerates checksums, and validates the installed bytes.
6. Update the plan's named Proton Pass entry manually. CapAuth deliberately has no Proton Pass write integration. Enter the new passphrase directly in Proton Pass, save it, then have a second operator or a separate clean session retrieve it and perform an unlock plus sign plus verify check. Never paste it into chat, a ticket, a commit, or a log. Record only the entry name, operator identity, date, and successful handoff outcome in the approved change record.
7. Restart consumers only under separate operator approval after the Proton Pass retrieval test and local validation succeed.

## Rollback

If any install or post-install validation fails, the rotate command restores changed files automatically. A durable, owner-only rollback directory is created before replacements begin and contains exact original bytes plus a JSON journal with SHA-256 hashes. It contains protected private material, so keep it in approved local custody.

For an operator-directed rollback:

```text
capauth passphrase rollback --journal /approved/local/capauth-rotation-rollback/TRANSACTION/journal.json --approve
```

The rollback command validates every saved hash before replacing any target. It requires interactive approval and never needs either passphrase. After rollback, validate the old passphrase and follow the separately approved consumer restart procedure. Retain or retire rollback material according to the custody retention policy. Do not perform ad hoc cleanup.
