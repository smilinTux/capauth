# CAPAUTH-WEBAUTHN-05 qualification plan

Card: `00bb69a3`

## Source boundary

Passkey credentials use only `CAPAUTH_PASSKEY_DATA_DIR`. The directory must be
an explicit absolute mode-0700 directory, and `passkeys.json` must be a regular
mode-0600 file. Missing, relative, symlinked, broadly accessible, malformed, or
unwritable state fails closed without redirecting any other CapAuth store.

`CAPAUTH_OIDC_ISSUER` must be named HTTPS. `CAPAUTH_WEBAUTHN_RP_ID` must be an
explicit DNS name equal to the issuer host or its parent suffix. IP literals,
HTTP origins, missing RP IDs, and mismatches fail as `passkey_rp_unavailable`
before the PGP verifier receives a proof.

The enrollment page displays the complete `CAPAUTH_NONCE_V1` payload, all five
bound fields, and truthful inline and detached GPG commands. Passkeys are
recommended only after one valid PGP bootstrap.

## Bounded live qualification plan

This plan requires separate exact runtime authorization before execution.

1. Pin the reviewed wheel hash, named issuer, RP ID, DNS answer, certificate
   chain, certificate name, and empty dedicated directory ownership and modes.
2. Restart only the explicitly authorized CapAuth qualification unit and prove
   unrelated OIDC and VAPID paths and hashes did not move.
3. With a synthetic approved PGP identity, register one virtual passkey, restart
   the same unit, and log in twice. Confirm the sign counter persists and each
   OIDC authorization code remains one use.
4. Repeat the IP issuer, HTTP issuer, RP mismatch, missing storage, read error,
   write error, stale challenge, unknown credential, and counter persistence
   negatives. Each must remain unavailable or denied without consuming a PGP
   proof where preflight applies.
5. Remove the synthetic credential and test directory only if the exact runtime
   authorization includes that cleanup. Record no credential, signature, nonce,
   code, state, PKCE value, token, private key, or passphrase.

## Rollback

Revert the reviewed source commit and remove only `CAPAUTH_PASSKEY_DATA_DIR` and
`CAPAUTH_WEBAUTHN_RP_ID` from the qualification unit. Do not delete credentials
or change shared `CAPAUTH_DATA_DIR`. Without the passkey settings, passkey routes
fail closed and all unrelated OIDC behavior retains its existing configuration.

No DNS, certificate, deployment, configuration, restart, key operation,
protected-data access, provider traffic, or external action occurred in this
source slice.
