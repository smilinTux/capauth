"""CapAuth OIDC/OAuth2 Identity Provider — FastAPI router (Track-2 spike).

Mount into the main CapAuth service::

    from capauth.service.oidc import build_oidc_router
    app.include_router(build_oidc_router(), prefix="/oidc")

Endpoints (under the mount prefix, default ``/oidc``)::

    GET  /oidc/.well-known/openid-configuration   discovery document
    GET  /oidc/jwks.json                           JWKS (RSA public signing key)
    GET  /oidc/authorize                           validate params + render PGP login page
    POST /oidc/complete                            (called by the login page) verify PGP -> code
    POST /oidc/token                               code + PKCE -> RS256 ID token + access token
    GET  /oidc/userinfo                            Bearer access token -> claims

A copy of the discovery document is ALSO served at the service root
(``/.well-known/openid-configuration``) by the main app so generic clients that
only know the issuer can autodiscover; that wiring lives in ``service/app.py``.

The login page reuses the canonical ``CAPAUTH_NONCE_V1`` payload contract and
the existing ``/capauth/v1/challenge`` + ``/capauth/v1/verify`` endpoints, so any
existing CapAuth signing client (CLI, browser extension, Nextcloud app) works
unchanged.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

import jwt as pyjwt
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from ... import resolve_capauth_home
from ...authentik.claims_mapper import preferred_username_fallback
from ...authz import decide
from ...exceptions import SubjectNamingError
from ...subject import canonical_subject
from ...tokens import TokenSigningError, export_token, mint_audience_token
from .clients import ClientRegistry
from .passkey import PasskeyRPUnavailableError, PasskeyStore, PasskeyStoreUnavailableError
from .signing_key import SigningKey
from .store import (
    AuthCodeStore,
    InvalidGrantError,
    OIDCStateUnavailableError,
    RateLimitExceededError,
)

logger = logging.getLogger("capauth.service.oidc")

SKDASHBOARD_AUDIENCE = "skdashboard"
SKDASHBOARD_SCOPES = ("skdashboard.read", "skdashboard.events.read")
SKDASHBOARD_AUTH_SCOPES = frozenset(("openid", *SKDASHBOARD_SCOPES))
SESSION_POLICY_VERSION = "skdashboard-session-v1"
SUPPORTED_SCOPES = ["openid", "profile", "email", "groups", *SKDASHBOARD_SCOPES]
MAX_TOKEN_TTL = 300
_OPAQUE_MIN_LENGTH = 16
_RATE_LIMITS = {"authorize": 30, "complete": 10, "token": 30, "logout": 30}


def _bounded_ttl(name: str) -> int:
    try:
        value = int(os.environ.get(name, str(MAX_TOKEN_TTL)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= value <= MAX_TOKEN_TTL:
        raise ValueError(f"{name} must be between 1 and 300 seconds")
    return value


def _validate_issuer(candidate: str) -> str:
    candidate = candidate.rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OIDC issuer must be an exact HTTPS origin")
    return candidate


def issuer_url() -> str:
    """Resolve and strictly validate the configured HTTPS issuer origin."""
    explicit = os.environ.get("CAPAUTH_OIDC_ISSUER")
    if explicit:
        candidate = explicit.rstrip("/")
    else:
        service_id = os.environ.get("CAPAUTH_SERVICE_ID", "capauth.local")
        candidate = os.environ.get("CAPAUTH_BASE_URL", f"https://{service_id}").rstrip("/")
    return _validate_issuer(candidate)


def discovery_document(issuer: Optional[str] = None) -> dict[str, Any]:
    """Build the OpenID Connect discovery document for the IdP.

    Args:
        issuer: Override issuer URL. Defaults to :func:`issuer_url`.

    Returns:
        dict: The ``.well-known/openid-configuration`` payload.
    """
    iss = _validate_issuer(issuer or issuer_url())
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oidc/authorize",
        "token_endpoint": f"{iss}/oidc/token",
        "userinfo_endpoint": f"{iss}/oidc/userinfo",
        "jwks_uri": f"{iss}/oidc/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "code_challenge_methods_supported": ["S256"],
        "revocation_endpoint": f"{iss}/oidc/revoke",
        "end_session_endpoint": f"{iss}/oidc/logout",
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "iat",
            "exp",
            "nonce",
            "amr",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "groups",
            "picture",
            "locale",
            "capauth_fingerprint",
            "agent_type",
        ],
    }


# ---------------------------------------------------------------------------
# PGP login page (server-rendered; reuses /capauth/v1/challenge + /verify)
# ---------------------------------------------------------------------------

_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CapAuth — Sign in with PGP</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f0f1a;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
    .card{{background:#1a1a35;border:1px solid rgba(124,58,237,.25);border-radius:14px;
           padding:2rem;max-width:520px;width:100%}}
    h1{{font-size:1.35rem;color:#a78bfa;margin-bottom:.4rem}}
    p.sub{{color:#94a3b8;font-size:.88rem;margin-bottom:1.3rem;line-height:1.5}}
    .step{{color:#64748b;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
    label{{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.3rem}}
    input,textarea{{width:100%;background:#0f0f1a;border:1px solid #334155;border-radius:8px;
                    color:#e2e8f0;padding:.6rem .8rem;font-size:.88rem;margin-bottom:1rem;
                    font-family:monospace}}
    textarea{{min-height:130px;resize:vertical}}
    button{{width:100%;background:#7C3AED;color:#fff;border:none;border-radius:8px;
            padding:.8rem;font-size:1rem;cursor:pointer;font-weight:600}}
    button:hover{{background:#6d28d9}}
    .nonce-box{{background:#0f0f1a;border:1px solid #334155;border-radius:8px;padding:.7rem;
                margin-bottom:.5rem;font-family:monospace;font-size:.78rem;color:#00e5ff;
                white-space:pre-wrap;word-break:break-all}}
    .copy{{width:auto;padding:.45rem .7rem;font-size:.78rem;background:#334155;margin-bottom:1rem}}
    .err{{color:#f87171;font-size:.85rem;margin-top:.6rem;display:none}}
    code{{color:#a78bfa}}
  </style>
</head>
<body>
<div class="card">
  <h1>Sign in with CapAuth</h1>
  <p class="sub">Authenticate to <strong>{client_name}</strong> with your PGP key.
     No password. Use a passkey if you already added one.</p>

  <button id="pk-btn" onclick="passkeyLogin()" style="background:#0e7490">Sign in with a passkey</button>
  <p class="sub" style="font-size:.74rem;margin:.4rem 0 1rem">Recommended after one PGP-proven enrollment. Passkey login then needs no fingerprint or pasted signature.
    <a href="{base_url}/oidc/passkey/enroll" style="color:#a78bfa">Add a passkey</a>
  </p>

  <div style="display:flex;align-items:center;gap:.6rem;margin:0 0 1rem;color:#475569;font-size:.74rem">
    <span style="flex:1;height:1px;background:#334155"></span>PGP FALLBACK<span style="flex:1;height:1px;background:#334155"></span>
  </div>

  <div class="step">1 — Your PGP fingerprint</div>
  <label for="fp">Fingerprint (40- or 64-hex chars)</label>
  <input id="fp" type="text" maxlength="64" placeholder="ABCDEF0123..." autocomplete="off"/>

  <div class="step">2 - Exact message to sign</div>
  <div class="nonce-box" id="nonce">Enter your fingerprint to load the complete signed payload.</div>
  <button class="copy" type="button" onclick="copyPayload()">Copy message</button>

  <div class="step">3 - Paste your signed message or detached signature</div>
  <label for="sig">Signed message / signature (ASCII armor)</label>
  <textarea id="sig" placeholder="-----BEGIN PGP MESSAGE-----&#10;...&#10;-----END PGP MESSAGE-----"></textarea>

  <p class="sub">This fingerprint must already have an approved CapAuth enrollment.</p>

  <button onclick="submitSig()">Verify &amp; Continue</button>
  <div class="err" id="err"></div>

  <div style="display:flex;align-items:center;gap:.6rem;margin:1.1rem 0 .2rem;color:#475569;font-size:.74rem">
    <span style="flex:1;height:1px;background:#334155"></span>OR<span style="flex:1;height:1px;background:#334155"></span>
  </div>
  <button id="ld-btn" onclick="capauthLocalSign()" style="background:#10b981;margin-top:.5rem">Sign on this device (key in your bunker)</button>
  <button id="ph-btn" onclick="capauthPhoneLogin()" style="background:#7C3AED;margin-top:.5rem">Sign from another device (QR)</button>
  <div id="pq" style="display:none;margin-top:1rem;text-align:center">
    <img id="pq-img" alt="pairing QR" style="width:200px;height:200px;background:#fff;border-radius:10px"/>
    <div id="pq-status" class="sub" style="margin-top:.5rem;color:#a78bfa"></div>
    <div id="pq-uri" style="font-size:.58rem;color:#475569;word-break:break-all;margin-top:.3rem"></div>
  </div>

  <p style="margin-top:1rem;font-size:.74rem;color:#475569">
    Manual GPG: copy the complete message, then use <code>gpg --armor --sign</code> for an inline signed message
    or <code>gpg --armor --detach-sign</code> for a detached signature. The browser extension can sign automatically.
  </p>
</div>

<script src="{base_url}/oidc/passkey.js?v=15"></script>
<script src="{base_url}/bunker/vendor/openpgp.min.js"></script>
<script type="module" src="{base_url}/oidc/bunker-login.js?v=15"></script>
<script>
const BASE = "{base_url}";
const REQUEST_ID = "{request_id}";
window._capauthBase = BASE; window._capauthReqId = REQUEST_ID; window._capauthCh = null;

async function passkeyLogin(){{
  document.getElementById("err").style.display="none";
  if(!window.capauthWebAuthn || !window.capauthWebAuthn.available()){{
    return setErr("This browser has no passkey support — use PGP above.");
  }}
  try{{
    const redirect = await window.capauthWebAuthn.login(BASE, REQUEST_ID);
    window.location.href = redirect;
  }}catch(e){{ setErr("Passkey sign-in: " + e.message); }}
}}
let currentNonce = null, currentEcho = null;
let currentPayload = "";

function setErr(m){{ const e=document.getElementById("err"); e.textContent=m; e.style.display="block"; }}

async function loadChallenge(fp){{
  const r = await fetch(BASE + "/capauth/v1/challenge", {{
    method:"POST", headers:{{"Content-Type":"application/json"}},
    body: JSON.stringify({{capauth_version:"1.0", fingerprint:fp,
      client_nonce: btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16))))}})
  }});
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}}

async function copyPayload(){{
  if(!currentPayload) return setErr("Enter a valid fingerprint to load a fresh challenge first.");
  try{{ await navigator.clipboard.writeText(currentPayload); }}
  catch(e){{ return setErr("Copy failed. Select the complete message and copy it manually."); }}
}}

document.getElementById("fp").addEventListener("blur", async function(){{
  const fp=this.value.trim().toUpperCase().replace(/\\s/g,"");
  if(![40,64].includes(fp.length)){{ return; }}
  try{{
    const ch=await loadChallenge(fp);
    currentNonce=ch.nonce; currentEcho=ch.client_nonce_echo; window._capauthCh=ch;
    currentPayload=["CAPAUTH_NONCE_V1", "nonce="+ch.nonce,
      "client_nonce="+ch.client_nonce_echo, "timestamp="+ch.timestamp,
      "service="+ch.service, "expires="+ch.expires].join("\\n");
    document.getElementById("nonce").textContent=currentPayload;
    // window.capauth provider: auto-sign with Tier B origin-binding. The
    // extension injects origin=window.location.origin and signs in-extension —
    // the private key never reaches this page. Falls back to manual paste.
    if(window.capauth && window.capauth.isCapAuth){{
      try{{
        const res=await window.capauth.signChallenge(ch);
        document.getElementById("sig").value=res.signature;
        submitSig();
      }}catch(e){{ /* denied/locked — leave the paste flow available */ }}
    }}
  }}catch(e){{ document.getElementById("nonce").textContent="Error: "+e.message; }}
}});

async function submitSig(){{
  document.getElementById("err").style.display="none";
  const fp=document.getElementById("fp").value.trim().toUpperCase().replace(/\\s/g,"");
  const sig=document.getElementById("sig").value.trim();
  if(![40,64].includes(fp.length)) return setErr("Fingerprint must be 40- or 64-hex characters.");
  if(!currentNonce) return setErr("No challenge loaded — tab out of the fingerprint field first.");
  if(!sig) return setErr("Paste your PGP signature.");

  const body={{request_id:REQUEST_ID, fingerprint:fp, nonce:currentNonce,
               nonce_signature:sig}};
  const r=await fetch(BASE + "/oidc/complete", {{
    method:"POST", headers:{{"Content-Type":"application/json"}}, body: JSON.stringify(body)
  }});
  if(!r.ok){{ const b=await r.json().catch(()=>({{}})); return setErr(b.detail || b.error || "Login failed."); }}
  const d=await r.json();
  window.location.href=d.redirect_to;
}}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Passkey (WebAuthn) browser helpers — served as static JS so we don't have to
# brace-escape a large script inside the .format() page templates.
# ---------------------------------------------------------------------------

_PASSKEY_JS = r"""
// CapAuth passkey (WebAuthn) browser helpers. Convenience front-door bound to a
// PGP fingerprint — the passkey logs into the SAME identity (amr=webauthn).
(function () {
  function b64urlToBuf(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    s += "=".repeat((4 - (s.length % 4)) % 4);
    const bin = atob(s), b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b.buffer;
  }
  function bufToB64url(buf) {
    const b = new Uint8Array(buf); let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function parseCreation(o) {
    const p = Object.assign({}, o);
    p.challenge = b64urlToBuf(o.challenge);
    p.user = Object.assign({}, o.user, { id: b64urlToBuf(o.user.id) });
    if (o.excludeCredentials)
      p.excludeCredentials = o.excludeCredentials.map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) }));
    return p;
  }
  function parseRequest(o) {
    const p = Object.assign({}, o);
    p.challenge = b64urlToBuf(o.challenge);
    if (o.allowCredentials)
      p.allowCredentials = o.allowCredentials.map((c) => Object.assign({}, c, { id: b64urlToBuf(c.id) }));
    return p;
  }
  function serializeAttestation(c) {
    return {
      id: c.id, rawId: bufToB64url(c.rawId), type: c.type,
      response: {
        attestationObject: bufToB64url(c.response.attestationObject),
        clientDataJSON: bufToB64url(c.response.clientDataJSON),
        transports: c.response.getTransports ? c.response.getTransports() : [],
      },
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    };
  }
  function serializeAssertion(c) {
    return {
      id: c.id, rawId: bufToB64url(c.rawId), type: c.type,
      response: {
        authenticatorData: bufToB64url(c.response.authenticatorData),
        clientDataJSON: bufToB64url(c.response.clientDataJSON),
        signature: bufToB64url(c.response.signature),
        userHandle: c.response.userHandle ? bufToB64url(c.response.userHandle) : null,
      },
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    };
  }
  async function post(url, body) {
    const r = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || d.error || ("HTTP " + r.status));
    return d;
  }

  window.capauthWebAuthn = {
    available() {
      return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
    },
    // Passkey login for an OIDC request_id. Returns the redirect URL.
    async login(baseUrl, requestId) {
      const options = await post(baseUrl + "/oidc/passkey/login/begin", { request_id: requestId });
      const assertion = await navigator.credentials.get({ publicKey: parseRequest(options) });
      const d = await post(baseUrl + "/oidc/passkey/login/complete", {
        request_id: requestId, credential: serializeAssertion(assertion),
      });
      return d.redirect_to;
    },
    // Register a passkey for a PGP-proven fingerprint. proof = {fingerprint, nonce, nonce_signature, public_key?}
    async enroll(baseUrl, proof) {
      const begin = await post(baseUrl + "/oidc/passkey/register/begin", proof);
      const credential = await navigator.credentials.create({ publicKey: parseCreation(begin.options) });
      return post(baseUrl + "/oidc/passkey/register/complete", {
        ticket: begin.ticket, credential: serializeAttestation(credential),
      });
    },
  };
})();
"""


_BUNKER_LOGIN_JS = r"""
// CapAuth "sign in with your phone" for the OIDC IdP login page. Reuses the
// deployed bunker E2E module (same origin) — the phone (bunker) signs the
// canonical challenge over an X25519+AES-GCM channel; the broker stays blind.
import { E2ESession } from "/bunker/lib/bunker-e2e.js";
import { decryptPrivateKey, isEncryptedEnvelope } from "/bunker/lib/keyvault.js";
(function () {
  const $ = (id) => document.getElementById(id);
  function status(s) { const e = $("pq-status"); if (e) e.textContent = s; }
  function err(m) { const e = $("err"); if (e) { e.textContent = m; e.style.display = "block"; } }

  async function loadChallengeFor(base, fp) {
    const cn = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16))));
    const r = await fetch(base + "/capauth/v1/challenge", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ capauth_version: "1.0", fingerprint: fp, client_nonce: cn }),
    });
    if (!r.ok) throw new Error("could not load challenge");
    return r.json();
  }

  // PHONE-ONLY (same device): the login page is the same origin as the bunker,
  // so the key you loaded in the bunker is readable here. Decrypt it with the
  // vault passphrase and sign locally — no QR, no scanning, no 2nd device.
  window.capauthLocalSign = async function () {
    const base = window._capauthBase, reqId = window._capauthReqId;
    const fp = (localStorage.getItem("capauth_bunker_fp") || "").toUpperCase();
    const raw = localStorage.getItem("capauth_bunker_envelope");
    if (!fp || !raw) {
      return err("No key on this device yet — open the Bunker (/bunker/), load your key, then come back.");
    }
    if (!window.openpgp) return err("OpenPGP not loaded — reload the page.");
    let env; try { env = JSON.parse(raw); } catch (e) { return err("Stored key is corrupt."); }
    if (!isEncryptedEnvelope(env)) return err("Stored key is not a valid vault envelope.");
    const pass = prompt("Vault passphrase (to unlock your key on this device):");
    if (!pass) return;
    try {
      status && status("");
      const armored = await decryptPrivateKey(env, pass);
      let pk = await window.openpgp.readPrivateKey({ armoredKey: armored });
      if (!pk.isDecrypted()) {
        try { pk = await window.openpgp.decryptKey({ privateKey: pk, passphrase: pass }); }
        catch (e) { pk = await window.openpgp.decryptKey({ privateKey: pk, passphrase: "" }); }
      }
      const ch = await loadChallengeFor(base, fp);
      const canonical = [
        "CAPAUTH_NONCE_V1", "nonce=" + ch.nonce, "client_nonce=" + ch.client_nonce_echo,
        "timestamp=" + ch.timestamp, "service=" + ch.service, "expires=" + ch.expires,
      ].join("\n");
      const sig = await window.openpgp.sign({
        message: await window.openpgp.createMessage({ text: canonical }),
        signingKeys: pk, detached: true,
      });
      const r = await fetch(base + "/oidc/complete", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ request_id: reqId, fingerprint: fp, nonce: ch.nonce, nonce_signature: sig }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || d.error || "login failed");
      window.location.href = d.redirect_to;
    } catch (e) { err("Sign on this device: " + e.message); }
  };

  // Produce a PGP proof {fingerprint, nonce, nonce_signature} from the local
  // bunker key — used by the passkey ENROLL page so you can prove your key with
  // "sign on this device" instead of pasting a signature. Throws on no-key/cancel.
  window.capauthLocalProof = async function (base) {
    base = base || window._capauthBase;
    const fp = (localStorage.getItem("capauth_bunker_fp") || "").toUpperCase();
    const raw = localStorage.getItem("capauth_bunker_envelope");
    if (!fp || !raw) throw new Error("No key on this device — open /bunker/, load your key, then come back.");
    if (!window.openpgp) throw new Error("OpenPGP not loaded — reload the page.");
    const env = JSON.parse(raw);
    if (!isEncryptedEnvelope(env)) throw new Error("Stored key is not a valid vault envelope.");
    const pass = prompt("Vault passphrase (to unlock your key on this device):");
    if (!pass) throw new Error("cancelled");
    const armored = await decryptPrivateKey(env, pass);
    let pk = await window.openpgp.readPrivateKey({ armoredKey: armored });
    if (!pk.isDecrypted()) {
      try { pk = await window.openpgp.decryptKey({ privateKey: pk, passphrase: pass }); }
      catch (e) { pk = await window.openpgp.decryptKey({ privateKey: pk, passphrase: "" }); }
    }
    const ch = await loadChallengeFor(base, fp);
    const canonical = [
      "CAPAUTH_NONCE_V1", "nonce=" + ch.nonce, "client_nonce=" + ch.client_nonce_echo,
      "timestamp=" + ch.timestamp, "service=" + ch.service, "expires=" + ch.expires,
    ].join("\n");
    const sig = await window.openpgp.sign({
      message: await window.openpgp.createMessage({ text: canonical }),
      signingKeys: pk, detached: true,
    });
    return { fingerprint: fp, nonce: ch.nonce, nonce_signature: sig };
  };

  window.capauthPhoneLogin = async function () {
    const base = window._capauthBase, reqId = window._capauthReqId, ch = window._capauthCh;
    const fp = ($("fp").value || "").trim().toUpperCase().replace(/\s/g, "");
    if (![40, 64].includes(fp.length)) return err("Enter your 40- or 64-hex fingerprint first.");
    if (!ch) return err("Tab out of the fingerprint field to load a challenge first.");
    const canonical = [
      "CAPAUTH_NONCE_V1", "nonce=" + ch.nonce, "client_nonce=" + ch.client_nonce_echo,
      "timestamp=" + ch.timestamp, "service=" + ch.service, "expires=" + ch.expires,
    ].join("\n");
    let sess;
    try {
      sess = await (await fetch(base + "/bunker/session", {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      })).json();
    } catch (e) { return err("Could not start phone session: " + e.message); }
    const img = $("pq-img"); if (img) img.src = sess.qr_data_url;
    const uri = $("pq-uri"); if (uri) uri.textContent = sess.pairing_uri;
    const box = $("pq"); if (box) box.style.display = "block";
    status("Scan this QR with your phone (the CapAuth Bunker), then tap Approve…");
    const e2e = new E2ESession(sess.pairing_secret);
    try {
      const resp = await new Promise((resolve, reject) => {
        const wsurl = sess.relay_ws_url + "?session=" + encodeURIComponent(sess.session_id) +
          "&role=client&key=" + encodeURIComponent(sess.pairing_secret);
        const ws = new WebSocket(wsurl); let sent = false;
        const t = setTimeout(() => { try { ws.close(); } catch (e) {} reject(new Error("Timed out waiting for your phone.")); }, 120000);
        ws.onmessage = async (ev) => {
          let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
          try {
            if (m.type === "paired") { ws.send(JSON.stringify(await e2e.start())); }
            else if (m.type === "kex") {
              await e2e.onKex(m.pub);
              if (!sent) {
                sent = true; status("Paired — approve the sign-in on your phone.");
                ws.send(JSON.stringify(await e2e.seal({
                  type: "sign_request", id: "idp-" + Date.now(), payload: canonical,
                  origin: location.origin, fingerprint: fp, version: "CAPAUTH_NONCE_V1",
                })));
              }
            } else if (m.type === "enc") {
              const inner = await e2e.open(m);
              if (inner.type === "sign_response") { clearTimeout(t); ws.close(); resolve(inner); }
              else if (inner.type === "reject") { clearTimeout(t); ws.close(); reject(new Error(inner.reason || "declined on phone")); }
            } else if (m.type === "error") { clearTimeout(t); ws.close(); reject(new Error("relay: " + (m.code || "error"))); }
            else if (m.type === "peer_left") { clearTimeout(t); ws.close(); reject(new Error("phone disconnected")); }
          } catch (e) { clearTimeout(t); try { ws.close(); } catch (_) {} reject(e); }
        };
        ws.onerror = () => { clearTimeout(t); reject(new Error("relay connection error")); };
      });
      status("Signed — completing login…");
      const r = await fetch(base + "/oidc/complete", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ request_id: reqId, fingerprint: resp.fingerprint || fp, nonce: ch.nonce, nonce_signature: resp.signature }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || d.error || "login failed");
      window.location.href = d.redirect_to;
    } catch (e) { err("Phone sign-in: " + e.message); status(""); }
  };
})();
"""


_ENROLL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CapAuth — Add a passkey</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f0f1a;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
    .card{{background:#1a1a35;border:1px solid rgba(124,58,237,.25);border-radius:14px;padding:2rem;max-width:520px;width:100%}}
    h1{{font-size:1.3rem;color:#a78bfa;margin-bottom:.4rem}}
    p.sub{{color:#94a3b8;font-size:.85rem;margin-bottom:1.2rem;line-height:1.5}}
    .step{{color:#64748b;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;margin:.8rem 0 .3rem}}
    input,textarea{{width:100%;background:#0f0f1a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;
                    padding:.6rem .8rem;font-size:.86rem;margin-bottom:.6rem;font-family:monospace}}
    textarea{{min-height:120px;resize:vertical}}
    button{{width:100%;background:#7C3AED;color:#fff;border:none;border-radius:8px;padding:.8rem;font-size:1rem;cursor:pointer;font-weight:600;margin-top:.4rem}}
    .nonce-box{{background:#0f0f1a;border:1px solid #334155;border-radius:8px;padding:.6rem;font-family:monospace;font-size:.76rem;color:#00e5ff;word-break:break-all;margin-bottom:.6rem}}
    .msg{{font-size:.85rem;margin-top:.8rem;min-height:1.1rem}}
    .identity{{background:#0f0f1a;border:1px solid #334155;border-radius:8px;padding:.7rem .8rem;
               color:#94a3b8;font-size:.8rem;margin:.8rem 0}}
    .workflow-step{{border:1px solid #334155;border-radius:10px;padding:.8rem;margin:.7rem 0}}
    .workflow-step h2{{font-size:.95rem;margin-bottom:.35rem}}
    .number{{display:inline-block;background:#7C3AED;border-radius:50%;width:1.5rem;height:1.5rem;
             line-height:1.5rem;text-align:center;margin-right:.4rem}}
    .setup{{display:inline-block;background:#334155;color:#fff;border-radius:8px;padding:.6rem .8rem;
            text-decoration:none;font-weight:600;margin-top:.4rem}}
    button:disabled{{background:#475569;cursor:not-allowed}}
    details{{border-top:1px solid #334155;margin-top:1.1rem;padding-top:.8rem}}
    summary{{color:#a78bfa;cursor:pointer;font-size:.85rem}}
    .ok{{color:#34d399}} .err{{color:#f87171}}
    code{{color:#a78bfa}}
  </style>
</head>
<body>
<div class="card">
  <h1>🔑 Add a passkey</h1>
  <p class="sub">A passkey is an <strong>easy, phishing-resistant</strong> way to sign in — bound to
     your sovereign PGP identity. Prove your fingerprint with PGP once, then create a passkey for it.
     (Convenience tier — your PGP key stays the root of trust.)</p>

  <div class="workflow-step">
    <h2><span class="number">1</span>Check this browser</h2>
    <div class="identity" id="identity-status">Checking for your existing CapAuth identity...</div>
    <a class="setup" id="setup-identity" href="{base_url}/bunker/">Set up this browser</a>
    <p class="sub" style="font-size:.74rem;margin:.4rem 0 0">You only need to load your existing identity. Do not create a new key.</p>
  </div>

  <div class="workflow-step">
    <h2><span class="number">2</span>Create the passkey</h2>
    <button id="ld-enroll" onclick="enrollLocal()" style="background:#10b981" disabled>Create passkey with this device</button>
    <p class="sub" style="font-size:.74rem;margin:.4rem 0 0">Unlock your existing identity once, then approve the passkey prompt from your browser or password manager.</p>
  </div>

  <div class="workflow-step" id="finish-step">
    <h2><span class="number">3</span>Finish</h2>
    <p class="sub" id="finish-text" style="margin:0">After creation, return to SKDashboard and choose Sign in with a passkey.</p>
  </div>

  <details id="manual-enrollment">
    <summary>Advanced recovery: prove the identity manually</summary>
    <p class="sub" style="font-size:.74rem;margin:.6rem 0">Use this only when the Bunker cannot be used in this browser. Each challenge expires and needs a fresh signature.</p>
    <div class="step">1 - PGP fingerprint</div>
    <input id="fp" maxlength="64" placeholder="Example: 40 or 64 hexadecimal characters" autocomplete="off"/>
    <div class="step">2 - Exact message to sign</div>
    <div class="nonce-box" id="nonce" style="white-space:pre-wrap">Enter your fingerprint to load the complete signed payload.</div>
    <button type="button" onclick="copyPayload()" style="width:auto;padding:.45rem .7rem;font-size:.78rem;background:#334155">Copy message</button>
    <div class="step">3 - Fresh PGP signature</div>
    <textarea id="sig" placeholder="-----BEGIN PGP MESSAGE-----"></textarea>
    <textarea id="pub" style="min-height:70px" placeholder="Public key, only if this identity is not enrolled yet"></textarea>
    <p class="sub" style="font-size:.74rem">Copy the complete message, then use <code>gpg --armor --sign</code> for an inline signed message or <code>gpg --armor --detach-sign</code> for a detached signature.</p>
    <button onclick="enroll()">Verify signature and create passkey</button>
  </details>
  <div class="msg" id="msg"></div>
</div>
<script src="{base_url}/oidc/passkey.js"></script>
<script src="{base_url}/bunker/vendor/openpgp.min.js"></script>
<script type="module" src="{base_url}/oidc/bunker-login.js?v=15"></script>
<script>
const BASE="{base_url}";
window._capauthBase = BASE;
let currentNonce=null, currentPayload="";
function msg(t,ok){{ const e=document.getElementById("msg"); e.textContent=t; e.className="msg "+(ok?"ok":"err"); }}
function friendlyError(e){{
  const text=String(e&&e.message||e||"");
  if(text.includes("passkey_rp_unavailable")) return "Passkey setup is not ready on this server. Ask the administrator to finish the named-host setup.";
  if(text.includes("fingerprint_not_approved")||text.includes("unknown_fingerprint")) return "This identity is not approved yet. Ask the administrator to enroll its public fingerprint, then try again.";
  if(text.includes("NotAllowedError")||text.includes("cancel")) return "The passkey prompt was cancelled. Click Create passkey when you are ready and approve the prompt.";
  return "Passkey creation failed. Open Advanced recovery only if the normal browser setup cannot be used. Details: "+text;
}}
function detectLocalIdentity(){{
  const fp=(localStorage.getItem("capauth_bunker_fp")||"").trim().toUpperCase().replace(/\\s/g,"");
  const hasEnvelope=Boolean(localStorage.getItem("capauth_bunker_envelope"));
  const valid=[40,64].includes(fp.length)&&/^[0-9A-F]+$/.test(fp)&&hasEnvelope;
  const status=document.getElementById("identity-status");
  const setup=document.getElementById("setup-identity");
  const button=document.getElementById("ld-enroll");
  if(valid){{
    status.textContent="Ready: CapAuth identity "+fp.slice(0,8)+"..."+fp.slice(-8)+" is loaded in this browser.";
    document.getElementById("fp").value=fp;
    setup.hidden=true;
    button.disabled=false;
  }}else{{
    status.textContent="Setup needed: load your existing identity in this browser first.";
    setup.hidden=false;
    button.disabled=true;
  }}
  return valid;
}}
async function enrollLocal(){{
  if(!window.capauthWebAuthn||!window.capauthWebAuthn.available()) return msg("Use a browser or password manager that supports passkeys.",false);
  if(!window.capauthLocalProof) return msg("The identity helper is still loading. Wait one second, then click again.",false);
  if(!detectLocalIdentity()) return msg("Open the Bunker, load your existing identity, then return here.",false);
  msg("Unlock your identity, then approve the passkey prompt.",true);
  try{{
    const proof=await window.capauthLocalProof(BASE);
    const res=await window.capauthWebAuthn.enroll(BASE,proof);
    document.getElementById("finish-text").textContent="Passkey created for "+res.fingerprint.slice(0,8)+"... Return to SKDashboard and choose Sign in with a passkey.";
    msg("Passkey created successfully.",true);
  }}catch(e){{ msg(friendlyError(e),false); }}
}}
async function loadChallenge(fp){{
  const r=await fetch(BASE+"/capauth/v1/challenge",{{method:"POST",headers:{{"Content-Type":"application/json"}},
    body:JSON.stringify({{capauth_version:"1.0",fingerprint:fp,
      client_nonce:btoa(String.fromCharCode.apply(null,crypto.getRandomValues(new Uint8Array(16))))}})}});
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}}
async function copyPayload(){{
  if(!currentPayload) return msg("Enter a valid fingerprint to load a fresh challenge first.",false);
  try{{ await navigator.clipboard.writeText(currentPayload); }}
  catch(e){{ msg("Copy failed. Select the complete message and copy it manually.",false); }}
}}
document.getElementById("fp").addEventListener("blur",async function(){{
  const fp=this.value.trim().toUpperCase().replace(/\\s/g,"");
  if(![40,64].includes(fp.length)) return;
  try{{ const ch=await loadChallenge(fp); currentNonce=ch.nonce;
    currentPayload=["CAPAUTH_NONCE_V1", "nonce="+ch.nonce,
      "client_nonce="+ch.client_nonce_echo, "timestamp="+ch.timestamp,
      "service="+ch.service, "expires="+ch.expires].join("\\n");
    document.getElementById("nonce").textContent=currentPayload;
    if(window.capauth&&window.capauth.isCapAuth){{ try{{ const res=await window.capauth.signChallenge(ch);
      document.getElementById("sig").value=res.signature; }}catch(e){{}} }}
  }}catch(e){{ document.getElementById("nonce").textContent="Error: "+e.message; }}
}});
async function enroll(){{
  if(!window.capauthWebAuthn||!window.capauthWebAuthn.available()) return msg("This browser has no passkey support.",false);
  const fp=document.getElementById("fp").value.trim().toUpperCase().replace(/\\s/g,"");
  const sig=document.getElementById("sig").value.trim();
  const pub=document.getElementById("pub").value.trim();
  if(![40,64].includes(fp.length)) return msg("Fingerprint must be 40- or 64-hex characters.",false);
  if(!currentNonce) return msg("Load a challenge first (tab out of the fingerprint field).",false);
  if(!sig) return msg("Paste your PGP signature.",false);
  msg("Verifying PGP and creating passkey…",true);
  try{{
    const proof={{fingerprint:fp,nonce:currentNonce,nonce_signature:sig}};
    if(pub) proof.public_key=pub;
    const res=await window.capauthWebAuthn.enroll(BASE,proof);
    msg("✅ Passkey created for "+res.fingerprint.slice(0,8)+"… — you can now sign in with it.",true);
  }}catch(e){{ msg("Failed: "+e.message,false); }}
}}
detectLocalIdentity();
document.addEventListener("visibilitychange",function(){{ if(!document.hidden) detectLocalIdentity(); }});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_oidc_router(
    *,
    signing_key: Optional[SigningKey] = None,
    clients: Optional[ClientRegistry] = None,
    store: Optional[AuthCodeStore] = None,
    passkeys: Optional[PasskeyStore] = None,
) -> APIRouter:
    """Build the OIDC IdP router.

    Args:
        signing_key: RSA token-signing key. Defaults to a persisted
            :class:`SigningKey`.
        clients: Static :class:`ClientRegistry`. Defaults to env-loaded.
        store: :class:`AuthCodeStore`. Defaults to the durable service store.

    Returns:
        APIRouter: Mount at prefix ``/oidc``.
    """
    signing_key = signing_key or SigningKey()
    clients = clients if clients is not None else ClientRegistry()
    store = store if store is not None else AuthCodeStore()
    passkeys = (
        passkeys
        if passkeys is not None
        else PasskeyStore(data_dir=os.environ.get("CAPAUTH_PASSKEY_DATA_DIR"))
    )

    router = APIRouter(tags=["oidc-idp"])
    # Expose internals for the main app / tests.
    router.signing_key = signing_key  # type: ignore[attr-defined]
    router.clients = clients  # type: ignore[attr-defined]
    router.store = store  # type: ignore[attr-defined]
    router.passkeys = passkeys  # type: ignore[attr-defined]

    def _passkey_preflight() -> None:
        try:
            passkeys.preflight()
        except PasskeyRPUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_rp_unavailable") from None
        except PasskeyStoreUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_state_unavailable") from None

    def _authorize_dashboard_grant(subject: str) -> None:
        try:
            policy_subject = canonical_subject(f"device:{subject}")
        except SubjectNamingError:
            logger.warning("OIDC dashboard grant denied: invalid policy subject")
            raise HTTPException(status_code=403, detail="grant_not_current")
        try:
            decisions = [
                decide(
                    policy_subject,
                    scope,
                    resource={"audience": SKDASHBOARD_AUDIENCE},
                    context={"purpose": "oidc_session_refresh"},
                    base_dir=resolve_capauth_home(),
                )
                for scope in SKDASHBOARD_SCOPES
            ]
        except Exception:
            raise HTTPException(status_code=503, detail="policy_unavailable")
        if not all(decision.allow for decision in decisions):
            denied = [
                scope
                for scope, decision in zip(SKDASHBOARD_SCOPES, decisions)
                if not decision.allow
            ]
            logger.warning("OIDC dashboard grant denied by policy for scopes=%s", ",".join(denied))
            raise HTTPException(status_code=403, detail="grant_not_current")

    def _mint_dashboard_access(subject: str, family_id: str) -> str:
        _authorize_dashboard_grant(subject)
        try:
            token = mint_audience_token(
                resolve_capauth_home(),
                subject,
                SKDASHBOARD_AUDIENCE,
                list(SKDASHBOARD_SCOPES),
                ttl_seconds=MAX_TOKEN_TTL,
                metadata={
                    "refresh_family": family_id,
                    "policy_version": SESSION_POLICY_VERSION,
                },
                sign=True,
                store=False,
            )
        except TokenSigningError:
            raise HTTPException(status_code=503, detail="signer_unavailable")
        except Exception:
            raise HTTPException(status_code=503, detail="issuer_unavailable")
        return base64.urlsafe_b64encode(export_token(token).encode("utf-8")).decode("ascii")

    def _verify_pgp(
        fingerprint: str,
        nonce: str,
        nonce_signature: str,
        public_key: str,
        claims: dict[str, Any],
        claims_signature: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Reuse the service's PGP verify path (challenge/nonce/verify/claims).

        Returns ``(ok, error_code, oidc_claims)``.  Implemented lazily so the
        OIDC module imports cleanly without the FastAPI app side-effects.
        """
        from ...authentik.nonce_store import peek
        from ...authentik.stage import verify_auth_response
        from ...authentik.verifier import fingerprint_from_armor
        from ..app import SERVICE_ID, get_keystore

        try:
            ks = get_keystore()
            existing = ks.get(fingerprint)
        except Exception:
            return False, "enrollment_unavailable", {}
        if existing is None:
            return False, "unknown_fingerprint", {}
        if not getattr(existing, "approved", False):
            return False, "fingerprint_not_approved", {}

        armor = public_key or existing.public_key_armor

        derived = fingerprint_from_armor(armor)
        if derived and derived.upper() != fingerprint.upper():
            return False, "invalid_fingerprint", {}

        nonce_record = peek(nonce)
        if nonce_record is None:
            return False, "invalid_nonce", {}
        challenge_ctx = {
            "nonce": nonce_record["nonce"],
            "client_nonce_echo": nonce_record.get("client_nonce_echo", ""),
            "timestamp": nonce_record["issued_at"],
            "service": SERVICE_ID,
            "expires": nonce_record["expires_at"],
        }
        ok, err, oidc_claims = verify_auth_response(
            fingerprint=fingerprint,
            nonce_id=nonce,
            nonce_signature_armor=nonce_signature,
            claims=claims,
            claims_signature_armor=claims_signature,
            public_key_armor=armor,
            challenge_context=challenge_ctx,
        )
        if ok:
            try:
                ks.update_last_auth(fingerprint)
            except Exception:
                return False, "enrollment_unavailable", {}
        return ok, err, oidc_claims

    # ------------------------------------------------------------------
    # Discovery + JWKS
    # ------------------------------------------------------------------

    @router.get("/.well-known/openid-configuration", summary="OIDC discovery")
    async def discovery() -> dict[str, Any]:
        return discovery_document()

    @router.get("/jwks.json", summary="JSON Web Key Set (RSA signing key)")
    async def jwks() -> dict[str, Any]:
        return signing_key.jwks()

    # ------------------------------------------------------------------
    # Authorization endpoint — renders the PGP login page
    # ------------------------------------------------------------------

    def _source(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _limit(bucket: str, key: str) -> None:
        try:
            store.enforce_rate_limit(bucket, key, limit=_RATE_LIMITS[bucket])
        except RateLimitExceededError:
            raise HTTPException(status_code=429, detail="rate_limited")
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")

    def _current_identity(fingerprint: str) -> bool:
        from ..app import get_keystore

        try:
            enrolled = get_keystore().get(fingerprint)
        except Exception:
            raise HTTPException(status_code=503, detail="enrollment_unavailable")
        return bool(enrolled is not None and getattr(enrolled, "approved", False))

    def _decode_access_token(token_str: str) -> dict[str, Any]:
        try:
            iss = issuer_url()
        except ValueError:
            raise HTTPException(status_code=503, detail="issuer_unavailable")
        try:
            payload = pyjwt.decode(
                token_str,
                signing_key.public_pem,
                algorithms=[signing_key.ALGORITHM],
                issuer=iss,
                audience=None,
                options={
                    "verify_aud": False,
                    "require": [
                        "sub",
                        "iss",
                        "aud",
                        "iat",
                        "exp",
                        "jti",
                        "scope",
                        "token_use",
                    ],
                },
            )
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token_expired")
        except pyjwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="invalid_token")
        if (
            payload.get("token_use") != "access"
            or not isinstance(payload.get("aud"), str)
            or type(payload.get("iat")) is not int
            or type(payload.get("exp")) is not int
            or not 1 <= payload["exp"] - payload["iat"] <= MAX_TOKEN_TTL
        ):
            raise HTTPException(status_code=401, detail="invalid_token")
        client = clients.get(payload["aud"])
        granted = str(payload.get("scope", "")).split()
        if client is None or "openid" not in granted or not set(granted).issubset(client.scopes):
            raise HTTPException(status_code=401, detail="grant_not_current")
        try:
            current = store.access_token_current(payload["jti"], payload["sub"], payload["aud"])
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="currentness_unavailable")
        if not current:
            raise HTTPException(status_code=401, detail="token_not_current")
        if not _current_identity(payload["sub"]):
            raise HTTPException(status_code=401, detail="enrollment_not_current")
        return payload

    @router.get("/authorize", summary="Authorization endpoint (renders PGP login)")
    async def authorize(
        request: Request,
        response_type: str = "code",
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "openid",
        state: str = "",
        nonce: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        issuer: str = "",
    ) -> Any:
        _limit("authorize", _source(request))
        if response_type != "code":
            raise HTTPException(status_code=400, detail="unsupported_response_type")

        client = clients.get(client_id)
        if client is None:
            raise HTTPException(status_code=400, detail="unknown client_id")
        if not redirect_uri or not client.redirect_uri_allowed(redirect_uri):
            # Per OAuth2: do NOT redirect on an invalid redirect_uri.
            raise HTTPException(status_code=400, detail="invalid redirect_uri")
        try:
            expected_issuer = issuer_url()
        except ValueError:
            raise HTTPException(status_code=503, detail="issuer_unavailable")
        if issuer and issuer != expected_issuer:
            raise HTTPException(status_code=400, detail="invalid_issuer")
        if code_challenge_method != "S256":
            raise HTTPException(status_code=400, detail="unsupported code_challenge_method")
        if not (43 <= len(code_challenge) <= 128):
            raise HTTPException(status_code=400, detail="invalid_code_challenge")
        if not (_OPAQUE_MIN_LENGTH <= len(state) <= 512):
            raise HTTPException(status_code=400, detail="invalid_state")
        if not (_OPAQUE_MIN_LENGTH <= len(nonce) <= 512):
            raise HTTPException(status_code=400, detail="invalid_nonce")
        scopes = scope.split()
        if (
            "openid" not in scopes
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset(client.scopes)
            or not set(scopes).issubset(SUPPORTED_SCOPES)
        ):
            raise HTTPException(status_code=400, detail="invalid_scope")

        try:
            req = store.create_login_request(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=" ".join(scopes),
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                nonce=nonce,
            )
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")

        base_url = expected_issuer
        html = _LOGIN_PAGE.format(
            base_url=base_url,
            request_id=req.request_id,
            client_name=client.name or client.client_id,
        )
        return HTMLResponse(content=html)

    # ------------------------------------------------------------------
    # Completion endpoint — called by the login page after the user signs
    # ------------------------------------------------------------------

    @router.post("/complete", summary="Complete PGP login and mint an auth code")
    async def complete(request: Request) -> dict[str, Any]:
        body = await request.json()
        request_id = (body.get("request_id") or "").strip()
        fingerprint = (body.get("fingerprint") or "").strip().upper()
        nonce_sig = (body.get("nonce_signature") or "").strip()
        nonce_id = (body.get("nonce") or "").strip()
        public_key = (body.get("public_key") or "").strip()
        claims = body.get("claims") or {}
        claims_sig = (body.get("claims_signature") or "").strip()

        _limit("complete", f"{_source(request)}:{fingerprint}")
        try:
            login_req = store.get_login_request(request_id)
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")
        if login_req is None:
            raise HTTPException(status_code=400, detail="expired or unknown request")
        if len(fingerprint) not in (40, 64) or not nonce_sig or not nonce_id:
            raise HTTPException(
                status_code=400, detail="fingerprint, nonce, nonce_signature required"
            )

        ok, err, oidc_claims = _verify_pgp(
            fingerprint=fingerprint,
            nonce=nonce_id,
            nonce_signature=nonce_sig,
            public_key=public_key,
            claims=claims,
            claims_signature=claims_sig,
        )
        if not ok:
            if err == "enrollment_unavailable":
                raise HTTPException(status_code=503, detail=err)
            if err == "fingerprint_not_approved":
                raise HTTPException(status_code=403, detail=err)
            raise HTTPException(status_code=401, detail=err or "pgp_verification_failed")

        try:
            login_req, code_record = store.complete_login_request(
                request_id, fingerprint, oidc_claims
            )
        except InvalidGrantError:
            raise HTTPException(status_code=400, detail="expired_or_unknown_request")
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")

        params = {"code": code_record.code}
        if login_req.state:
            params["state"] = login_req.state
        redirect_to = f"{login_req.redirect_uri}?{urlencode(params)}"
        logger.info("OIDC code issued for fp=%s client=%s", fingerprint[:8], login_req.client_id)
        return {"redirect_to": redirect_to}

    # ------------------------------------------------------------------
    # Passkey (WebAuthn) — convenience front-door bound to a PGP fingerprint
    # ------------------------------------------------------------------

    @router.post("/passkey/register/begin", summary="Begin passkey registration (PGP-gated)")
    async def passkey_register_begin(request: Request) -> dict[str, Any]:
        """Authorize passkey registration by verifying a PGP signature for the
        fingerprint, then return WebAuthn creation options + a binding ticket.
        A passkey can ONLY be registered for a fingerprint you can sign for."""
        _passkey_preflight()
        body = await request.json()
        fingerprint = (body.get("fingerprint") or "").strip().upper()
        nonce_sig = (body.get("nonce_signature") or "").strip()
        nonce_id = (body.get("nonce") or "").strip()
        public_key = (body.get("public_key") or "").strip()
        if len(fingerprint) not in (40, 64) or not nonce_sig or not nonce_id:
            raise HTTPException(
                status_code=400, detail="fingerprint, nonce, nonce_signature required"
            )
        ok, err, _claims = _verify_pgp(
            fingerprint=fingerprint,
            nonce=nonce_id,
            nonce_signature=nonce_sig,
            public_key=public_key,
            claims={},
            claims_signature="",
        )
        if not ok:
            if err == "enrollment_unavailable":
                raise HTTPException(status_code=503, detail=err)
            if err == "fingerprint_not_approved":
                raise HTTPException(status_code=403, detail=err)
            raise HTTPException(status_code=401, detail=err or "pgp_verification_failed")
        ticket, options = passkeys.begin_registration(fingerprint)
        return {"ticket": ticket, "options": options}

    @router.post("/passkey/register/complete", summary="Finish passkey registration")
    async def passkey_register_complete(request: Request) -> dict[str, Any]:
        body = await request.json()
        ticket = (body.get("ticket") or "").strip()
        credential = body.get("credential")
        if not ticket or not credential:
            raise HTTPException(status_code=400, detail="ticket + credential required")
        try:
            fp, cid = passkeys.complete_registration(ticket, credential)
        except PasskeyRPUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_rp_unavailable")
        except PasskeyStoreUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_state_unavailable")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"registration_failed: {exc}")
        return {"ok": True, "fingerprint": fp, "credential_id": cid}

    @router.post("/passkey/login/begin", summary="Begin passkey login")
    async def passkey_login_begin(request: Request) -> dict[str, Any]:
        _passkey_preflight()
        body = await request.json()
        request_id = (body.get("request_id") or "").strip()
        fingerprint_hint = (body.get("fingerprint") or "").strip().upper()
        try:
            login_req = store.get_login_request(request_id)
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")
        if login_req is None:
            raise HTTPException(status_code=400, detail="expired or unknown request")
        return passkeys.begin_authentication(request_id, fingerprint_hint)

    @router.post("/passkey/login/complete", summary="Finish passkey login -> auth code")
    async def passkey_login_complete(request: Request) -> dict[str, Any]:
        body = await request.json()
        request_id = (body.get("request_id") or "").strip()
        credential = body.get("credential")
        try:
            login_req = store.get_login_request(request_id)
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")
        if login_req is None:
            raise HTTPException(status_code=400, detail="expired or unknown request")
        if not credential:
            raise HTTPException(status_code=400, detail="credential required")
        try:
            fingerprint = passkeys.complete_authentication(request_id, credential)
        except PasskeyRPUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_rp_unavailable")
        except PasskeyStoreUnavailableError:
            raise HTTPException(status_code=503, detail="passkey_state_unavailable")
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"passkey_verification_failed: {exc}")

        # The passkey resolves to a fingerprint; that key MUST already be an
        # approved CapAuth identity (it was enrolled when the passkey was
        # registered behind PGP proof). Refuse otherwise.
        if not _current_identity(fingerprint):
            raise HTTPException(status_code=403, detail="fingerprint_not_approved")

        claims = {"amr": ["webauthn"]}
        try:
            login_req, code_record = store.complete_login_request(request_id, fingerprint, claims)
        except InvalidGrantError:
            raise HTTPException(status_code=400, detail="expired_or_unknown_request")
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")
        params = {"code": code_record.code}
        if login_req.state:
            params["state"] = login_req.state
        redirect_to = f"{login_req.redirect_uri}?{urlencode(params)}"
        logger.info(
            "OIDC code issued (passkey) for fp=%s client=%s", fingerprint[:8], login_req.client_id
        )
        return {"redirect_to": redirect_to}

    @router.get("/passkey/enroll", summary="Passkey enrollment page (PGP-gated)")
    async def passkey_enroll() -> Any:
        _passkey_preflight()
        return HTMLResponse(content=_ENROLL_PAGE.format(base_url=issuer_url()))

    _JS_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}  # noqa: N806

    @router.get("/passkey.js", summary="Passkey (WebAuthn) browser helpers")
    async def passkey_js() -> Any:
        from fastapi.responses import Response

        return Response(
            content=_PASSKEY_JS, media_type="application/javascript", headers=_JS_NO_CACHE
        )

    @router.get("/bunker-login.js", summary="Sign-in-with-your-phone (bunker) helper")
    async def bunker_login_js() -> Any:
        from fastapi.responses import Response

        return Response(
            content=_BUNKER_LOGIN_JS, media_type="application/javascript", headers=_JS_NO_CACHE
        )

    # ------------------------------------------------------------------
    # Token endpoint
    # ------------------------------------------------------------------

    @router.post("/token", summary="Token endpoint (authorization_code + PKCE)")
    async def token(
        request: Request,
        grant_type: str = Form(default="authorization_code"),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
        refresh_token: str = Form(default=""),
    ) -> dict[str, Any]:
        if grant_type not in {"authorization_code", "refresh_token"}:
            raise HTTPException(status_code=400, detail="unsupported_grant_type")

        # Support HTTP Basic client auth (client_secret_basic) as well.
        if not client_id:
            import base64 as _b64

            auth = request.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                try:
                    decoded = _b64.b64decode(auth[6:]).decode("utf-8")
                    client_id, _, client_secret = decoded.partition(":")
                except Exception:
                    raise HTTPException(status_code=401, detail="invalid_client")

        _limit("token", f"{_source(request)}:{client_id}")
        client = clients.get(client_id)
        if client is None or not client.secret_matches(client_secret):
            raise HTTPException(status_code=401, detail="invalid_client")

        if grant_type == "refresh_token":
            if client_id != SKDASHBOARD_AUDIENCE or not refresh_token:
                raise HTTPException(status_code=400, detail="invalid_grant")
            try:
                grant = store.inspect_refresh_token(refresh_token)
            except InvalidGrantError:
                raise HTTPException(status_code=400, detail="invalid_grant")
            except OIDCStateUnavailableError:
                raise HTTPException(status_code=503, detail="state_unavailable")
            if (
                grant.client_id != client_id
                or grant.audience != SKDASHBOARD_AUDIENCE
                or grant.scope != " ".join(SKDASHBOARD_SCOPES)
                or grant.policy_version != SESSION_POLICY_VERSION
                or not set(SKDASHBOARD_AUTH_SCOPES).issubset(client.scopes)
                or not _current_identity(grant.subject)
            ):
                raise HTTPException(status_code=403, detail="grant_not_current")
            access_token = _mint_dashboard_access(grant.subject, grant.family_id)
            try:
                successor = store.rotate_refresh_token(grant)
            except InvalidGrantError:
                raise HTTPException(status_code=400, detail="invalid_grant")
            except OIDCStateUnavailableError:
                raise HTTPException(status_code=503, detail="state_unavailable")
            return {
                "access_token": access_token,
                "refresh_token": successor.token,
                "token_type": "Bearer",
                "expires_in": MAX_TOKEN_TTL,
                "scope": successor.scope,
            }

        try:
            record = store.consume_code(code, client_id, redirect_uri, code_verifier)
        except InvalidGrantError:
            raise HTTPException(status_code=400, detail="invalid_grant")
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")

        try:
            iss = issuer_url()
            id_token_ttl = _bounded_ttl("CAPAUTH_OIDC_ID_TOKEN_TTL")
            access_token_ttl = _bounded_ttl("CAPAUTH_OIDC_ACCESS_TOKEN_TTL")
        except ValueError:
            raise HTTPException(status_code=503, detail="configuration_unavailable")
        now = int(time.time())
        sub = record.fingerprint

        id_claims: dict[str, Any] = {
            "iss": iss,
            "sub": sub,
            "aud": client_id,
            "iat": now,
            "exp": now + id_token_ttl,
            # How the user actually authenticated: ["pgp"] (sovereign) or
            # ["webauthn"] (passkey convenience tier). Set when the code is minted.
            "amr": record.claims.get("amr", ["pgp"]),
            "capauth_fingerprint": sub,
        }
        if record.nonce:
            id_claims["nonce"] = record.nonce
        # Fold in verified profile claims (name/email/groups/etc.) from mapper.
        for key in (
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "groups",
            "picture",
            "locale",
            "agent_type",
        ):
            if key in record.claims:
                id_claims[key] = record.claims[key]
        id_claims.setdefault("preferred_username", preferred_username_fallback(sub))

        headers = {"kid": signing_key.kid}
        jti = secrets.token_urlsafe(24)
        access_claims = dict(id_claims)
        access_claims["exp"] = now + access_token_ttl
        access_claims["token_use"] = "access"
        access_claims["jti"] = jti
        access_claims["scope"] = record.scope
        try:
            id_token = pyjwt.encode(
                id_claims,
                signing_key.private_pem,
                algorithm=signing_key.ALGORITHM,
                headers=headers,
            )
            access_token = pyjwt.encode(
                access_claims,
                signing_key.private_pem,
                algorithm=signing_key.ALGORITHM,
                headers=headers,
            )
        except Exception:
            raise HTTPException(status_code=503, detail="signer_unavailable")

        if client_id == SKDASHBOARD_AUDIENCE:
            if frozenset(record.scope.split()) != SKDASHBOARD_AUTH_SCOPES:
                raise HTTPException(status_code=403, detail="grant_not_current")
            if not _current_identity(sub):
                raise HTTPException(status_code=403, detail="enrollment_not_current")
            try:
                refresh = store.create_refresh_family(
                    subject=sub,
                    client_id=client_id,
                    audience=SKDASHBOARD_AUDIENCE,
                    scope=" ".join(SKDASHBOARD_SCOPES),
                    policy_version=SESSION_POLICY_VERSION,
                )
            except OIDCStateUnavailableError:
                raise HTTPException(status_code=503, detail="state_unavailable")
            try:
                access_token = _mint_dashboard_access(sub, refresh.family_id)
            except HTTPException:
                try:
                    store.revoke_refresh_family(refresh.token)
                except OIDCStateUnavailableError:
                    pass
                raise
            return {
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": refresh.token,
                "token_type": "Bearer",
                "expires_in": MAX_TOKEN_TTL,
                "scope": refresh.scope,
            }
        try:
            store.register_access_token(jti, sub, client_id, now + access_token_ttl)
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="state_unavailable")

        logger.info("OIDC token issued for fp=%s client=%s", sub[:8], client_id)
        return {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": access_token_ttl,
            "scope": record.scope,
        }

    # ------------------------------------------------------------------
    # UserInfo endpoint
    # ------------------------------------------------------------------

    @router.get("/userinfo", summary="UserInfo (Bearer access token -> claims)")
    async def userinfo(request: Request) -> dict[str, Any]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token_str = auth[len("Bearer ") :]
        payload = _decode_access_token(token_str)

        drop = {"iat", "exp", "iss", "aud", "token_use", "nonce", "jti", "scope"}
        return {k: v for k, v in payload.items() if k not in drop}

    @router.post("/logout", summary="Revoke the current OIDC access token")
    @router.post("/revoke", summary="Revoke the current OIDC access token")
    async def revoke(
        request: Request,
        token: str = Form(default=""),
        token_type_hint: str = Form(default=""),
    ) -> dict[str, bool]:
        _limit("logout", _source(request))
        if token:
            if token_type_hint not in ("", "refresh_token"):
                raise HTTPException(status_code=400, detail="unsupported_token_type")
            try:
                store.revoke_refresh_family(token)
            except OIDCStateUnavailableError:
                raise HTTPException(status_code=503, detail="currentness_unavailable")
            return {"revoked": True}
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing_bearer_token")
        payload = _decode_access_token(auth[len("Bearer ") :])
        _limit("logout", f"{_source(request)}:{payload['sub']}")
        try:
            revoked = store.revoke_access_token(payload["jti"])
        except OIDCStateUnavailableError:
            raise HTTPException(status_code=503, detail="currentness_unavailable")
        if not revoked:
            raise HTTPException(status_code=401, detail="token_not_current")
        return {"revoked": True}

    return router
