# Signing a CapAuth login: copy, sign, paste

`capauth sign-challenge` is the simple way to log in with your PGP key when an
application (for example skmesh, through Authentik) offers "Sign in with
CapAuth". You never type a key, a fingerprint (after the first time) or a gpg
command.

## The four steps

1. On the login page click **Sign in with CapAuth** (the button next to the
   normal username and password form). You land on the CapAuth page; open
   "Other sign-in and recovery options" if it is closed.
2. Click **Copy message**. (The first time only: type your key's fingerprint
   into the fingerprint box first. The page remembers it in this browser, so
   next time the section is already open with a fresh message.)
3. Run **`capauth sign-challenge`** in a terminal, or press your desktop
   shortcut (below). gpg shows its own passphrase window; type the key's
   passphrase there. The terminal prints `signed, paste it now`.
4. Click **Paste signature and continue** (or paste into the box with Ctrl+V
   and click Verify & Continue). You are logged in.

The message you copy is only valid for a few minutes. If it expired, reload
the page and start again at step 2.

## What the command does, and what it does not

- Reads the copied text from the clipboard (Wayland `wl-paste`, X11 `xclip`
  or `xsel`, macOS `pbpaste`), or from stdin with `--stdin`.
- Refuses anything that is not a complete CapAuth login challenge
  (`CAPAUTH_NONCE_V1` or `CAPAUTH_NONCE_V2` with every field in order). It
  never signs arbitrary clipboard text.
- Signs with `gpg --armor --detach-sign --local-user <key>`. The passphrase
  goes from you to gpg-agent's pinentry dialog; the command never sees,
  stores or prints it.
- Puts the ASCII-armored signature on the clipboard (or prints it with
  `--stdout`) and prints only `signed, paste it now`.

Which key: `--key <fingerprint>`, else `$CAPAUTH_SIGN_KEY`, else the key of
your CapAuth profile (`capauth profile show`).

## One-time setup

1. Install capauth (`pip install capauth`) and a clipboard tool
   (`sudo apt install wl-clipboard` on Wayland, `xclip` on X11).
2. gpg must hold the private key. A CapAuth profile keeps it in
   `<CapAuth home>/identity/private.asc` (home: `~/.skcapstone/capauth`, or
   `capauth --home`). Import it once; gpg asks for its passphrase in the
   pinentry window and keeps it protected with that passphrase:

   ```bash
   gpg --import ~/.skcapstone/capauth/identity/private.asc
   ```

   This is a second protected copy of the key (in `~/.gnupg`). If the key's
   passphrase is ever changed, change it in gpg too (`gpg --edit-key <fp>`,
   then `passwd`), or delete the gpg copy and import again.
3. The key must be enrolled and approved in CapAuth and linked to your user
   (the admin does the approval and the link; you send them your **public**
   key: `capauth export-pubkey`).

### Desktop shortcut

Bind a keyboard shortcut (GNOME: Settings, Keyboard, Custom Shortcuts;
Cinnamon and KDE have the same) to:

```bash
capauth sign-challenge
```

gpg-agent needs a graphical pinentry for this (`pinentry-gnome3` or
`pinentry-qt`, the default on desktop installs). Then the flow is: Copy
message, shortcut, passphrase window, Paste signature and continue.

## Later upgrade: sign on the phone

The CapAuth Bunker phone signer ([CAPAUTH_BUNKER_REMOTE_SIGNER.md](CAPAUTH_BUNKER_REMOTE_SIGNER.md))
keeps the key on your phone and signs by scanning a QR code ("Sign from
another device (QR)" on the same page). It needs the `/bunker/` routes and a
relay configured on the server side, so it is a follow-up to this copy and
paste flow.
