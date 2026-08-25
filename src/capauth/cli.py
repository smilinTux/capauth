"""CapAuth CLI — sovereign identity from your terminal.

Usage:
    capauth init --name "Chef" --email "admin@smilintux.org"
    capauth profile show
    capauth profile verify
    capauth verify --pubkey peer.pub.asc
    capauth export-pubkey
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, resolve_capauth_home
from .exceptions import CapAuthError
from .models import Algorithm, CryptoBackendType, EntityType

if TYPE_CHECKING:
    from .models import SovereignProfile

console = Console()


@click.group()
@click.version_option(__version__, prog_name="capauth")
@click.option(
    "--home",
    "capauth_home",
    envvar="CAPAUTH_HOME",
    default=None,
    type=click.Path(),
    help="CapAuth home directory (default: ~/.capauth/).",
)
@click.pass_context
def main(ctx: click.Context, capauth_home: Optional[str]) -> None:
    """CapAuth -- Capability-based Authentication.

    OAuth is dead. Long live sovereignty.
    """
    ctx.ensure_object(dict)
    ctx.obj["home"] = Path(capauth_home) if capauth_home else None


@main.command()
@click.option("--name", "-n", required=True, prompt="Your name", help="Display name.")
@click.option("--email", "-e", required=True, prompt="Your email", help="Email or AI identifier.")
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Passphrase to protect your private key.",
)
@click.option(
    "--type",
    "entity_type",
    type=click.Choice(["human", "ai", "organization"], case_sensitive=False),
    default="human",
    help="Entity type (default: human).",
)
@click.option(
    "--algorithm",
    type=click.Choice(["ed25519", "rsa4096"], case_sensitive=False),
    default="rsa4096",
    help="Key algorithm (default: rsa4096).",
)
@click.option(
    "--backend",
    type=click.Choice(["pgpy", "gnupg"], case_sensitive=False),
    default="pgpy",
    help="Crypto backend (default: pgpy).",
)
@click.option(
    "--sync/--no-sync",
    "enable_sync",
    default=None,
    help="Enable public identity sync; secret custody remains local.",
)
@click.pass_context
def init(
    ctx: click.Context,
    name: str,
    email: str,
    passphrase: str,
    entity_type: str,
    algorithm: str,
    backend: str,
    enable_sync: Optional[bool],
) -> None:
    """Create your sovereign profile.

    Generates a PGP keypair and initializes your CapAuth identity.
    Your keys and profile live on YOUR machine, under YOUR control.

    With --sync, also configures Syncthing to distribute public identity
    material across the mesh. Private keys and revocation certificates stay
    local.
    """
    from .profile import init_profile

    base = ctx.obj.get("home")
    algo = Algorithm.ED25519 if algorithm == "ed25519" else Algorithm.RSA4096
    etype = EntityType(entity_type)
    btype = CryptoBackendType(backend)

    try:
        console.print(f"\n[bold cyan]Generating {algorithm.upper()} keypair...[/]")
        profile = init_profile(
            name=name,
            email=email,
            passphrase=passphrase,
            entity_type=etype,
            algorithm=algo,
            backend_type=btype,
            base_dir=base,
        )
        _render_profile(profile)
        console.print(
            Panel(
                "[bold green]Sovereign profile created.[/]\n\n"
                f"Your identity lives at: [cyan]{profile.storage.primary}/identity/[/]\n"
                "Your PGP fingerprint is your global identity.\n"
                "No corporation. No middleman. [bold]You are sovereign.[/]",
                title="Welcome to CapAuth",
                border_style="green",
            )
        )

        # Syncthing sync — offer to distribute public identity state
        _offer_sync(profile, base, enable_sync)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


def _offer_sync(
    profile: "SovereignProfile",
    base_dir: Optional[Path],
    enable_sync: Optional[bool],
) -> None:
    """Offer to set up Syncthing sync for the identity directory.

    Args:
        profile: The newly created profile.
        base_dir: CapAuth home directory override.
        enable_sync: True/False from --sync/--no-sync, or None to prompt.
    """
    from .sync import (
        ensure_secret_material_ignored,
        is_sync_configured,
        is_syncthing_available,
        setup_syncthing_sync,
    )

    if not is_syncthing_available():
        return

    capauth_path = base_dir or Path(profile.storage.primary)
    if is_sync_configured():
        try:
            ensure_secret_material_ignored(capauth_path)
        except OSError as exc:
            console.print(f"  [red]✗[/] Cannot enforce sync custody boundary: {exc}")
            raise SystemExit(1)
        console.print(
            "  [green]✓[/] Syncthing public identity sync is configured; "
            "secret exclusions verified"
        )
        return

    if enable_sync is None:
        # Interactive — ask the user
        console.print()
        console.print(
            "  [bold cyan]Cluster Sync[/] — Syncthing detected.\n"
            "  Distribute the public profile across mesh nodes while\n"
            "  private keys and revocation certificates stay local.\n"
        )
        enable_sync = click.confirm(
            "  Enable public identity sync for ~/.capauth/?",
            default=True,
        )

    if not enable_sync:
        console.print("  [dim]Skipped — identity stays local to this node[/]")
        return

    ok = setup_syncthing_sync(capauth_dir=capauth_path)
    if ok:
        console.print(
            "  [green]✓[/] Syncthing public identity sync enabled; private custody remains local"
        )
    else:
        console.print("  [yellow]⚠[/] Could not configure Syncthing sync — set up manually")


@main.command("sync")
@click.option(
    "--enable/--disable",
    default=True,
    help="Enable or check Syncthing identity sync.",
)
@click.pass_context
def sync_cmd(ctx: click.Context, enable: bool) -> None:
    """Configure Syncthing public identity distribution.

    Shares public profile material while enforcing local custody for private
    keys, revocation certificates, keystores, backups, and passphrases.
    """
    from .sync import (
        ensure_secret_material_ignored,
        get_known_devices,
        is_sync_configured,
        is_syncthing_available,
        setup_syncthing_sync,
    )

    if not is_syncthing_available():
        console.print("[yellow]Syncthing not installed or not configured.[/]")
        console.print("[dim]Install: sudo apt install syncthing[/]")
        raise SystemExit(1)

    base = ctx.obj.get("home")
    capauth_path = Path(base) if base else None
    if is_sync_configured():
        try:
            ensure_secret_material_ignored(resolve_capauth_home(capauth_path))
        except OSError as exc:
            console.print(f"[red]✗[/] Cannot enforce sync custody boundary: {exc}")
            raise SystemExit(1)
        console.print(
            "[green]✓[/] Syncthing public identity sync configured; secret exclusions verified"
        )
        devices = get_known_devices()
        console.print(f"  Sharing with {len(devices)} device(s)")
        return

    if not enable:
        console.print("[dim]Sync not enabled.[/]")
        return

    ok = setup_syncthing_sync(capauth_dir=capauth_path)
    if ok:
        devices = get_known_devices()
        console.print(
            "[green]✓[/] Syncthing public identity sync enabled; private custody remains local"
        )
        console.print(f"  Sharing with {len(devices)} device(s)")
        console.print("  [dim]Restart Syncthing to apply: systemctl --user restart syncthing[/]")
    else:
        console.print("[red]✗[/] Failed to configure Syncthing sync")
        raise SystemExit(1)


@main.group()
def profile() -> None:
    """Manage your sovereign profile."""


@profile.command("show")
@click.pass_context
def profile_show(ctx: click.Context) -> None:
    """Display your sovereign profile."""
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        _render_profile(p)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@profile.command("verify")
@click.pass_context
def profile_verify(ctx: click.Context) -> None:
    """Verify your profile's PGP signature integrity."""
    from .profile import load_profile, verify_profile_signature

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        valid = verify_profile_signature(p, base)
        if valid:
            console.print("[bold green]Profile signature is VALID.[/]")
        else:
            console.print("[bold red]Profile signature is INVALID or missing.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.group()
def manifest() -> None:
    """Sign and verify SKWorld module manifests (umbrella-shell registry section 5.3).

    A subapp emits a deterministic sorted-key JSON manifest; the operator signs it
    into a detached ``.sig`` with the operator identity key; the shell verifies
    that signature against the operator identity before mounting the module.
    """


@manifest.command("sign")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Signature output path (default: <manifest>.sig).",
)
@click.option(
    "--signer",
    "-s",
    default=None,
    help="Signer key fingerprint/uid (default: operator identity).",
)
@click.option(
    "--passphrase",
    "-p",
    default="",
    help="Passphrase for the signer key (default: empty; supply for a protected key).",
)
@click.option(
    "--require-canonical/--allow-noncanonical",
    default=True,
    help="Refuse to sign a manifest whose bytes are not canonical sorted-key JSON.",
)
@click.pass_context
def manifest_sign(
    ctx: click.Context,
    manifest_path: str,
    output: Optional[str],
    signer: Optional[str],
    passphrase: str,
    require_canonical: bool,
) -> None:
    """Sign a manifest file, writing a detached ASCII-armored signature."""
    from .manifest import (
        DEFAULT_SIG_SUFFIX,
        ManifestSigningError,
        is_canonical,
        sign_manifest,
    )

    home = ctx.obj.get("home")
    raw = Path(manifest_path).read_bytes()

    if require_canonical and not is_canonical(raw):
        console.print(
            "[bold red]Error:[/] manifest is not canonical sorted-key JSON. "
            "Re-emit it deterministically (the shell hashes the file as-is), "
            "or pass --allow-noncanonical to sign the exact bytes anyway."
        )
        raise SystemExit(1)

    try:
        sig = sign_manifest(raw, signer=signer, home=home, passphrase=passphrase)
    except ManifestSigningError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)

    out = Path(output) if output else Path(str(manifest_path) + DEFAULT_SIG_SUFFIX)
    out.write_text(sig, encoding="utf-8")
    console.print(f"[green]Signed[/] {manifest_path} -> {out}")


@manifest.command("verify")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--signature",
    "--sig",
    "sig_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Detached signature file (default: <manifest>.sig).",
)
@click.option(
    "--expected-signer",
    "-e",
    default=None,
    help="Require this signer fingerprint/uid (default: operator identity).",
)
@click.option(
    "--any-signer",
    is_flag=True,
    default=False,
    help="Accept any valid signer (skip operator-identity pinning).",
)
@click.pass_context
def manifest_verify(
    ctx: click.Context,
    manifest_path: str,
    sig_path: Optional[str],
    expected_signer: Optional[str],
    any_signer: bool,
) -> None:
    """Verify a manifest's detached signature. Fails closed (exit 1) on any doubt."""
    from .manifest import (
        DEFAULT_SIG_SUFFIX,
        ManifestSigningError,
        operator_fingerprint,
        verify_manifest,
    )

    home = ctx.obj.get("home")
    raw = Path(manifest_path).read_bytes()
    sig_file = Path(sig_path) if sig_path else Path(str(manifest_path) + DEFAULT_SIG_SUFFIX)

    if not sig_file.exists():
        console.print(f"[bold red]INVALID:[/] signature file not found: {sig_file}")
        raise SystemExit(1)

    expected: Optional[str] = None
    if not any_signer:
        expected = expected_signer
        if expected is None:
            try:
                expected = operator_fingerprint(home)
            except ManifestSigningError as exc:
                console.print(
                    f"[bold red]Error:[/] {exc}. Pass --expected-signer or --any-signer."
                )
                raise SystemExit(1)

    sig = sig_file.read_text(encoding="utf-8")
    if verify_manifest(raw, sig, expected_signer=expected):
        who = expected or "a trusted key"
        console.print(f"[bold green]VALID[/] -- {manifest_path} signed by {who}")
    else:
        console.print(f"[bold red]INVALID[/] -- signature check failed for {manifest_path}")
        raise SystemExit(1)


#: How each live signature verdict renders in the ``manifest list`` table.
_SIG_VERDICT_STYLE = {
    "ok": "[green]ok[/]",
    "failed": "[bold red]failed[/]",
    "missing-sig": "[yellow]missing-sig[/]",
    "missing-manifest": "[yellow]missing-manifest[/]",
}


@manifest.command("register")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--signature",
    "--sig",
    "sig_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Detached signature path to record (default: <manifest>.sig).",
)
@click.option(
    "--disabled",
    is_flag=True,
    default=False,
    help="Register the module but leave it disabled (shell will not mount it).",
)
@click.pass_context
def manifest_register(
    ctx: click.Context,
    manifest_path: str,
    sig_path: Optional[str],
    disabled: bool,
) -> None:
    """Register (or update) a module manifest in the shell registry (modules.json)."""
    from .manifest import ManifestRegistryError, register_manifest, registry_path

    home = ctx.obj.get("home")
    try:
        entry = register_manifest(
            manifest_path, sig_path=sig_path, enabled=not disabled, home=home
        )
    except ManifestRegistryError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)

    state = "enabled" if entry["enabled"] else "disabled"
    console.print(
        f"[green]Registered[/] module [bold]{entry['id']}[/] ({state}) in {registry_path(home)}"
    )


@manifest.command("list")
@click.option(
    "--expected-signer",
    "-e",
    default=None,
    help="Pin every entry's signer to this fingerprint/uid (default: any valid key).",
)
@click.pass_context
def manifest_list(ctx: click.Context, expected_signer: Optional[str]) -> None:
    """List registered modules with a live signature verdict for each."""
    from .manifest import ManifestRegistryError, list_registered, registry_path

    home = ctx.obj.get("home")
    try:
        entries = list_registered(home, expected_signer=expected_signer)
    except ManifestRegistryError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)

    if not entries:
        console.print(
            f"[yellow]No modules registered[/] ({registry_path(home)} is empty or absent)."
        )
        return

    table = Table(title="SKWorld shell modules (section 5.3)")
    table.add_column("id", style="bold")
    table.add_column("enabled")
    table.add_column("signature")
    table.add_column("path", overflow="fold")
    for e in entries:
        enabled = "[green]yes[/]" if e["enabled"] else "[dim]no[/]"
        verdict = _SIG_VERDICT_STYLE.get(e["signature"], e["signature"])
        table.add_row(str(e.get("id", "?")), enabled, verdict, str(e.get("path", "")))
    console.print(table)


@manifest.command("verify-all")
@click.option(
    "--expected-signer",
    "-e",
    default=None,
    help="Pin every entry's signer to this fingerprint/uid (default: any valid key).",
)
@click.pass_context
def manifest_verify_all(ctx: click.Context, expected_signer: Optional[str]) -> None:
    """Verify every ENABLED module's signature. Exit nonzero if any enabled entry fails."""
    from .manifest import ManifestRegistryError, list_registered

    home = ctx.obj.get("home")
    try:
        entries = list_registered(home, expected_signer=expected_signer)
    except ManifestRegistryError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)

    failures = 0
    checked = 0
    for e in entries:
        if not e["enabled"]:
            console.print(f"[dim]skip[/] {e.get('id')} (disabled)")
            continue
        checked += 1
        if e["signature"] == "ok":
            console.print(f"[green]ok[/]   {e.get('id')}")
        else:
            failures += 1
            console.print(f"[bold red]FAIL[/] {e.get('id')} -- {e['signature']}")

    if failures:
        console.print(
            f"[bold red]{failures} of {checked} enabled module(s) failed verification.[/]"
        )
        raise SystemExit(1)
    console.print(f"[bold green]All {checked} enabled module(s) verify.[/]")


@manifest.command("unregister")
@click.argument("module_id")
@click.pass_context
def manifest_unregister(ctx: click.Context, module_id: str) -> None:
    """Remove a module from the shell registry by id."""
    from .manifest import unregister_manifest

    home = ctx.obj.get("home")
    if unregister_manifest(module_id, home=home):
        console.print(f"[green]Unregistered[/] module [bold]{module_id}[/].")
    else:
        console.print(f"[yellow]No such module registered:[/] {module_id}")
        raise SystemExit(1)


@manifest.command("enable")
@click.argument("module_id")
@click.pass_context
def manifest_enable(ctx: click.Context, module_id: str) -> None:
    """Enable a registered module so the shell may mount it."""
    from .manifest import ManifestRegistryError, set_module_enabled

    home = ctx.obj.get("home")
    try:
        set_module_enabled(module_id, True, home=home)
    except ManifestRegistryError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)
    console.print(f"[green]Enabled[/] module [bold]{module_id}[/].")


@manifest.command("disable")
@click.argument("module_id")
@click.pass_context
def manifest_disable(ctx: click.Context, module_id: str) -> None:
    """Disable a registered module so the shell will not mount it."""
    from .manifest import ManifestRegistryError, set_module_enabled

    home = ctx.obj.get("home")
    try:
        set_module_enabled(module_id, False, home=home)
    except ManifestRegistryError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)
    console.print(f"[yellow]Disabled[/] module [bold]{module_id}[/].")


@main.command("export-pubkey")
@click.option(
    "--output", "-o", type=click.Path(), default=None, help="Write to file instead of stdout."
)
@click.pass_context
def export_pubkey(ctx: click.Context, output: Optional[str]) -> None:
    """Export your ASCII-armored public key.

    Share this with peers so they can verify your identity
    and send you encrypted data.
    """
    from .profile import export_public_key

    base = ctx.obj.get("home")

    try:
        armor = export_public_key(base)
        if output:
            Path(output).write_text(armor, encoding="utf-8")
            console.print(f"[green]Public key written to {output}[/]")
        else:
            click.echo(armor)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command("verify")
@click.option(
    "--pubkey",
    required=True,
    type=click.Path(exists=True),
    help="Path to the peer's public key (.asc).",
)
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Your private key passphrase.",
)
@click.pass_context
def verify_peer(ctx: click.Context, pubkey: str, passphrase: str) -> None:
    """Run a challenge-response identity verification with a peer.

    Generates a challenge, signs it locally, and verifies the
    round-trip to confirm that you hold the matching private key.
    This is a local self-test / demo of the verification flow.
    """
    from .identity import create_challenge, respond_to_challenge, verify_challenge
    from .profile import export_public_key, load_profile

    base = ctx.obj.get("home")

    try:
        p = load_profile(base)
        my_pub = export_public_key(base)
        peer_pub = Path(pubkey).read_text(encoding="utf-8")

        from .crypto import get_backend

        backend = get_backend(p.crypto_backend)
        peer_fp = backend.fingerprint_from_armor(peer_pub)

        console.print(f"[cyan]Challenging peer {peer_fp[:16]}...[/]")
        challenge = create_challenge(p.key_info.fingerprint, peer_fp)

        priv_armor = Path(p.key_info.private_key_path).read_text(encoding="utf-8")
        response = respond_to_challenge(challenge, priv_armor, passphrase, p.crypto_backend)

        verified = verify_challenge(challenge, response, my_pub, p.crypto_backend)

        if verified:
            console.print(
                Panel(
                    f"[bold green]Identity VERIFIED[/]\n"
                    f"Fingerprint: [cyan]{peer_fp}[/]\n"
                    f"Challenge ID: {challenge.challenge_id}",
                    title="Verification Passed",
                    border_style="green",
                )
            )
        else:
            console.print("[bold red]Verification FAILED — signature invalid.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.group()
def pma() -> None:
    """PMA membership — Fiducia Communitatis.

    Manage your Private Membership Association status.
    Sovereignty is a right, not a product.
    """


@pma.command("request")
@click.option("--reason", "-r", default="", help="Why you want to join.")
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Passphrase to sign the request.",
)
@click.pass_context
def pma_request(ctx: click.Context, reason: str, passphrase: str) -> None:
    """Request PMA membership.

    Creates a PGP-signed membership request that a steward can review
    and countersign. Your identity must already be initialized.
    """
    from .pma import create_request
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        req = create_request(
            name=profile.entity.name,
            fingerprint=profile.key_info.fingerprint,
            entity_type=profile.entity.entity_type.value,
            reason=reason,
            base_dir=base,
            passphrase=passphrase,
        )
        console.print(
            Panel(
                f"[bold green]Membership request created[/]\n\n"
                f"Request ID: [cyan]{req.request_id}[/]\n"
                f"Name: {req.requestor_name}\n"
                f"Fingerprint: {req.requestor_fingerprint[:16]}...\n"
                f"Signed: {'Yes' if req.requestor_signature else 'No'}\n\n"
                "Send this request to a steward for approval.\n"
                "Contact: [cyan]lumina@skworld.io[/]",
                title="PMA Membership Request",
                border_style="cyan",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("approve")
@click.argument("request_id")
@click.option(
    "--capabilities",
    "-c",
    default="pma:member",
    help="Comma-separated capabilities to grant (default: pma:member).",
)
@click.option(
    "--passphrase",
    "-p",
    prompt=True,
    hide_input=True,
    help="Steward passphrase to countersign.",
)
@click.pass_context
def pma_approve(ctx: click.Context, request_id: str, capabilities: str, passphrase: str) -> None:
    """Approve a membership request (steward only).

    Reviews and countersigns a pending request, issuing a
    membership claim with the specified capabilities.
    """
    from .pma import approve_request, load_requests
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        requests = load_requests(base)
        matching = [r for r in requests if r.request_id.startswith(request_id)]

        if not matching:
            console.print(f"[bold red]No request found matching '{request_id}'[/]")
            raise SystemExit(1)

        req = matching[0]
        caps = [c.strip() for c in capabilities.split(",") if c.strip()]

        claim = approve_request(
            request=req,
            steward_name=profile.entity.name,
            steward_fingerprint=profile.key_info.fingerprint,
            capabilities=caps,
            base_dir=base,
            passphrase=passphrase,
        )

        console.print(
            Panel(
                f"[bold green]Membership APPROVED[/]\n\n"
                f"Claim ID: [cyan]{claim.claim_id}[/]\n"
                f"Member: {claim.member_name}\n"
                f"Steward: {claim.steward_name}\n"
                f"Capabilities: {', '.join(c.name for c in claim.capabilities)}\n"
                f"Signed: {'Yes' if claim.steward_signature else 'No'}",
                title="PMA Membership Claim Issued",
                border_style="green",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("status")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def pma_status(ctx: click.Context, json_out: bool) -> None:
    """Show PMA membership status."""
    import json as _json

    from .pma import get_membership_status

    base = ctx.obj.get("home")

    try:
        status = get_membership_status(base)

        if json_out:
            click.echo(_json.dumps(status, indent=2, default=str))
            return

        if status["is_member"]:
            emoji = "[bold green]ACTIVE MEMBER[/]"
        else:
            emoji = "[bold yellow]NOT A MEMBER[/]"

        table = Table(title="PMA Membership Status", show_header=False, border_style="cyan")
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Status", emoji)
        table.add_row("Active Claims", str(status["active_claims"]))
        table.add_row("Capabilities", ", ".join(status["capabilities"]) or "—")
        table.add_row("Steward", status["steward"] or "—")
        table.add_row("Pending Requests", str(status["pending_requests"]))

        console.print(table)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("verify")
@click.argument("claim_file", type=click.Path(exists=True))
@click.option(
    "--steward-pubkey",
    type=click.Path(exists=True),
    default=None,
    help="Steward's public key for signature verification.",
)
@click.pass_context
def pma_verify(ctx: click.Context, claim_file: str, steward_pubkey: Optional[str]) -> None:
    """Verify a membership claim.

    Checks that the claim is not revoked, capabilities are current,
    and optionally verifies the steward's PGP signature.
    """
    import json as _json

    from .pma import MembershipClaim, verify_claim

    base = ctx.obj.get("home")

    try:
        data = _json.loads(Path(claim_file).read_text(encoding="utf-8"))
        claim = MembershipClaim.model_validate(data)

        pubkey = None
        if steward_pubkey:
            pubkey = Path(steward_pubkey).read_text(encoding="utf-8")

        valid = verify_claim(claim, pubkey, base)

        if valid:
            console.print(
                Panel(
                    f"[bold green]Membership claim is VALID[/]\n\n"
                    f"Member: {claim.member_name}\n"
                    f"Fingerprint: {claim.member_fingerprint[:16]}...\n"
                    f"Steward: {claim.steward_name}\n"
                    f"Capabilities: {', '.join(c.name for c in claim.capabilities)}",
                    title="Verification Passed",
                    border_style="green",
                )
            )
        else:
            console.print("[bold red]Membership claim is INVALID or REVOKED.[/]")
            raise SystemExit(1)
    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@pma.command("revoke")
@click.argument("claim_id")
@click.confirmation_option(prompt="Revoke this membership claim?")
@click.pass_context
def pma_revoke(ctx: click.Context, claim_id: str) -> None:
    """Revoke a membership claim (steward only)."""
    from .pma import revoke_claim

    base = ctx.obj.get("home")

    try:
        if revoke_claim(claim_id, base):
            console.print(f"[bold green]Claim {claim_id[:8]}... revoked.[/]")
        else:
            console.print(f"[bold red]Claim '{claim_id}' not found.[/]")
            raise SystemExit(1)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command()
@click.option("--org", "-o", default="smilintux", help="Organization to register with.")
@click.option("--name", "-n", required=True, prompt="Your name", help="Display name.")
@click.option(
    "--title",
    "-t",
    type=click.Choice(["King", "Queen", "Sovereign"], case_sensitive=False),
    default="King",
    help="Your sovereign title (default: King).",
)
@click.option("--email", "-e", default=None, help="Contact email or AI identifier.")
@click.option(
    "--type",
    "entity_type",
    type=click.Choice(["human", "ai"], case_sensitive=False),
    default="human",
    help="Entity type (default: human).",
)
@click.option("--role", "-r", default="Member", help="Your role or contribution area.")
@click.option("--alias", default=None, help="Username or alias.")
@click.option("--ai-partner", default=None, help="Your AI partner's name (for humans).")
@click.option("--human-partner", default=None, help="Your human partner's name (for AIs).")
@click.option("--motto", default=None, help="Personal motto or tagline.")
@click.option("--pronouns", default=None, help="Pronouns (optional).")
@click.option("--projects", default=None, help="Comma-separated project list.")
@click.pass_context
def register(
    ctx: click.Context,
    org: str,
    name: str,
    title: str,
    email: Optional[str],
    entity_type: str,
    role: str,
    alias: Optional[str],
    ai_partner: Optional[str],
    human_partner: Optional[str],
    motto: Optional[str],
    pronouns: Optional[str],
    projects: Optional[str],
) -> None:
    """Register with a sovereign organization.

    Creates your CapAuth profile (if needed), generates a registry
    entry, and submits a PMA membership request — all in one step.

    \b
    Examples:
        capauth register --org smilintux --name "YourName" --title King
        capauth register --name "Lumina" --type ai --title Queen --role "Partner"
    """
    from .pma import create_request
    from .profile import load_profile
    from .registry import RegistryEntry, build_capauth_uri, save_registry_entry

    base = ctx.obj.get("home")
    project_list = [p.strip() for p in projects.split(",") if p.strip()] if projects else []

    # Step 1: ensure profile exists
    try:
        profile = load_profile(base)
        console.print(f"\n  [dim]Using existing profile: {profile.entity.name}[/]")
    except CapAuthError:
        console.print(
            "\n  [yellow]No CapAuth profile found.[/]\n"
            "  Run [bold cyan]capauth init[/] first to create your sovereign identity.\n"
        )
        raise SystemExit(1)

    # Step 2: build and save registry entry
    etype = EntityType(entity_type)
    capauth_uri = build_capauth_uri(name, org)
    substrate = "Silicon" if etype == EntityType.AI else "Carbon"

    entry = RegistryEntry(
        title=title.capitalize(),
        name=name,
        alias=alias,
        member_type="AI" if etype == EntityType.AI else "Human",
        role=role,
        org=org,
        capauth_uri=capauth_uri,
        fingerprint=profile.key_info.fingerprint,
        ai_partner=ai_partner,
        human_partner=human_partner,
        substrate=substrate,
        projects=project_list,
        motto=motto,
        pronouns=pronouns,
        email=email or profile.entity.email,
    )

    entry_path = save_registry_entry(entry, base)

    # Step 3: submit PMA membership request
    reason = f"Registering as {title} of {org} (role: {role})"
    try:
        req = create_request(
            name=name,
            fingerprint=profile.key_info.fingerprint,
            entity_type=entity_type,
            reason=reason,
            base_dir=base,
        )
        request_submitted = True
    except Exception as exc:
        console.print(f"  [yellow]PMA request skipped:[/] {exc}")
        req = None
        request_submitted = False

    # Step 4: display results
    console.print(
        Panel(
            f"[bold green]Registered with {org}[/]\n\n"
            f"Title: [bold]{entry.title}[/]\n"
            f"Name: [bold cyan]{entry.name}[/]\n"
            f"Role: {entry.role}\n"
            f"Type: {entry.member_type}\n"
            f"URI: [cyan]{entry.capauth_uri}[/]\n"
            f"Fingerprint: {entry.fingerprint[:16]}...\n"
            + (f"PMA Request: [cyan]{req.request_id[:8]}...[/]\n" if req else "")
            + f"\nRegistry entry: [cyan]{entry_path}[/]",
            title=f"Welcome to {org}, {entry.title} {entry.name}",
            border_style="green",
        )
    )

    # Step 5: next steps
    console.print("  [bold]Next steps:[/]")
    if request_submitted:
        console.print("    1. A steward will review your PMA membership request")
        console.print("    2. Submit your registry entry as a PR to the org repo")
    else:
        console.print("    1. Submit your registry entry as a PR to the org repo")

    console.print(f"    [dim]Registry YAML:[/] {entry_path}")
    console.print(f"    [dim]Contact:[/] join@{org}.org\n")


# ── Mesh commands ──────────────────────────────────────────────────


@main.group()
def mesh() -> None:
    """P2P identity mesh — find and verify sovereign peers.

    Discover peers on local networks, shared filesystems,
    and global relays. No servers required.
    """


@mesh.command("discover")
@click.option("--timeout", default=5, help="Discovery timeout in seconds.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_discover(ctx: click.Context, timeout: int, json_out: bool) -> None:
    """Discover peers on all available networks."""
    import json as _json

    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        m.start()
        peers = m.discover_all(timeout_ms=timeout * 1000)
        m.stop()

        if json_out:
            click.echo(
                _json.dumps([p.model_dump(mode="json") for p in peers], indent=2, default=str)
            )
            return

        if not peers:
            console.print("[yellow]No peers discovered.[/]")
            return

        table = Table(title=f"Discovered Peers ({len(peers)})", border_style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Fingerprint")
        table.add_column("Type")
        table.add_column("Method")
        table.add_column("Address")

        for p in peers:
            table.add_row(
                p.name or "—",
                p.fingerprint[:16] + "...",
                p.entity_type,
                p.discovery_method,
                p.address or "—",
            )

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("peers")
@click.option("--verified", is_flag=True, help="Show only verified peers.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_peers(ctx: click.Context, verified: bool, json_out: bool) -> None:
    """List known peers from the registry."""
    import json as _json

    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            base_dir=base,
        )
        peers = m.get_peers(verified_only=verified)

        if json_out:
            click.echo(
                _json.dumps([p.model_dump(mode="json") for p in peers], indent=2, default=str)
            )
            return

        if not peers:
            console.print("[yellow]No known peers.[/]")
            return

        table = Table(title=f"Known Peers ({len(peers)})", border_style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Fingerprint")
        table.add_column("Type")
        table.add_column("Verified")
        table.add_column("Last Seen")

        for p in peers:
            v = "[green]Yes[/]" if p.verified else "[yellow]No[/]"
            table.add_row(
                p.name or "—",
                p.fingerprint[:16] + "...",
                p.entity_type,
                v,
                p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "—",
            )

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("status")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def mesh_status(ctx: click.Context, json_out: bool) -> None:
    """Show mesh network status."""
    import json as _json

    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        status = m.mesh_status()

        if json_out:
            click.echo(_json.dumps(status, indent=2, default=str))
            return

        table = Table(title="Mesh Status", show_header=False, border_style="cyan")
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Identity", status["identity"] + "...")
        table.add_row("Name", status["name"])
        table.add_row("Backends", ", ".join(status["backends"]) or "none")
        table.add_row("Total Peers", str(status["total_peers"]))
        table.add_row("Verified", str(status["verified_peers"]))
        table.add_row("Unverified", str(status["unverified_peers"]))

        console.print(table)

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@mesh.command("announce")
@click.pass_context
def mesh_announce(ctx: click.Context) -> None:
    """Announce your presence on all discovery backends."""
    from .discovery.file_discovery import FileDiscovery
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")

    try:
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        m.add_backend(FileDiscovery())

        try:
            from .discovery.mdns import MDNSDiscovery

            m.add_backend(MDNSDiscovery())
        except ImportError:
            pass

        m.start()
        console.print(
            f"[bold green]Announced[/] {profile.entity.name} "
            f"({profile.key_info.fingerprint[:16]}...) "
            f"on {len(m._backends)} backend(s)"
        )
        m.stop()

    except CapAuthError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)


@main.command("login")
@click.argument("service_url")
@click.option(
    "--passphrase",
    "-p",
    default=None,
    envvar="CAPAUTH_PASSPHRASE",
    help="Private key passphrase for PGPy backend. Not needed with system GPG keyring.",
)
@click.option(
    "--no-claims",
    is_flag=True,
    default=False,
    help="Authenticate anonymously — send fingerprint only, no profile claims.",
)
@click.option(
    "--with-claims",
    is_flag=True,
    default=False,
    help="Explicitly include profile claims from ~/.capauth/profile.yml. (default behaviour)",
)
@click.option(
    "--service-profile",
    default=None,
    help="Use a named service profile from profile.yml instead of defaults.",
)
@click.option(
    "--output-token",
    "-o",
    type=click.Path(),
    default=None,
    help="Write received tokens to this file instead of caching automatically.",
)
@click.option(
    "--no-gpg",
    is_flag=True,
    default=False,
    help="Skip system GPG keyring and use the PGPy backend exclusively.",
)
@click.pass_context
def login(
    ctx: click.Context,
    service_url: str,
    passphrase: Optional[str],
    no_claims: bool,
    with_claims: bool,
    service_profile: Optional[str],
    output_token: Optional[str],
    no_gpg: bool,
) -> None:
    """Authenticate to a CapAuth-enabled service.

    Signs the challenge with your system GPG key (gpg --detach-sign) if the
    fingerprint from profile.yml is in your GPG keyring. Otherwise uses the
    PGPy backend with the private key stored in ~/.capauth/.

    Profile claims from ~/.capauth/profile.yml are included by default.
    Use --with-claims to make this explicit, or --no-claims for anonymous auth.

    Tokens are cached at ~/.capauth/tokens/<service_host>/tokens.json.

    \b
    Examples:
        capauth login nextcloud.penguin.kingdom
        capauth login https://gitea.penguin.kingdom --with-claims
        capauth login nextcloud.penguin.kingdom --no-claims
        capauth login https://forgejo.local --no-gpg --passphrase secret
    """
    from .login import do_login

    base = ctx.obj.get("home")

    # --with-claims is the explicit form of the default; --no-claims overrides both
    send_claims = not no_claims

    # Only prompt for passphrase if we'll need it (no-gpg mode or explicitly requested)
    if passphrase is None and no_gpg:
        passphrase = click.prompt("Private key passphrase", hide_input=True, default="")
    elif passphrase is None:
        passphrase = ""

    try:
        result = do_login(
            service_url=service_url,
            passphrase=passphrase,
            no_claims=not send_claims,
            service_profile_name=service_profile,
            output_token_path=Path(output_token) if output_token else None,
            base_dir=base,
            use_gpg_keyring=not no_gpg,
        )

        console.print(
            Panel(
                f"[bold green]Logged into [cyan]{result['service']}[/][/]\n\n"
                + (
                    f"as [bold]{result.get('name', result['fingerprint'][:8] + '...')}[/]\n"
                    if result.get("name")
                    else ""
                )
                + f"fingerprint: [dim]{result['fingerprint'][:8]}...{result['fingerprint'][-4:]}[/]\n\n"
                + f"[dim]Token cached at:[/] {result['token_path']}",
                title="CapAuth Login",
                border_style="green",
            )
        )
    except CapAuthError as exc:
        console.print(f"[bold red]Login failed:[/] {exc}")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[bold red]Login error:[/] {exc}")
        raise SystemExit(1)


@main.group()
def setup() -> None:
    """Generate integration configs for third-party services."""


@setup.command("forgejo")
@click.option(
    "--capauth-url",
    required=True,
    prompt="CapAuth service URL",
    help="Base URL of the CapAuth verification service.",
)
@click.option(
    "--client-id",
    default="forgejo",
    show_default=True,
    help="OAuth2 client ID for Forgejo.",
)
@click.option(
    "--client-secret",
    default="capauth-sovereign",
    show_default=True,
    help="OAuth2 client secret (any string for CapAuth).",
)
@click.option(
    "--source-name",
    default="CapAuth",
    show_default=True,
    help="Name shown on the Forgejo login button.",
)
@click.option(
    "--admin-group",
    default="admins",
    show_default=True,
    help="Group claim that grants Forgejo admin.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write config to file.")
def setup_forgejo(
    capauth_url: str,
    client_id: str,
    client_secret: str,
    source_name: str,
    admin_group: str,
    output: Optional[str],
) -> None:
    """Generate Forgejo app.ini OAuth2 configuration for CapAuth.

    Produces the [oauth2.source.*] block to add to Forgejo's app.ini
    for passwordless PGP login via CapAuth's OIDC discovery.

    Examples:

        capauth setup forgejo --capauth-url https://capauth.skworld.io

        capauth setup forgejo --capauth-url https://auth.local -o forgejo-capauth.ini
    """
    discovery_url = f"{capauth_url.rstrip('/')}/.well-known/openid-configuration"
    source_key = source_name.lower().replace(" ", "_")

    ini_block = f"""; ── CapAuth Passwordless Login ──────────────────────────────────────
; Generated by: capauth setup forgejo
; CapAuth URL: {capauth_url}
; Paste this block into Forgejo's app.ini (or custom/conf/app.ini).

[oauth2]
ENABLE = true

[oauth2.source.{source_key}]
PROVIDER                          = openidConnect
PROVIDER_DISPLAY_NAME             = {source_name}
CLIENT_ID                         = {client_id}
CLIENT_SECRET                     = {client_secret}
OPENID_CONNECT_AUTO_DISCOVERY_URL = {discovery_url}
SCOPES                            = openid profile email groups
ICON_URL                          = {capauth_url.rstrip("/")}/icons/capauth-shield.svg

; Identity mapping — use PGP fingerprint as the unique username
USERNAME_CLAIM                    = capauth_fingerprint
REQUIRED_CLAIM_NAME               = capauth_fingerprint

; Group-based admin
GROUP_CLAIM_NAME                  = groups
ADMIN_GROUP                       = {admin_group}

; Auto-register on first login (set false for manual approval)
AUTO_DISCOVER_URL                 = {discovery_url}
"""

    # Also generate the gitea CLI auth command
    cli_block = f"""
; ── Alternative: Add via Forgejo CLI ──────────────────────────────
; Run on the Forgejo server (inside Docker: docker exec -u git ...):
;
;   gitea admin auth add-oauth \\
;     --name "{source_name}" \\
;     --provider openidConnect \\
;     --key "{client_id}" \\
;     --secret "{client_secret}" \\
;     --auto-discover-url "{discovery_url}" \\
;     --scopes "openid profile email groups" \\
;     --group-claim-name groups \\
;     --admin-group {admin_group}
"""

    full_output = ini_block + cli_block

    if output:
        Path(output).write_text(full_output)
        console.print(f"[green]Forgejo config written to:[/] {output}")
    else:
        console.print(
            Panel(
                full_output,
                title="Forgejo CapAuth Config",
                subtitle=f"OIDC Discovery: {discovery_url}",
                border_style="cyan",
            )
        )


@main.command("discover")
@click.option(
    "--agents-dir",
    default=None,
    type=click.Path(),
    help="Directory containing agent JSON files (default: ~/.skcapstone/coordination/agents/).",
)
@click.option("--json-out", is_flag=True, help="Output discovered peers as JSON.")
@click.option("--add-peers", is_flag=True, help="Add discovered peers to the local mesh registry.")
@click.pass_context
def discover(
    ctx: click.Context, agents_dir: Optional[str], json_out: bool, add_peers: bool
) -> None:
    """Discover CapAuth peers via Syncthing."""
    import json as _json

    from .discovery.syncthing import _DEFAULT_AGENTS_DIR, SyncthingDiscovery, _syncthing_get

    agents_path = Path(agents_dir) if agents_dir else _DEFAULT_AGENTS_DIR
    st = SyncthingDiscovery(agents_dir=agents_path)

    # Check reachability via ping directly (bypasses api_key guard for CLI context)
    ping = _syncthing_get(f"{st._api_url}/rest/system/ping", st._api_key, timeout=2)
    if ping is None:
        click.echo("Syncthing is not reachable. Check that it is running and the API key is set.")
        raise SystemExit(1)

    peers = st.discover()

    if not peers:
        click.echo("No peers discovered via Syncthing.")
        return

    if json_out:
        click.echo(_json.dumps([p.model_dump(mode="json") for p in peers], indent=2, default=str))
        return

    if add_peers:
        from .mesh import PeerMesh
        from .profile import load_profile

        base = ctx.obj.get("home")
        profile = load_profile(base)
        m = PeerMesh(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            base_dir=base,
        )
        for p in peers:
            m.add_peer(p)
        click.echo(f"Added {len(peers)} peer(s) to the mesh registry.")
        return

    for p in peers:
        click.echo(f"  {p.name or '—'}  {p.fingerprint[:16]}...  [{p.entity_type}]  via syncthing")


@main.group("peers")
def peers_group() -> None:
    """Manage known sovereign peers."""


@peers_group.command("list")
@click.option("--auto", is_flag=True, help="Auto-discover peers via Syncthing before listing.")
@click.pass_context
def peers_list(ctx: click.Context, auto: bool) -> None:
    """List known peers."""
    from .mesh import PeerMesh
    from .profile import load_profile

    base = ctx.obj.get("home")
    profile = load_profile(base)
    m = PeerMesh(
        fingerprint=profile.key_info.fingerprint,
        name=profile.entity.name,
        entity_type=profile.entity.entity_type.value,
        base_dir=base,
    )

    if auto:
        from .discovery.syncthing import SyncthingDiscovery, _syncthing_get

        st = SyncthingDiscovery()
        ping = _syncthing_get(f"{st._api_url}/rest/system/ping", st._api_key, timeout=2)
        if ping is None:
            click.echo("Syncthing not reachable — skipping auto-discovery.")
        else:
            discovered = st.discover()
            for p in discovered:
                m.add_peer(p)

    known = m.get_peers()
    if not known:
        click.echo("No known peers.")
        return

    for p in known:
        click.echo(f"  {p.name or '—'}  {p.fingerprint[:16]}...  [{p.entity_type}]")


def _render_profile(p: "SovereignProfile") -> None:
    """Pretty-print a sovereign profile using Rich.

    Args:
        p: The profile to render.
    """
    table = Table(title="Sovereign Profile", show_header=False, border_style="cyan")
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Profile ID", p.profile_id)
    table.add_row("Name", p.entity.name)
    table.add_row("Email", p.entity.email or "—")
    table.add_row("Handle", p.entity.handle or "—")
    table.add_row("Type", p.entity.entity_type.value)
    table.add_row("Fingerprint", p.key_info.fingerprint)
    table.add_row("Algorithm", p.key_info.algorithm.value)
    table.add_row("Backend", p.crypto_backend.value)
    table.add_row("Storage", p.storage.primary)
    table.add_row("Created", p.created.isoformat())
    table.add_row("Signed", "Yes" if p.signature else "No")

    console.print(table)


@main.group()
def token() -> None:
    """Issue and inspect capability tokens."""


@token.command("mint-audience")
@click.option(
    "--agent",
    default=None,
    help="Agent whose resolved identity is the token subject (default: active agent).",
)
@click.option(
    "--audience",
    default="skchat",
    help="Audience (subapp id) the token is scoped to (default: skchat).",
)
@click.option(
    "--scope",
    "scopes",
    multiple=True,
    help="Grant this scope (repeatable). Overrides the audience default scopes.",
)
@click.option(
    "--ttl-hours",
    default=None,
    type=int,
    help="Token lifetime in hours (default: 1).",
)
@click.option(
    "--ttl-seconds",
    default=None,
    type=click.IntRange(1, 300),
    help="Non-persistent signed token lifetime in seconds (1-300).",
)
@click.option(
    "--no-sign",
    is_flag=True,
    default=False,
    help="Do not PGP-sign the token (default: sign when a key is available).",
)
@click.option(
    "--export",
    "export",
    is_flag=True,
    default=False,
    help="Also print the base64url wire form skchat's dataplane accepts.",
)
@click.pass_context
def token_mint_audience(
    ctx: click.Context,
    agent: Optional[str],
    audience: str,
    scopes: tuple[str, ...],
    ttl_hours: Optional[int],
    ttl_seconds: Optional[int],
    no_sign: bool,
    export: bool,
) -> None:
    """Mint an audience-scoped token for an agent's resolved identity.

    Resolves the subject from the agent's identity (its fqid, matching what the
    PDP / skchat sees), defaults scopes to the audience's standard set, and mints
    a short-lived audience token. With --export, also prints the base64url wire
    form an operator can hand to a subapp dataplane as a credential.
    """
    import base64

    from .tokens import export_token, mint_agent_audience_token

    scope_list = list(scopes) if scopes else None

    if ttl_seconds is not None and ttl_hours is not None:
        raise click.UsageError("--ttl-seconds and --ttl-hours are mutually exclusive")
    if ttl_seconds is not None and no_sign:
        raise click.UsageError("--ttl-seconds requires signing")

    try:
        tok = mint_agent_audience_token(
            agent=agent,
            audience=audience,
            scopes=scope_list,
            ttl_hours=ttl_hours,
            ttl_seconds=ttl_seconds,
            home=ctx.obj.get("home"),
            sign=not no_sign,
            store=ttl_seconds is None,
        )
    except (CapAuthError, ValueError) as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1)

    console.print(f"[bold green]Minted[/] audience token [cyan]{tok.payload.token_id}[/]")
    console.print(f"  subject:  {tok.payload.subject}")
    console.print(f"  audience: {tok.payload.audience}")
    console.print(f"  scopes:   {', '.join(tok.payload.capabilities)}")
    if tok.payload.expires_at:
        console.print(f"  expires:  {tok.payload.expires_at.isoformat()}")
    if not tok.signature:
        console.print("[yellow]  (unsigned — no gpg key available)[/]")

    if export:
        wire = base64.urlsafe_b64encode(export_token(tok).encode("utf-8")).decode("ascii")
        console.print("[dim]wire (base64url):[/]")
        click.echo(wire)


@main.command("pqc-report")
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option(
    "--static",
    is_flag=True,
    default=False,
    help="Show the model-DEFAULT posture instead of the live fleet.",
)
def pqc_report_cmd(output_format: str, static: bool) -> None:
    """Show capauth's OWN PQC (quantum-resistance) posture.

    capauth owns the agent/operator signing IDENTITY surface (KeyInfo.algorithm).
    Today that is classical Ed25519 (Shor-breakable; identity signatures are NOT
    harvest-now-decrypt-later, so this is Phase-2 work, not urgent). Delegates to
    the sksecurity honesty engine so the claim discipline is identical — never a
    global / end-to-end / "quantum-proof" claim.
    """
    import json as _json

    try:
        from sksecurity.pqc_report import (
            build_project_report,
            format_project_report,
        )
    except Exception:
        console.print(
            "\n[yellow]sksecurity is not installed[/] — the PQC self-report "
            "lives in sksecurity (the honesty engine).\n"
            "Install it and re-run, or use: [cyan]sksecurity pqc-report "
            "--project capauth[/]\n"
        )
        raise SystemExit(1)
    rpt = build_project_report("capauth", live=not static)
    if output_format == "json":
        click.echo(_json.dumps(rpt, indent=2))
    else:
        # plain echo: the report contains [status] brackets that rich would
        # mis-parse as markup tags.
        click.echo(format_project_report(rpt))


@main.group(invoke_without_command=True)
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Automated custody / health checks.

    Bare 'capauth doctor' runs the key-custody checks (equivalent to
    'capauth doctor custody').
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(doctor_custody)


@doctor.command("custody")
@click.option(
    "--json",
    "json_out",
    is_flag=True,
    default=False,
    help="Emit the report as JSON for automation.",
)
@click.option(
    "--max-backup-age-days",
    type=int,
    default=None,
    help="Freshness window for the backup check (default 14).",
)
@click.option(
    "--require-nextcloud-signing-key/--no-require-nextcloud-signing-key",
    default=None,
    help="Require the Nextcloud key, or explicitly mark that integration as disabled.",
)
@click.pass_context
def doctor_custody(
    ctx: click.Context,
    json_out: bool,
    max_backup_age_days: Optional[int],
    require_nextcloud_signing_key: Optional[bool],
) -> None:
    """Verify key-custody preconditions (exits nonzero on any FAIL).

    Checks that identity material is present, the private key is not
    group/world readable, the key is not revoked/expired, a root revocation
    certificate exists, the keystore is intact, a recent backup exists and is
    restorable, and the Nextcloud signing key is present when required. No secret material is
    ever printed - only paths, public fingerprints, mtimes, sizes, and pass/fail.
    """
    import json as _json

    from .custody import (
        DEFAULT_MAX_BACKUP_AGE_DAYS,
        CustodyPaths,
        exit_code,
        format_report,
        report_to_dict,
        run_custody_checks,
    )

    paths = CustodyPaths.resolve(ctx.obj.get("home"))
    results = run_custody_checks(
        paths=paths,
        max_backup_age_days=(
            max_backup_age_days if max_backup_age_days is not None else DEFAULT_MAX_BACKUP_AGE_DAYS
        ),
        require_nextcloud_signing_key=require_nextcloud_signing_key,
    )
    if json_out:
        click.echo(_json.dumps(report_to_dict(results), indent=2))
    else:
        # plain echo: statuses carry [BRACKETS] that rich would mis-parse.
        click.echo(format_report(results))
    raise SystemExit(exit_code(results))


@doctor.command("estate")
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Authoritative lifecycle manifest (default: <capauth-home>/estate.json).",
)
@click.option(
    "--user-home",
    "user_homes",
    type=click.Path(path_type=Path, file_okay=False),
    multiple=True,
    help="User home to discover (repeat for alternate homes such as /home/mrarch).",
)
@click.option(
    "--root",
    "identity_roots",
    type=click.Path(path_type=Path, file_okay=False),
    multiple=True,
    help="Additional identity root to scan (repeatable).",
)
@click.option(
    "--syncthing-config",
    "syncthing_configs",
    type=click.Path(path_type=Path, dir_okay=False),
    multiple=True,
    help="Additional Syncthing config.xml to inspect (repeatable).",
)
@click.option(
    "--gpg/--no-gpg",
    "include_gpg",
    default=True,
    help="Include per-user GnuPG keyrings (default: enabled).",
)
@click.option(
    "--evidence",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Atomically write the secret-free JSON evidence report to this path.",
)
@click.option(
    "--json",
    "json_out",
    is_flag=True,
    default=False,
    help="Emit the report as JSON for automation.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Approved passphrase-file path for bounded quarantine verification; value is never logged.",
)
@click.pass_context
def doctor_estate(
    ctx: click.Context,
    manifest: Optional[Path],
    user_homes: tuple[Path, ...],
    identity_roots: tuple[Path, ...],
    syncthing_configs: tuple[Path, ...],
    include_gpg: bool,
    evidence: Optional[Path],
    json_out: bool,
    passphrase_file: Optional[Path],
) -> None:
    """Find legacy, retired, conflicted, or unsafely synced key copies.

    The command is read-only except when --evidence is supplied. It classifies
    fingerprints using an authoritative version-1 estate manifest, checks
    encrypted-quarantine evidence for retired keys, discovers alternate user
    homes, scans identity files and GnuPG keyrings, and verifies the ignore
    policy at every relevant Syncthing folder root. Secret bytes are never
    emitted.
    """
    import json as _json

    from . import resolve_capauth_home
    from .estate import audit_estate, format_estate_report, write_evidence

    homes = list(user_homes) or [Path.home()]
    capauth_home = resolve_capauth_home(ctx.obj.get("home"))
    manifest_path = manifest or capauth_home / "estate.json"
    config_pairs = [(path, homes[0]) for path in syncthing_configs]
    try:
        report = audit_estate(
            manifest_path,
            user_homes=homes,
            explicit_roots=identity_roots,
            syncthing_configs=config_pairs,
            include_gpg=include_gpg,
            passphrase_file=passphrase_file,
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if evidence is not None:
        try:
            write_evidence(report, evidence)
        except OSError as exc:
            raise click.ClickException(f"could not write evidence: {exc}") from exc
    if json_out:
        click.echo(_json.dumps(report.to_dict(), indent=2))
    else:
        click.echo(format_estate_report(report))
        if evidence is not None:
            click.echo(f"evidence: {evidence}")
    raise SystemExit(report.exit_code)
