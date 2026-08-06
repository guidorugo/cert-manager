"""Flask CLI commands for CA key-backend management (A1).

`flask keys migrate-to-hsm` moves software CA signing keys into the PKCS#11
token. This is intentionally one-way: after migration the key is non-extractable
and the encrypted software copy is scrubbed, so the trust anchor can no longer be
read off the host. Back up any key you might need to export BEFORE migrating.
"""
import click
from flask import current_app
from flask.cli import AppGroup

from .extensions import db
from .models.ca import CertificateAuthority
from .services.crypto_utils import decrypt_private_key
from .services.keybackend import get_backend, hsm_available
from .services.ca_service import _key_label

keys_cli = AppGroup("keys", help="CA key-backend management.")


@keys_cli.command("migrate-to-hsm")
@click.option("--ca-id", type=int, default=None,
              help="Migrate only this CA (default: every software-keyed CA).")
@click.option("--dry-run", is_flag=True,
              help="Show what would migrate without changing anything.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def migrate_to_hsm(ca_id, dry_run, yes):
    """Move software CA signing keys into the PKCS#11 token (IRREVERSIBLE)."""
    if not hsm_available():
        raise click.ClickException(
            "HSM backend not available. Set KEY_BACKEND=softhsm and the PKCS11_* "
            "settings, and initialise the token, before migrating.")

    q = CertificateAuthority.query.filter(
        CertificateAuthority.key_backend == "software",
        CertificateAuthority.private_key_enc != b"",
    )
    if ca_id is not None:
        q = q.filter(CertificateAuthority.id == ca_id)
    cas = q.all()
    if not cas:
        click.echo("No software-keyed CAs to migrate.")
        return

    click.echo("The following CA keys will be moved into the HSM token:")
    for ca in cas:
        click.echo(f"  [{ca.id}] {ca.name} ({ca.key_type} {ca.key_size})")
    click.echo("")
    click.echo("This is IRREVERSIBLE: each key becomes non-extractable and its")
    click.echo("encrypted software copy is scrubbed. Back up any key you may need")
    click.echo("to export (e.g. `flask` export or the UI Key/PKCS#12 buttons) BEFORE")
    click.echo("migrating — afterwards export is refused.")

    if dry_run:
        click.echo("\n--dry-run: no changes made.")
        return
    if not yes:
        click.confirm("\nProceed with migration?", abort=True)

    secret = current_app.config["MASTER_PASSPHRASE"]
    backend = get_backend("softhsm")
    migrated = 0
    for ca in cas:
        key = decrypt_private_key(ca.private_key_enc, secret)
        label = _key_label()
        backend.import_ca_key(key, label=label, secret=secret)
        ca.key_backend = "softhsm"
        ca.key_label = label
        ca.private_key_enc = b""
        db.session.add(ca)
        db.session.commit()
        migrated += 1
        click.echo(f"Migrated [{ca.id}] {ca.name} -> HSM ({label})")
    click.echo(f"\nDone. {migrated} CA key(s) migrated.")
