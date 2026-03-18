# Generated migration for CapAuthStage and CapAuthKeyRegistry.
# Requires Authentik's authentik_flows app (Stage model) to be installed.
# Run inside Authentik environment: python manage.py migrate capauth

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("authentik_flows", "0001_squashed_0007_auto_20200703_2059"),
    ]

    operations = [
        migrations.CreateModel(
            name="CapAuthKeyRegistry",
            fields=[
                (
                    "fingerprint",
                    models.CharField(
                        help_text="Full 40-character uppercase PGP fingerprint.",
                        max_length=40,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "public_key_armor",
                    models.TextField(
                        help_text="ASCII-armored PGP public key. Needed for signature verification."
                    ),
                ),
                ("enrolled_at", models.DateTimeField(auto_now_add=True)),
                ("last_auth", models.DateTimeField(blank=True, null=True)),
                (
                    "approved",
                    models.BooleanField(
                        default=True,
                        help_text="Set to False when require_enrollment_approval is active.",
                    ),
                ),
                (
                    "linked_to",
                    models.CharField(
                        blank=True,
                        help_text="Primary fingerprint for multi-device identities.",
                        max_length=40,
                        null=True,
                    ),
                ),
            ],
            options={
                "verbose_name": "CapAuth Key",
                "verbose_name_plural": "CapAuth Keys",
            },
        ),
        migrations.CreateModel(
            name="CapAuthStage",
            fields=[
                (
                    "stage_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="authentik_flows.stage",
                    ),
                ),
                ("name", models.TextField(unique=True)),
                (
                    "service_id",
                    models.CharField(
                        default="authentik.local",
                        help_text="Hostname/identifier clients must use in their auth requests.",
                        max_length=255,
                    ),
                ),
                (
                    "require_enrollment_approval",
                    models.BooleanField(
                        default=False,
                        help_text="If True, new PGP keys require admin approval before first login.",
                    ),
                ),
                (
                    "nonce_ttl_seconds",
                    models.IntegerField(
                        default=60, help_text="How long (seconds) a challenge nonce remains valid."
                    ),
                ),
            ],
            options={
                "verbose_name": "CapAuth Stage",
                "verbose_name_plural": "CapAuth Stages",
            },
            bases=("authentik_flows.stage",),
        ),
    ]
