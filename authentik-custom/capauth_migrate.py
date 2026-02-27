"""
Lifecycle system migration: run capauth Django migrations on startup.

Authentik loads scripts from /lifecycle/system_migrations/ at boot
(before the Django server starts). BaseMigration receives raw psycopg
cursor/connection, not Django ORM.
"""

from lifecycle.migrate import BaseMigration


class Migration(BaseMigration):
    def needs_migration(self) -> bool:
        self.cur.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'capauth_capauthstage'"
        )
        return self.cur.fetchone() is None

    def run(self):
        # Authentik's venv python is on PATH; lifecycle.ak wraps manage.py
        self.system_crit("python -m lifecycle.ak migrate capauth")
