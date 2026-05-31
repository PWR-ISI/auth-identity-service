from django.core.management.base import BaseCommand
from django.db import connection, DEFAULT_DB_ALIAS
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Initialize database and ensure all tables are created'

    def handle(self, *args, **options):
        self.stdout.write("Initializing database...")

        # Check if api_user table exists
        table_exists = False
        with connection.cursor() as cursor:
            try:
                cursor.execute("SELECT 1 FROM api_user LIMIT 1")
                table_exists = True
                self.stdout.write(self.style.SUCCESS("✓ api_user table exists"))
            except Exception as e:
                self.stdout.write(self.style.WARNING("✗ api_user table does not exist"))

        # If table doesn't exist, clear migration history and re-run
        if not table_exists:
            self.stdout.write("Clearing api migration history...")
            with connection.cursor() as cursor:
                try:
                    cursor.execute("DELETE FROM django_migrations WHERE app = 'api'")
                    self.stdout.write(self.style.SUCCESS("  Migration history cleared"))
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"  Could not clear history: {e}"))

        # Run migrations
        self.stdout.write("Running migrations...")
        try:
            call_command('migrate', verbosity=2, interactive=False)
            self.stdout.write(self.style.SUCCESS("✓ Migrations completed"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Migration error: {e}"))
            raise

        # Final check
        with connection.cursor() as cursor:
            try:
                cursor.execute("SELECT 1 FROM api_user LIMIT 1")
                self.stdout.write(self.style.SUCCESS("✓ Database initialized successfully"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Database initialization failed: {e}"))
                raise
