#!/bin/bash
set -e

echo "Starting auth-identity-service entrypoint..."

# Wait for database to be ready (if using PostgreSQL)
if [ "$DB_ENGINE" = "postgresql" ]; then
    echo "Waiting for PostgreSQL to be ready..."
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if python manage.py dbshell < /dev/null 2>&1; then
            echo "Database is ready"
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
fi

# Initialize database with custom management command
echo "Initializing database..."
python manage.py init_db

echo "Entrypoint setup complete, starting application..."

# Start the application
gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 --access-logfile - --error-logfile - auth_identity.wsgi:application
