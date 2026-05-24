from django.core.management.base import BaseCommand
from api.models import User, UserProfile


class Command(BaseCommand):
    help = 'Create test users for development'

    def handle(self, *args, **options):
        test_users = [
            {
                'email': 'admin@example.com',
                'first_name': 'Admin',
                'last_name': 'User',
                'role': 'admin',
                'password': 'admin123'
            },
            {
                'email': 'doctor@example.com',
                'first_name': 'John',
                'last_name': 'Doctor',
                'role': 'doctor',
                'password': 'doctor123'
            },
            {
                'email': 'staff@example.com',
                'first_name': 'Jane',
                'last_name': 'Staff',
                'role': 'staff',
                'password': 'staff123'
            },
            {
                'email': 'patient@example.com',
                'first_name': 'Patient',
                'last_name': 'User',
                'role': 'patient',
                'password': 'patient123'
            },
        ]

        for user_data in test_users:
            password = user_data.pop('password')
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults=user_data
            )
            if created:
                user.set_password(password)
                user.save()
                UserProfile.objects.get_or_create(user=user)
                self.stdout.write(
                    self.style.SUCCESS(f'Created user: {user.email} ({user.role})')
                )
            else:
                self.stdout.write(f'User already exists: {user.email}')
