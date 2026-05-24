from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


class AuthAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            role='patient',
            first_name='Test',
            last_name='User'
        )

    def test_login(self):
        response = self.client.post('/api/v2/auth/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_login_invalid_credentials(self):
        response = self.client.post('/api/v2/auth/login/', {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_current_user(self):
        response = self.client.post('/api/v2/auth/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        token = response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get('/api/v2/auth/me/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'test@example.com')


class UserAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            role='admin'
        )

    def test_create_user(self):
        response = self.client.post('/api/v2/users/', {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'patient',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_list_users_requires_auth(self):
        response = self.client.get('/api/v2/users/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
