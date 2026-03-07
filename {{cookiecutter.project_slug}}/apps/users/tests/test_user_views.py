from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from unittest.mock import patch

User = get_user_model()


class UserAPITests(APITestCase):

    def setUp(self):
        self.register_url = reverse('user-register')
        self.login_url = reverse('user-login')
        self.change_password_url = reverse('change-password')
        self.send_otp_url = reverse('send-otp')
        self.verify_otp_url = reverse('verify-otp')
        self.reset_password_with_otp_url = reverse('reset-password-otp')

        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User'
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_register_view(self):
        data = {
            'email': 'newuser@example.com',
            'password': 'newpassword123',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(User.objects.get(email='newuser@example.com').first_name, 'New')

    def test_login_view(self):
        data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_change_password_view(self):
        self.client.force_authenticate(user=self.user)
        data = {
            'old_password': self.user_data['password'],
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.change_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

    @patch('apps.users.models.user_model.send_mail')
    def test_send_otp_view(self, mock_send_mail):
        mock_send_mail.return_value = 1
        data = {'email': self.user_data['email']}
        response = self.client.post(self.send_otp_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.otp)

    def test_verify_otp_view(self):
        self.user.generate_otp()
        data = {
            'email': self.user_data['email'],
            'otp': self.user.otp
        }
        response = self.client.post(self.verify_otp_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    def test_reset_password_with_otp_view(self):
        self.user.generate_otp()
        data = {
            'email': self.user_data['email'],
            'otp': self.user.otp,
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.reset_password_with_otp_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))