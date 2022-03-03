from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
from rest_framework import status

from users.factory import UserFactory
from users.api.serializers import SignupUserSerializer, LoginSerializer

from freezegun import freeze_time


User = get_user_model()


class TestSignupView(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.existing_user = UserFactory.create()

        cls.valid_username = 'testusername'
        cls.valid_email = 'test@email.com'
        cls.valid_password = 'testuserpassword_123'

        cls.url = reverse('signup')

    def make_valid_request(self, with_username: bool = False):
        request_data = {
            'email': self.valid_email,
            'password': self.valid_password,
        }
        if with_username:
            request_data.update({
                'username': self.valid_username,
            })

        response = self.client.post(self.url, request_data)

        self.assertTrue(User.objects.filter(email=self.valid_email))
        self.assertTrue(Token.objects.filter(user__email=self.valid_email))

        user = User.objects.get(email=self.valid_email)
        token = Token.objects.get(user=user)

        return response, user, token

    def test_required_fields(self):
        request_data = {}
        expected_result = {
            'email': [_('This field is required.')],
            'password': [_('This field is required.')],
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(expected_result, response.data)

    def test_user_with_this_email_already_exists(self):
        request_data = {
            'email': self.existing_user.email,
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertIn('email', response.data)
        self.assertEqual([SignupUserSerializer.EMAIL_IS_REQUIRED_ERROR_MESSAGE], response.data['email'])

    def test_invalid_email(self):
        request_data = {
            'email': 'test',
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertIn('email', response.data)
        self.assertEqual([_('Enter a valid email address.')], response.data['email'])

    def test_provided_password_is_too_short(self):
        request_data = {
            'password': '1',
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertIn('password', response.data)
        self.assertEqual([SignupUserSerializer.PASSWORD_IS_TOO_SHORT_ERROR_MESSAGE], response.data['password'])

    def test_valid_request_without_username__response(self):
        response, user, token = self.make_valid_request()
        self.assertEqual(status.HTTP_201_CREATED, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(
            {
                'token': token.key,
                'token_type': settings.API_AUTHENTICATION_TOKEN_TYPE,
            },
            response.data,
        )

    @freeze_time('2022-01-01 12:00:00')
    def test_valid_request_without_username__created_user(self):
        response, user, token = self.make_valid_request()
        self.assertEqual('', user.username)
        self.assertEqual(self.valid_email, user.email)
        self.assertFalse(user.is_email_verified)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(timezone.now(), user.last_login)
        self.assertTrue(user.check_password(self.valid_password))

    def test_valid_request_with_username__response(self):
        response, user, token = self.make_valid_request(with_username=True)
        self.assertEqual(status.HTTP_201_CREATED, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(
            {
                'token': token.key,
                'token_type': settings.API_AUTHENTICATION_TOKEN_TYPE,
            },
            response.data,
        )

    @freeze_time('2022-01-01 12:00:00')
    def test_valid_request_with_username__created_user(self):
        response, user, token = self.make_valid_request(with_username=True)
        self.assertEqual(self.valid_username, user.username)
        self.assertEqual(self.valid_email, user.email)
        self.assertFalse(user.is_email_verified)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(timezone.now(), user.last_login)
        self.assertTrue(user.check_password(self.valid_password))


class TestLoginView(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.valid_email = 'test@email.com'
        cls.valid_password = 'testpassword123@#'

        cls.invalid_email = 'invalid@email.com'
        cls.invalid_password = 'invalid_password'

        cls.active_user = User.objects.create_user(email=cls.valid_email, password=cls.valid_password)

        cls.url = reverse('login')

    def make_valid_request(self):
        request_data = {
            'email': self.valid_email,
            'password': self.valid_password,
        }

        response = self.client.post(self.url, request_data)

        token = Token.objects.filter(user=self.active_user).first()

        self.assertIsNotNone(token)

        return response, token

    def test_required_data(self):
        response = self.client.post(self.url, {})

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(
            {
                'email': [_('This field is required.')],
                'password': [_('This field is required.')],
            },
            response.data,
        )

    def test_request_with_invalid_email(self):
        request_data = {
            'email': self.invalid_email,
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertIn('email', response.data)
        self.assertEqual([LoginSerializer.USER_WITH_PROVIDED_EMAIL_DOES_NOT_EXIST_ERROR_MESSAGE], response.data['email'])

    def test_request_with_invalid_password(self):
        request_data = {
            'email': self.valid_email,
            'password': self.invalid_password,
        }

        response = self.client.post(self.url, request_data)

        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertIn('password', response.data)
        self.assertEqual([LoginSerializer.INVALID_PASSWORD_ERROR_MESSAGE], response.data['password'])

    def test_response_after_valid_request(self):
        response, token = self.make_valid_request()

        self.assertEqual(status.HTTP_201_CREATED, response.status_code)
        self.assertEqual('application/json', response.headers['Content-Type'])
        self.assertEqual(
            {
                'token': token.key,
                'token_type': settings.API_AUTHENTICATION_TOKEN_TYPE,
            },
            response.data,
        )

    @freeze_time('2022-01-01 12:00:00')
    def test_user_after_valid_request(self):
        response, token = self.make_valid_request()

        user = User.objects.filter(email=self.valid_email).first()

        self.assertIsNotNone(user)
        self.assertEqual(self.active_user.username, user.username)
        self.assertEqual(self.active_user.email, user.email)
        self.assertEqual(self.active_user.is_email_verified, user.is_email_verified)
        self.assertEqual(self.active_user.is_active, user.is_active)
        self.assertEqual(self.active_user.is_staff, user.is_staff)
        self.assertEqual(self.active_user.is_superuser, user.is_superuser)
        self.assertTrue(user.check_password(self.valid_password))
        self.assertEqual(timezone.now(), user.last_login)
