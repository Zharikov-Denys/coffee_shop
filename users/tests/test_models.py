from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core import mail
from django.conf import settings

from users.factory import UserFactory
from users.managers import UserManager
from users.models import ConfirmationToken
from users.constants import ConfirmationTokenTypeEnum, PASSWORD_RESET_CONFIRMATION_URL

from freezegun import freeze_time
from datetime import timedelta

User = get_user_model()


class TestUser(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.user = UserFactory.create()

    def test_default_manager(self):
        self.assertTrue(isinstance(User.objects, UserManager))

    @freeze_time('2021-12-12 12:00')
    def test_successful_user_creation(self):
        email = 'test@email.com'
        User.objects.create(email=email)

        self.assertEqual(2, User.objects.count())

        user = User.objects.get(email=email)

        self.assertEqual(email, user.email)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(timezone.now(), user.date_joined)

    def test_str_method(self):
        self.assertIn(self.user.email, str(self.user))


class TestConfirmationToken(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.user = UserFactory.create()

    @classmethod
    def create_confirmation_token(cls, **kwargs) -> ConfirmationToken:
        parameters = {
            'user': cls.user,
            'type': ConfirmationTokenTypeEnum.PASSWORD_RESET.value,
        }
        parameters.update(kwargs)
        return ConfirmationToken.objects.create(**parameters)

    @freeze_time('2022-01-01 12:00:00')
    def test_creation(self):
        self.create_confirmation_token()

        self.assertEqual(1, ConfirmationToken.objects.count())

        confirmation_token = ConfirmationToken.objects.first()

        self.assertEqual(self.user, confirmation_token.user)
        self.assertEqual(ConfirmationTokenTypeEnum.PASSWORD_RESET.value, confirmation_token.type)
        self.assertFalse(confirmation_token.is_used)
        self.assertEqual(timezone.now(), confirmation_token.created)
        self.assertIsNone(confirmation_token.usage_date)

    def test_str_method(self):
        confirmation_token = self.create_confirmation_token()

        string_representation = str(confirmation_token)

        self.assertIn(confirmation_token.user.email, string_representation)
        self.assertIn(str(confirmation_token.get_type_display()), string_representation)
        self.assertIn(str(confirmation_token.token), string_representation)
        self.assertIn(str(confirmation_token.is_used), string_representation)

    @freeze_time('2022-01-01 12:00:00')
    def test_use_token_method_if_is_used_field_is_False(self):
        confirmation_token = self.create_confirmation_token()
        confirmation_token.use_token()

        confirmation_token = ConfirmationToken.objects.get(id=confirmation_token.id)

        self.assertEqual(self.user, confirmation_token.user)
        self.assertEqual(ConfirmationTokenTypeEnum.PASSWORD_RESET.value, confirmation_token.type)
        self.assertTrue(confirmation_token.is_used)
        self.assertEqual(timezone.now(), confirmation_token.created)
        self.assertEqual(timezone.now(), confirmation_token.usage_date)

    @freeze_time('2022-01-01 12:00:00')
    def test_use_token_method_if_is_used_field_is_True(self):
        usage_date = timezone.now() - timedelta(days=10)
        confirmation_token = self.create_confirmation_token(is_used=True, usage_date=usage_date)
        confirmation_token.use_token()

        confirmation_token = ConfirmationToken.objects.get(id=confirmation_token.id)

        self.assertEqual(self.user, confirmation_token.user)
        self.assertEqual(ConfirmationTokenTypeEnum.PASSWORD_RESET.value, confirmation_token.type)
        self.assertTrue(confirmation_token.is_used)
        self.assertEqual(timezone.now(), confirmation_token.created)
        self.assertEqual(usage_date, confirmation_token.usage_date)

    def test_send_email_method__password_reset(self):
        confirmation_token = self.create_confirmation_token()
        confirmation_token.send_email()

        self.assertEqual(1, len(mail.outbox))

        email = mail.outbox[0]

        confirmation_url = PASSWORD_RESET_CONFIRMATION_URL.format(token=str(confirmation_token.token))

        self.assertEqual(ConfirmationToken.PASSWORD_RESET_EMAIL_SUBJECT, email.subject)
        self.assertEqual(settings.DEFAULT_FROM_EMAIL, email.from_email)
        self.assertEqual([confirmation_token.user.email], email.to)
        self.assertIn(confirmation_url, email.body)
        self.assertIn(confirmation_url, str(email.alternatives[0]))
