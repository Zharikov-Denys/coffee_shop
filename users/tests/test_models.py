from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone

from users.factory import UserFactory
from users.managers import UserManager

from freezegun import freeze_time

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
