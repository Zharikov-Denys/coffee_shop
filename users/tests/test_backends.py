from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase

from users.backends import EmailBackend


User = get_user_model()


class TestEmailBackend(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.request = HttpRequest()
        cls.backend = EmailBackend()

        cls.nonexistent_user_id = 10000
        cls.nonexistent_email = 'nonexistent@email.com'
        cls.valid_password = 'testpassword123*@'
        cls.invalid_password = 'invalid_password'

        cls.active_user = User.objects.create_user(email='test_1@email.com', password=cls.valid_password)
        cls.inactive_user = User.objects.create_user(email='test_2@email.com', password=cls.valid_password, is_active=False)

    def test_get_user__success(self):
        user_from_db = User.objects.get(id=self.active_user.id)
        user = self.backend.get_user(user_id=self.active_user.id)
        self.assertEqual(user_from_db, user)

    def test_get_user__user_with_provided_id_does_not_exist(self):
        self.assertIsNone(self.backend.get_user(user_id=self.nonexistent_user_id))

    def test_get_user__user_id_inactive(self):
        self.assertIsNone(self.backend.get_user(user_id=self.inactive_user.id))

    def test_authenticate__success(self):
        user_from_db = User.objects.get(id=self.active_user.id)
        user = self.backend.authenticate(
            request=self.request,
            username=self.active_user.email,
            password=self.valid_password,
        )
        self.assertEqual(user_from_db, user)

    def test_authenticate__invalid_username_value(self):
        self.assertIsNone(self.backend.authenticate(
            request=self.request,
            username=self.nonexistent_email,
            password=self.valid_password,
        ))

    def test_authenticate__invalid_password(self):
        self.assertIsNone(self.backend.authenticate(
            request=self.request,
            username=self.active_user.email,
            password=self.invalid_password,
        ))
