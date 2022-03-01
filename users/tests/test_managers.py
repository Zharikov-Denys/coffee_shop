from django.test import TestCase
from django.contrib.auth import get_user_model

from users.managers import UserManager


User = get_user_model()


class TestUserManager(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.manager = UserManager()
        cls.manager.model = User
        cls.email = 'test@email.com'
        cls.password = 'testpassword123@'

    def test_create_user__email_field_is_required(self):
        with self.assertRaises(ValueError, msg=self.manager.create_user_errors['email field is required']):
            self.manager.create_user(email='', password=self.password)

    def test_create_user__success(self):
        user = self.manager.create_user(email=self.email, password=self.password)

        self.assertEqual(1, User.objects.count())
        self.assertEqual(1, User.objects.filter(id=user.id).count())

        user_from_db = User.objects.filter(id=user.id).first()

        self.assertEqual(user.email, user_from_db.email)
        self.assertEqual(user.password, user_from_db.password)
        self.assertIsNone(user_from_db.username)
        self.assertFalse(user_from_db.is_email_verified)
        self.assertTrue(user_from_db.is_active)
        self.assertFalse(user_from_db.is_staff)
        self.assertFalse(user_from_db.is_superuser)

        self.assertTrue(user.check_password(self.password))

    def test_create_superuser__is_staff_field_is_False(self):
        with self.assertRaises(ValueError, msg=self.manager.create_superuser_errors['is_staff field is required to be True']):
            self.manager.create_superuser(
                email=self.email,
                password=self.password,
                is_staff=False,
            )

    def test_create_superuser__is_superuser_field_is_False(self):
        with self.assertRaises(ValueError, msg=self.manager.create_superuser_errors['is_superuser field is required to be True']):
            self.manager.create_superuser(
                email=self.email,
                password=self.password,
                is_superuser=False,
            )

    def test_create_superuser__success(self):
        user = self.manager.create_superuser(email=self.email, password=self.password)

        self.assertEqual(1, User.objects.count())
        self.assertEqual(1, User.objects.filter(id=user.id).count())

        user_from_db = User.objects.filter(id=user.id).first()

        self.assertEqual(user.email, user_from_db.email)
        self.assertEqual(user.password, user_from_db.password)
        self.assertIsNone(user_from_db.username)
        self.assertFalse(user_from_db.is_email_verified)
        self.assertTrue(user_from_db.is_active)
        self.assertTrue(user_from_db.is_staff)
        self.assertTrue(user_from_db.is_superuser)

        self.assertTrue(user.check_password(self.password))

