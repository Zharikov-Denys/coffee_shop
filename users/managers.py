from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import BaseUserManager

from typing import Optional


class UserManager(BaseUserManager):
    create_user_errors = {
        'email field is required': _('The email field is required.'),
    }
    create_superuser_errors = {
        'is_staff field is required to be True': _('The is_staff field have to be set to True for a superuser.'),
        'is_superuser field is required to be True': _('The is_superuser field have to be set to True for a superuser.'),
    }

    def create_user(self, email: str, password: Optional[str] = None, **extra_fields):
        if not email:
            raise ValueError(self.create_user_errors['email field is required'])
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email: str, password: str, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(self.create_superuser_errors['is_staff field is required to be True'])
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(self.create_superuser_errors['is_superuser field is required to be True'])
        return self.create_user(email, password, **extra_fields)
