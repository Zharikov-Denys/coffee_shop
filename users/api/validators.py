from django.utils.translation import gettext_lazy as _

from rest_framework import serializers


class PasswordValidator:
    MIN_PASSWORD_LENGTH = 8
    PASSWORD_IS_TOO_SHORT_ERROR_MESSAGE = _(f'Password has to be at least {MIN_PASSWORD_LENGTH} symbols length.')

    def __call__(self, value: str) -> None:
        if len(value) < self.MIN_PASSWORD_LENGTH:
            raise serializers.ValidationError(self.PASSWORD_IS_TOO_SHORT_ERROR_MESSAGE)

