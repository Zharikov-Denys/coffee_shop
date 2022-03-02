from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers
from rest_framework.authtoken.models import Token


User = get_user_model()


class SignupUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    MIN_PASSWORD_LENGTH = 8
    EMAIL_IS_REQUIRED_ERROR_MESSAGE = _('User with provided email already exist.')
    PASSWORD_IS_TOO_SHORT_ERROR_MESSAGE = _(f'Password has to be at least {MIN_PASSWORD_LENGTH} symbols length.')

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        validators = []

    def validate_email(self, email: str) -> str:
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(self.EMAIL_IS_REQUIRED_ERROR_MESSAGE)
        return email

    def validate_password(self, password: str) -> str:
        if len(password) < self.MIN_PASSWORD_LENGTH:
            raise serializers.ValidationError(self.PASSWORD_IS_TOO_SHORT_ERROR_MESSAGE)
        return password

    def to_representation(self, instance: User) -> dict:
        return {
            'token': self.token.key,
            'token_type': settings.API_AUTHENTICATION_TOKEN_TYPE,
        }

    def create(self, validated_data: dict) -> User:
        user = User.objects.create_user(
            username=validated_data.get('username', ''),
            email=validated_data['email'],
            password=validated_data['password'],
            last_login=timezone.now(),
        )

        self.token, created = Token.objects.get_or_create(user=user)

        return user

