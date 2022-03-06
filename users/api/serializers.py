from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from users.models import ConfirmationToken
from users.constants import ConfirmationTokenTypeEnum
from users.api.fields import PasswordField

import uuid
from phonenumber_field.serializerfields import PhoneNumberField


User = get_user_model()


class SignupUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = PasswordField(required=True)

    EMAIL_IS_REQUIRED_ERROR_MESSAGE = _('User with provided email already exist.')

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        validators = []

    def validate_email(self, email: str) -> str:
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(self.EMAIL_IS_REQUIRED_ERROR_MESSAGE)
        return email

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


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, required=True)
    password = serializers.CharField(max_length=128, required=True)

    USER_WITH_PROVIDED_EMAIL_DOES_NOT_EXIST_ERROR_MESSAGE = _('The user with provided email does not exist.')
    INVALID_PASSWORD_ERROR_MESSAGE = _('Incorrect password.')

    class Meta:
        model = User
        fields = ['email', 'password']

    def to_representation(self, instance: User) -> dict:
        token, created = Token.objects.get_or_create(user=instance)
        return {
            'token': token.key,
            'token_type': settings.API_AUTHENTICATION_TOKEN_TYPE,
        }

    def validate_email(self, email: str) -> str:
        try:
            self.user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(self.USER_WITH_PROVIDED_EMAIL_DOES_NOT_EXIST_ERROR_MESSAGE)
        return email

    def validate(self, validated_data: dict) -> dict:
        password = validated_data['password']

        if not self.user.check_password(password):
            raise serializers.ValidationError({'password': self.INVALID_PASSWORD_ERROR_MESSAGE}, code='invalid')

        return validated_data

    def create(self, validated_data: dict) -> User:
        self.user.last_login = timezone.now()
        self.user.save(update_fields=['last_login'])
        return self.user


class PasswordResetSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, required=True)

    USER_WITH_PROVIDED_EMAIL_DOES_NOT_EXIST_ERROR_MESSAGE = _('The user with provided email address does not exist.')

    class Meta:
        model = User
        fields = ['email']

    def to_representation(self, instance: User) -> dict:
        return {
            'email': instance.email,
        }

    def validate_email(self, email: str) -> str:
        try:
            self.user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(self.USER_WITH_PROVIDED_EMAIL_DOES_NOT_EXIST_ERROR_MESSAGE)
        return email

    def create(self, validated_data: dict) -> User:
        confirmation_token, created = ConfirmationToken.objects.get_or_create(
            user=self.user,
            is_used=False,
            type=ConfirmationTokenTypeEnum.PASSWORD_RESET.value,
        )
        confirmation_token.send_email()
        return self.user


class PasswordResetConfirmationSerializer(serializers.ModelSerializer):
    password = PasswordField(required=True)
    token = serializers.UUIDField(required=True)

    INVALID_CONFIRMATION_TOKEN_ERROR_MESSAGE = _('Confirmation token is not valid.')

    class Meta:
        model = ConfirmationToken
        fields = ['token', 'password']

    def to_representation(self, instance: ConfirmationToken) -> dict:
        return {
            'is_used': instance.is_used,
        }

    def validate_token(self, token: uuid) -> uuid:
        if not ConfirmationToken.objects.filter(token=token, is_used=False, type=ConfirmationTokenTypeEnum.PASSWORD_RESET.value).exists():
            raise serializers.ValidationError(self.INVALID_CONFIRMATION_TOKEN_ERROR_MESSAGE)
        return token

    def create(self, validated_data: dict) -> ConfirmationToken:
        confirmation_token = ConfirmationToken.objects.get(token=validated_data['token'])
        confirmation_token.use_token()
        user = confirmation_token.user
        user.set_password(validated_data['password'])
        user.save(update_fields=['password'])
        return confirmation_token


class AccountSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, required=False)
    phone_number = PhoneNumberField(required=False, allow_blank=True)
    password = PasswordField(required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'phone_number', 'password']
        extra_kwargs = {
            'email': {
                'required': False,
            },
        }

    def to_representation(self, instance: User) -> dict:
        return {
            'username': instance.username,
            'email': instance.email,
            'phone_number': instance.phone_number.as_e164 if instance.phone_number else '',
        }

    def update(self, instance: User, validated_data: dict) -> User:
        username = validated_data.get('username')
        email = validated_data.get('email')
        phone_number = validated_data.get('phone_number')
        password = validated_data.get('password')

        update_fields = []

        if username is not None:
            instance.username = username
            update_fields.append('username')
        if email is not None:
            instance.email = email
            update_fields.append('email')
        if phone_number is not None:
            instance.phone_number = phone_number
            update_fields.append('phone_number')
        if password is not None:
            instance.set_password(password)
            update_fields.append('password')

        instance.save(update_fields=update_fields)

        return instance
