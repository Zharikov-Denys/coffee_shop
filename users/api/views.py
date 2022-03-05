from rest_framework.generics import CreateAPIView

from users.api.serializers import (
    SignupUserSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmationSerializer,
)


class SignupUserView(CreateAPIView):
    serializer_class = SignupUserSerializer


class LoginView(CreateAPIView):
    serializer_class = LoginSerializer


class PasswordResetView(CreateAPIView):
    serializer_class = PasswordResetSerializer


class PasswordResetConfirmationView(CreateAPIView):
    serializer_class = PasswordResetConfirmationSerializer
