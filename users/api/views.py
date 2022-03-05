from rest_framework.generics import CreateAPIView

from users.api.serializers import (
    SignupUserSerializer,
    LoginSerializer,
    PasswordResetSerializer,
)


class SignupUserView(CreateAPIView):
    serializer_class = SignupUserSerializer


class LoginView(CreateAPIView):
    serializer_class = LoginSerializer


class PasswordResetView(CreateAPIView):
    serializer_class = PasswordResetSerializer
