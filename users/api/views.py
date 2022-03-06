from django.contrib.auth import get_user_model

from rest_framework.generics import CreateAPIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from users.api.serializers import (
    SignupUserSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmationSerializer,
    AccountSerializer,
    SocialAuthenticationSerializer,
)

from social_django.utils import load_strategy, load_backend


User = get_user_model()


class SignupUserView(CreateAPIView):
    serializer_class = SignupUserSerializer


class LoginView(CreateAPIView):
    serializer_class = LoginSerializer


class PasswordResetView(CreateAPIView):
    serializer_class = PasswordResetSerializer


class PasswordResetConfirmationView(CreateAPIView):
    serializer_class = PasswordResetConfirmationSerializer


class AccountViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = AccountSerializer
    queryset = User.objects.filter(is_active=True)
    lookup_url_kwarg = 'user_id'
    lookup_field = 'id'


class SocialAuthenticationView(CreateAPIView):
    serializer_class = SocialAuthenticationSerializer

    BACKEND = None

    def update_request_by_social_backend(self, request) -> None:
        request.social_strategy = load_strategy(request)
        request.backend = load_backend(request.social_strategy, self.BACKEND, redirect_uri=None)

    def create(self, request, *args, **kwargs):
        self.update_request_by_social_backend(request)
        return super().create(request, *args, **kwargs)
