from rest_framework.generics import CreateAPIView

from users.api.serializers import SignupUserSerializer, LoginSerializer


class SignupUserView(CreateAPIView):
    serializer_class = SignupUserSerializer


class LoginView(CreateAPIView):
    serializer_class = LoginSerializer
