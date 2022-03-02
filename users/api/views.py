from rest_framework.generics import CreateAPIView

from users.api.serializers import SignupUserSerializer


class SignupUserView(CreateAPIView):
    serializer_class = SignupUserSerializer
