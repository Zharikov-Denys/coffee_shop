from django.conf import settings

from rest_framework.authentication import TokenAuthentication


class CustomTokenAuthentication(TokenAuthentication):
    keyword = settings.API_AUTHENTICATION_TOKEN_TYPE
