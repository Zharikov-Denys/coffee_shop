from django.utils.translation import gettext_lazy as _
from django.conf import settings

from enum import Enum, unique


PASSWORD_RESET_CONFIRMATION_URL = settings.BASE_URL + '/password-reset-url/{token}/'


@unique
class ConfirmationTokenTypeEnum(Enum):
    PASSWORD_RESET = 1


CONFIRMATION_TOKEN_TYPE_CHOICES = (
    (ConfirmationTokenTypeEnum.PASSWORD_RESET.value, _('Password reset')),
)
