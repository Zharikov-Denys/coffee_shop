from django.db import models
from django.db.models import Q, CheckConstraint
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.template.loader import get_template
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import AbstractUser

from users.managers import UserManager
from users.constants import CONFIRMATION_TOKEN_TYPE_CHOICES, ConfirmationTokenTypeEnum, PASSWORD_RESET_CONFIRMATION_URL

import uuid


class User(AbstractUser):
    email = models.EmailField(unique=True, verbose_name=_('Email'))
    username = models.CharField(
        max_length=150,
        blank=True,
        help_text=_('150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        verbose_name=_('Username'),
    )
    is_email_verified = models.BooleanField(default=False, verbose_name=_('Is email verified'))

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        return f'{self.email}'


class ConfirmationToken(models.Model):
    user = models.ForeignKey(User, related_name='confirmation_tokens', on_delete=models.CASCADE, verbose_name=_('User'))
    type = models.PositiveSmallIntegerField(choices=CONFIRMATION_TOKEN_TYPE_CHOICES, verbose_name=_('Type'))
    token = models.UUIDField(default=uuid.uuid4, editable=False, verbose_name=_('Token'))
    is_used = models.BooleanField(default=False, verbose_name=_('Is used'))
    created = models.DateTimeField(default=timezone.now, verbose_name=_('Created'))
    usage_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Usage date'))

    PASSWORD_RESET_EMAIL_SUBJECT = _('Password reset confirmation.')

    class Meta:
        verbose_name = _('Confirmation token')
        verbose_name_plural = _('Confirmation tokens')
        unique_together = ['user', 'type']
        constraints = [
            CheckConstraint(
                name='%(app_label)s_%(class)s_usage_date_is_required',
                check=Q(is_used=False) | Q(is_used=True, usage_date__isnull=False),
            )
        ]

    def __str__(self) -> str:
        return f'{self.user.email} | {self.get_type_display()} | {self.token} | {self.is_used}'

    def use_token(self) -> None:
        if self.is_used:
            return
        self.is_used = True
        self.usage_date = timezone.now()
        self.save()

    def send_email(self) -> None:
        if self.type == ConfirmationTokenTypeEnum.PASSWORD_RESET.value:
            subject = self.PASSWORD_RESET_EMAIL_SUBJECT

            text_email_template = get_template('users/emails/password_reset_confirmation.txt')
            html_email_template = get_template('users/emails/password_reset_confirmation.html')

            confirmation_url = PASSWORD_RESET_CONFIRMATION_URL.format(token=str(self.token))

            text_email = text_email_template.render({'confirmation_url': confirmation_url})
            html_email = html_email_template.render({'confirmation_url': confirmation_url})

            send_mail(
                subject=subject,
                message=text_email,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[self.user.email],
                html_message=html_email,
            )

