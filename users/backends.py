from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest

from typing import Optional


User = get_user_model()


class EmailBackend(ModelBackend):
    def authenticate(
            self,
            request: HttpRequest,
            username: Optional[str] = None,
            password: Optional[str] = None,
            **kwargs
    ) -> Optional[User]:
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return
        else:
            return user if user.check_password(password) else None

    def get_user(self, user_id: int) -> Optional[User]:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return
        else:
            return user if self.user_can_authenticate(user) else None
