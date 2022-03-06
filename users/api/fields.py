from rest_framework import serializers

from users.api.validators import PasswordValidator


class PasswordField(serializers.CharField):
    def __init__(self, **kwargs) -> None:
        kwargs.update({'max_length': 128})
        super().__init__(**kwargs)
        self.validators.append(PasswordValidator())
