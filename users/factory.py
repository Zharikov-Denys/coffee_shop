from django.contrib.auth import get_user_model

import factory


User = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    email = factory.Sequence(lambda number: f'email_{number}')
    is_active = True
    is_staff = False
    is_superuser = False


class SuperuserFactory(UserFactory):
    is_active = True
    is_staff = True
    is_superuser = True
