from django.urls import path

from users.api.views import (
    SignupUserView,
    LoginView,
    PasswordResetView,
)


urlpatterns = [
    path('signup/', SignupUserView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
]
