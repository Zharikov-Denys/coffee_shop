from django.urls import path

from users.api.views import SignupUserView


urlpatterns = [
    path('signup/', SignupUserView.as_view(), name='signup'),
]
