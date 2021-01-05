from django.urls import path
from .views import (
    RegistrationAPIView, LoginAPIView
)
from rest_framework_jwt.views import refresh_jwt_token, obtain_jwt_token

app_name = 'authentication'

urlpatterns = [
    path('register', RegistrationAPIView.as_view(), name='registerAPI'),
    path('login', LoginAPIView.as_view(), name='loginAPI'),
    # path('user', UserRetrieveUpdateAPIView.as_view(), name='user'),
    # path('reset', UpdatePassword.as_view(), name='reset'),
    path('token/refresh', refresh_jwt_token),
    path('api-token-auth', obtain_jwt_token)
]
