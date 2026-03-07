from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from django.urls import path
from .views.user_view import (
    LoginView,
    RegisterView,
    VerifyOtpView,
    SendOtpView,
    ChangePasswordView,
    ResetPasswordWithOtpView,
    EnableMfaView,
    VerifyMfaView,
    DisableMfaView,
)

user = [
    path('login/', LoginView.as_view(), name='user-login'),
    path('register/', RegisterView.as_view(), name='user-register'),
    path('refresh/', TokenRefreshView.as_view(), name='user-refresh'),
    path('verify_otp/', VerifyOtpView.as_view(), name='verify-otp'),
    path('send_otp/', SendOtpView.as_view(), name='send-otp'),
    path('change_password/', ChangePasswordView.as_view(), name='change-password'),
    path('reset_password_otp/', ResetPasswordWithOtpView.as_view(),
         name='reset-password-otp'),
    path('enable_mfa/', EnableMfaView.as_view(), name='enable-mfa'),
    path('verify_mfa/', VerifyMfaView.as_view(), name='verify-mfa'),
    path('disable_mfa/', DisableMfaView.as_view(), name='disable-mfa'),

]

urlpatterns = [
    *user
]
