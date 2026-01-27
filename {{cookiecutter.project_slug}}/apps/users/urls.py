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
)

from .views.google_oauth_view import (
    GoogleLoginView,
    GoogleCallbackView,
)

user = [
    path('user/refresh/', TokenRefreshView.as_view(), name='refresh-token'),
    path('user/login/', LoginView.as_view(), name='user-login'),
    path('user/register/', RegisterView.as_view(), name='user-register'),
    path('user/verify_otp/', VerifyOtpView.as_view(), name='verify-otp'),
    path('user/send_otp/', SendOtpView.as_view(), name='send-otp'),
    path('user/change_password/', ChangePasswordView.as_view(), name='change-password'),
    path('user/reset_password_otp/', ResetPasswordWithOtpView.as_view(), name='reset-password-otp'),
    
    # Google OAuth2 URLs
    path('user/google/login/', GoogleLoginView.as_view(), name='google-login'),
    path('user/google/callback/', GoogleCallbackView.as_view(), name='google-callback'),
]

urlpatterns = [
    *user
]
