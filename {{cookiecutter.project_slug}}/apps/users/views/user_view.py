import pyotp
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import *
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from apps.users.serializers.user_serializer import (
    LoginSerializer,
    RegisterSerializer,
    SendOtpSerializer,
    VerifyOtpSerializer,
    ResetPasswordWithOtpSerializer,
    ChangePasswordSerializer
)

import pyotp

User = get_user_model()

# Create your views here.


class RegisterView(APIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'User Register Successfully'}, status=HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            return Response(serializer.validated_data, status=HTTP_200_OK)
        else:
            errors = serializer.errors
            if isinstance(errors, dict) and 'is_verified' in errors:
                return Response(errors, status=HTTP_403_FORBIDDEN)
            return Response(errors, status=HTTP_401_UNAUTHORIZED)


class VerifyOtpView(APIView):
    serializer_class = VerifyOtpSerializer

    def post(self, request):
        serializer = VerifyOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        otp = serializer.validated_data.get('otp')

        try:
            user = User.objects.get(email=email)
        except:
            return Response({'message': 'User not Found'}, status=HTTP_404_NOT_FOUND)

        if user.verify_otp(otp):
            return Response({'message': 'OTP verified successfully'}, status=HTTP_200_OK)
        else:
            return Response({'message': 'Invalid or Expired OTP'}, status=HTTP_400_BAD_REQUEST)


class SendOtpView(APIView):
    serializer_class = SendOtpSerializer

    def post(self, request):
        serializer = SendOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')

        try:
            user = User.objects.get(email=email)
        except:
            return Response({'message': 'User not found'}, status=HTTP_404_NOT_FOUND)

        if user.generate_otp():
            return Response({'message': 'OTP sent'}, status=HTTP_200_OK)
        else:
            return Response({'message': 'Error, OTP not sent'}, status=HTTP_503_SERVICE_UNAVAILABLE)


class ResetPasswordWithOtpView(APIView):
    serializer_class = ResetPasswordWithOtpSerializer

    def post(self, request):
        serializer = ResetPasswordWithOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        otp = serializer.validated_data.get('otp')
        new_password = serializer.validated_data.get('new_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=HTTP_404_NOT_FOUND)

        if not user.verify_otp(otp):
            return Response({'message': 'Invalid or expired OTP'}, status=HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successfully'}, status=HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

        user = request.user
        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')

        if not user.check_password(old_password):
            return Response({'message': 'Old password is incorrect'}, status=HTTP_403_FORBIDDEN)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=HTTP_200_OK)


class EnableMfaView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()

        user.mfs_enabled = True
        user.save()

        totp = pyotp.TOTP(user.mfa_secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="SniffyBot")

        return Response({'message': 'MFA enabled successfully', 'uri': uri}, status=HTTP_200_OK)


class VerifyMfaView(APIView):

    def post(self, request):
        otp = request.data.get('otp')
        mfa_token = request.data.get('mfa_token')

        if not mfa_token or not otp:
            return Response({'message': 'mfa_token and otp are required'}, status=HTTP_400_BAD_REQUEST)

        # Find user by mfa_token
        try:
            user = User.objects.get(mfa_token=mfa_token)
        except User.DoesNotExist:
            return Response({'message': 'Invalid or expired MFA token'}, status=HTTP_401_UNAUTHORIZED)

        # Verify the mfa_token is still valid (not expired)
        if not user.verify_mfa_token(mfa_token):
            return Response({'message': 'MFA token expired. Please login again.'}, status=HTTP_401_UNAUTHORIZED)

        if not user.mfa_secret or not user.mfs_enabled:
            return Response({'message': 'MFA is not enabled for this user'}, status=HTTP_400_BAD_REQUEST)

        # Verify the OTP from Google Authenticator
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(otp, valid_window=1):
            return Response({'message': 'Invalid OTP'}, status=HTTP_400_BAD_REQUEST)

        # Clear the mfa_token after successful verification (one-time use)
        user.clear_mfa_token()

        # Generate tokens after successful MFA verification
        from rest_framework_simplejwt.tokens import RefreshToken
        tokens = RefreshToken.for_user(user)

        return Response({
            'refresh': str(tokens),
            'access': str(tokens.access_token),
            'is_admin': True if user.is_superuser else False,
            'id': user.id,
        }, status=HTTP_200_OK)


class DisableMfaView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        otp = request.data.get('otp')

        if not user.mfs_enabled:
            return Response({'message': 'MFA is not enabled'}, status=HTTP_400_BAD_REQUEST)

        # Verify OTP before disabling for security
        if not otp:
            return Response({'message': 'OTP is required to disable MFA'}, status=HTTP_400_BAD_REQUEST)

        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(otp, valid_window=1):
            return Response({'message': 'Invalid OTP'}, status=HTTP_400_BAD_REQUEST)

        user.mfs_enabled = False
        user.mfa_secret = None
        user.save()

        return Response({'message': 'MFA disabled successfully'}, status=HTTP_200_OK)
