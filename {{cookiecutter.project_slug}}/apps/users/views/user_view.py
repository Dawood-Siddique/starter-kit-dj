from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import *
from apps.users.serializers.user_serializer import (
    LoginSerializer,
    RegisterSerializer,
)
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.tokens import RefreshToken


User = get_user_model()
# Create your views here.


class RegisterView(APIView):
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
            return Response(serializer.errors, status=HTTP_401_UNAUTHORIZED)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not old_password or not new_password:
            return Response({'message': 'Both old and new passwords are required'}, status=HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({'message': 'Old password is incorrect'}, status=HTTP_403_FORBIDDEN)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=HTTP_200_OK)


class ResetPasswordWithOtpView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        new_password = request.data.get('new_password')
        user = request.user

        if not new_password:
            return Response({'message': 'New Password are required'}, status=HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successfully'}, status=HTTP_200_OK)


class SendOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'message': 'Email is required'}, status=HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except:
            return Response({'message': 'User not found'}, status=HTTP_404_NOT_FOUND)

            # if the debug is true in setting then return OTP sent
        if settings.DEBUG:
            print(f"OTP for {email}: {user.otp}")
            return Response({'message': 'OTP sent (DEBUG)'}, status=HTTP_200_OK)

        try:
            if user.generate_otp():
                return Response({'message': 'OTP sent'}, status=HTTP_200_OK)
        except:
            return Response({'message': 'Error sending OTP'}, status=HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            return Response({'message': 'Error, OTP not sent'}, status=HTTP_503_SERVICE_UNAVAILABLE)


class VerifyOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'message': 'Email and OTP required'}, status=HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except:
            return Response({'message': 'User not Found'}, status=HTTP_404_NOT_FOUND)

        if user.verify_otp(otp):
            # Send access and refresh token of the user
            tokens = RefreshToken.for_user(user)
            return Response({
                'refresh': str(tokens),
                'access': str(tokens.access_token)
            }, status=HTTP_200_OK)

        else:
            return Response({'message': 'Invalid or Expired OTP'}, status=HTTP_400_BAD_REQUEST)
