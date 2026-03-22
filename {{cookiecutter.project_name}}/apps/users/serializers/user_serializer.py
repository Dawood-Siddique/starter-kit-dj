from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'email',
            'first_name',
            'last_name',
            'password',
        ]

    def create(self, validated_data):
        password = validated_data.pop('password', '')
        user = User.objects.create_user(**validated_data, password=password)

        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])

        if not user:
            raise serializers.ValidationError({
                'message': 'Invalid Email or Password',
            })

        # Check if the user is active
        if not user.is_superuser and not user.is_verified:
            raise serializers.ValidationError({
                'message': 'Email is not Verified',
                'is_verified': False,
                'email': user.email
            })

        # Check if MFA is enabled for this user
        if user.mfa_secret and user.mfs_enabled:
            # Generate temporary token to prove password was verified
            mfa_token = user.generate_mfa_token()
            return {
                'mfa_required': True,
                'mfa_token': mfa_token,
                'message': 'MFA verification required. Please provide OTP.',
            }

        tokens = RefreshToken.for_user(user)
        return {
            'refresh': str(tokens),
            'access': str(tokens.access_token),
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'is_admin': True if user.is_superuser else False,
            'id': user.id,
        }


class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()


class SendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordWithOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    new_password = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name',
                  'last_name', 'is_staff', 'is_superuser']


class GoogleSignInSerializer(serializers.Serializer):
    """Accepts a Google ID token from the frontend and returns JWT tokens."""
    id_token = serializers.CharField(write_only=True)

    def validate(self, data):
        token = data['id_token']
        client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)

        if not client_id:
            raise serializers.ValidationError(
                {'detail': 'GOOGLE_CLIENT_ID is not configured on the server.'}
            )

        # Verify the token with Google's servers
        try:
            id_info = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                client_id,
            )
        except ValueError as e:
            raise serializers.ValidationError({'detail': f'Invalid Google token: {e}'})

        email = id_info.get('email', '').lower()
        first_name = id_info.get('given_name', '')
        last_name = id_info.get('family_name', '')

        if not email:
            raise serializers.ValidationError(
                {'detail': 'Google account does not have an email address.'}
            )

        # Get or create the user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'is_verified': True,
            }
        )

        # If the user already existed, ensure they are marked verified
        if not created and not user.is_verified:
            user.is_verified = True
            user.save(update_fields=['is_verified'])

        # Issue JWT tokens
        tokens = RefreshToken.for_user(user)
        return {
            'refresh': str(tokens),
            'access': str(tokens.access_token),
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
        }


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except Exception as e:
            raise serializers.ValidationError({'refresh': [str(e)]})