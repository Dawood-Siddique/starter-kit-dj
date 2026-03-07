from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken

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
