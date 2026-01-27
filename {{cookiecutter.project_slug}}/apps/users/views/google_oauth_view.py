from urllib.parse import urlencode
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import *
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class GoogleLoginView(APIView):
    """
    GET /auth/user/google/login/
    Returns the Google authorization URL that the frontend should redirect to.
    """
    def get(self, request):
        params = {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'response_type': 'code',
            'scope': 'openid email profile',
            'access_type': 'offline',
            'prompt': 'consent',  # forces consent screen every time
        }
        auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
        return Response({'auth_url': auth_url}, status=HTTP_200_OK)


class GoogleCallbackView(APIView):
    """
    GET /auth/user/google/callback/?code=...
    Google redirects here after user approves.
    Exchanges code → token → user info → login/create user → return JWT
    """
    def get(self, request):
        error = request.GET.get('error')
        if error:
            return Response({'error': error}, status=HTTP_400_BAD_REQUEST)

        code = request.GET.get('code')
        if not code:
            return Response({'error': 'No authorization code provided'}, status=HTTP_400_BAD_REQUEST)

        # Exchange code for access token
        token_data = {
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code',
        }
        token_response = requests.post('https://oauth2.googleapis.com/token', data=token_data)
        if token_response.status_code != 200:
            return Response({'error': 'Failed to exchange code for token'}, status=HTTP_400_BAD_REQUEST)

        tokens = token_response.json()
        access_token = tokens.get('access_token')
        if not access_token:
            return Response({'error': 'No access token received'}, status=HTTP_400_BAD_REQUEST)

        # Get user info from Google
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        if userinfo_response.status_code != 200:
            return Response({'error': 'Failed to fetch user info'}, status=HTTP_400_BAD_REQUEST)

        userinfo = userinfo_response.json()
        email = userinfo['email']
        first_name = userinfo.get('given_name', '')
        last_name = userinfo.get('family_name', '')

        # Find or create user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Create new user (no password = unusable password)
            user = User.objects.create_user(
                email=email,
                password=None,          # makes password unusable
                first_name=first_name,
                last_name=last_name,
            )
            user.set_unusable_password()
            user.is_verified = True     # Google already verified the email
            user.save()

        # If existing user wasn't verified, mark as verified now
        if not user.is_verified:
            user.is_verified = True
            user.save()

        # Generate JWT tokens (same as your login)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'message': 'Logged in with Google successfully'
        }, status=HTTP_200_OK)