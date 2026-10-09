import base64
import re
import hashlib
import hmac
import struct
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import include, path
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.notifications.middleware import get_user

BASE = '/_allauth/app/v1'
PASSWORD = 'Str0ng-pass-123'
LOCMEM = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}


def totp(secret):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class ProtectedView(APIView):
    """Stands in for any project endpoint that relies on DRF's default authentication."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'email': request.user.email})


urlpatterns = [
    path('', include('config.urls')),
    path('protected/', ProtectedView.as_view()),
]


@override_settings(DEBUG=True, CACHES=LOCMEM, ROOT_URLCONF=__name__)
class AuthFlowTests(TestCase):
    def setUp(self):
        cache.clear()

    # helpers ---------------------------------------------------------------

    def call(self, method, path, data=None, session=None, access=None, headers=None):
        headers = dict(headers or {})
        if session:
            headers['X-Session-Token'] = session
        if access:
            headers['Authorization'] = f'Bearer {access}'
        kwargs = {'headers': headers}
        if data is not None:
            kwargs.update(data=data, content_type='application/json')
        return getattr(self.client, method)(path if path.startswith('/protected') else BASE + path, **kwargs)

    def signup(self, email='user@example.com', password=PASSWORD):
        return self.call('post', '/auth/signup', {'email': email, 'password': password})

    def signup_and_verify(self, email='user@example.com'):
        res = self.signup(email)
        session = res.json()['meta']['session_token']
        res = self.call('post', '/auth/email/verify', {'key': '12345'}, session=session)
        self.assertEqual(res.status_code, 200, res.json())
        return res.json()['meta']

    def login(self, email='user@example.com', password=PASSWORD):
        return self.call('post', '/auth/login', {'email': email, 'password': password})

    # 1. sign up and verify -------------------------------------------------

    def test_signup_then_verify_with_12345_issues_jwt_pair(self):
        res = self.signup()
        self.assertEqual(res.status_code, 401)  # authenticated only after verifying
        self.assertEqual(
            [f['id'] for f in res.json()['data']['flows'] if f.get('is_pending')], ['verify_email'])
        self.assertNotIn('access_token', res.json()['meta'])

        meta = self.signup_and_verify(email='second@example.com')
        self.assertTrue(meta['access_token'])
        self.assertTrue(meta['refresh_token'])

    def test_wrong_code_rejected_and_code_dies_after_max_attempts(self):
        session = self.signup().json()['meta']['session_token']
        for _ in range(3):
            res = self.call('post', '/auth/email/verify', {'key': '99999'}, session=session)
            self.assertNotEqual(res.status_code, 200)
        res = self.call('post', '/auth/email/verify', {'key': '12345'}, session=session)
        self.assertNotEqual(res.status_code, 200)

    def test_login_blocked_until_email_verified(self):
        self.signup()
        # Straight after signup the verification email is in its cooldown, so login is refused outright.
        res = self.login()
        self.assertEqual(res.status_code, 400)
        self.assertNotIn('access_token', res.json().get('meta', {}))
        # After the cooldown, login re-sends the code and waits for verification. Still no tokens.
        cache.clear()
        res = self.login()
        self.assertEqual(res.status_code, 401)
        self.assertNotIn('access_token', res.json()['meta'])
        self.assertIn('verify_email', [f['id'] for f in res.json()['data']['flows'] if f.get('is_pending')])

    @override_settings(DEBUG=False)
    def test_without_debug_code_is_random_and_emailed(self):
        session = self.signup().json()['meta']['session_token']
        self.assertEqual(len(mail.outbox), 1)
        res = self.call('post', '/auth/email/verify', {'key': '12345'}, session=session)
        self.assertNotEqual(res.status_code, 200)
        code = re.search(r'^([A-Z0-9]{4}-[A-Z0-9]{4})$', mail.outbox[0].body, re.M).group(1)
        res = self.call('post', '/auth/email/verify', {'key': code}, session=session)
        self.assertEqual(res.status_code, 200, res.json())

    def test_signup_invalid_input(self):
        self.signup_and_verify()
        # Duplicate signup must not reveal the account exists, create a second user or hand out tokens.
        for email in ('user@example.com', 'USER@example.com'):
            cache.clear()
            res = self.signup(email=email)
            self.assertEqual(res.status_code, 401)
            self.assertNotIn('access_token', res.json()['meta'])
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(self.signup(email='not-an-email').status_code, 400)
        self.assertEqual(self.signup(email='').status_code, 400)
        self.assertEqual(self.signup(email='weak@example.com', password='123').status_code, 400)
        self.assertEqual(self.call('post', '/auth/signup', {'password': PASSWORD}).status_code, 400)

    def test_signup_user_is_not_staff(self):
        self.signup_and_verify()
        user = get_user_model().objects.get(email='user@example.com')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    # 2. login --------------------------------------------------------------

    def test_login(self):
        self.signup_and_verify()
        res = self.login()
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()['meta']['access_token'])

        self.assertEqual(self.login(email='USER@Example.com').status_code, 200)  # case-insensitive

        for res in (self.login(password='wrong-password'), self.login(email='nobody@example.com')):
            self.assertEqual(res.status_code, 400)
            self.assertNotIn('access_token', res.json().get('meta', {}))

    # 3. tokens -------------------------------------------------------------

    def test_refresh_rotates_and_old_refresh_token_is_rejected(self):
        meta = self.signup_and_verify()
        res = self.call('post', '/tokens/refresh', {'refresh_token': meta['refresh_token']})
        self.assertEqual(res.status_code, 200, res.json())
        new = res.json()['data']
        self.assertTrue(new['access_token'])
        self.assertNotEqual(new['refresh_token'], meta['refresh_token'])

        res = self.call('post', '/tokens/refresh', {'refresh_token': meta['refresh_token']})
        self.assertEqual(res.status_code, 400)
        res = self.call('post', '/tokens/refresh', {'refresh_token': 'garbage'})
        self.assertEqual(res.status_code, 400)

    def test_access_token_on_own_api_and_logout_invalidates_it(self):
        meta = self.signup_and_verify()
        self.assertEqual(self.call('get', '/protected/', access=meta['access_token']).status_code, 200)
        self.assertEqual(self.call('get', '/protected/').status_code, 401)
        self.assertEqual(self.call('get', '/protected/', access='garbage').status_code, 401)

        self.call('delete', '/auth/session', access=meta['access_token'])
        self.assertEqual(self.call('get', '/protected/', access=meta['access_token']).status_code, 401)
        res = self.call('post', '/tokens/refresh', {'refresh_token': meta['refresh_token']})
        self.assertEqual(res.status_code, 400)

    def test_websocket_middleware_resolves_user_from_access_token(self):
        meta = self.signup_and_verify()
        self.assertEqual(get_user.func(meta['access_token']).email, 'user@example.com')
        self.assertIsInstance(get_user.func('garbage'), AnonymousUser)
        self.assertIsInstance(get_user.func(meta['refresh_token']), AnonymousUser)

    # 4. password reset by code ---------------------------------------------

    def test_password_reset_by_code(self):
        self.signup_and_verify()
        res = self.call('post', '/auth/password/request', {'email': 'user@example.com'})
        self.assertEqual(res.status_code, 401, res.json())
        session = res.json()['meta']['session_token']

        new_password = 'An0ther-strong-pass'
        res = self.call('post', '/auth/password/reset', {'key': '99999', 'password': new_password}, session=session)
        self.assertEqual(res.status_code, 400)
        res = self.call('post', '/auth/password/reset', {'key': '12345', 'password': new_password}, session=session)
        self.assertIn(res.status_code, (200, 401), res.json())

        self.assertEqual(self.login(password=PASSWORD).status_code, 400)
        self.assertEqual(self.login(password=new_password).status_code, 200)

    def test_password_reset_for_unknown_email_looks_the_same(self):
        res = self.call('post', '/auth/password/request', {'email': 'nobody@example.com'})
        self.assertEqual(res.status_code, 401, res.json())  # same as a known email: no enumeration
        self.assertEqual(get_user_model().objects.count(), 0)

    # 5. MFA ----------------------------------------------------------------

    def test_totp_makes_login_require_second_step(self):
        self.signup_and_verify()
        meta = self.login().json()['meta']  # enabling MFA needs a recent password login
        res = self.call('get', '/account/authenticators/totp', access=meta['access_token'])
        self.assertEqual(res.status_code, 404, res.json())  # not active yet; returns a secret
        secret = res.json()['meta']['secret']
        res = self.call('post', '/account/authenticators/totp', {'code': totp(secret)}, access=meta['access_token'])
        self.assertEqual(res.status_code, 200, res.json())

        res = self.login()
        self.assertEqual(res.status_code, 401)
        self.assertNotIn('access_token', res.json()['meta'])
        self.assertIn('mfa_authenticate', [f['id'] for f in res.json()['data']['flows'] if f.get('is_pending')])
        session = res.json()['meta']['session_token']

        res = self.call('post', '/auth/2fa/authenticate', {'code': '000000'}, session=session)
        self.assertEqual(res.status_code, 400)
        res = self.call('post', '/auth/2fa/authenticate', {'code': totp(secret)}, session=session)
        self.assertEqual(res.status_code, 200, res.json())
        self.assertTrue(res.json()['meta']['access_token'])
