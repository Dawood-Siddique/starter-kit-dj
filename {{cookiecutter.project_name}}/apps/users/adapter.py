from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter


class AccountAdapter(DefaultAccountAdapter):
    """In DEBUG, every emailed code is 12345, so development needs no inbox."""

    def generate_email_verification_code(self):
        if settings.DEBUG:
            return '12345'
        return super().generate_email_verification_code()

    def generate_password_reset_code(self):
        if settings.DEBUG:
            return '12345'
        return super().generate_password_reset_code()
