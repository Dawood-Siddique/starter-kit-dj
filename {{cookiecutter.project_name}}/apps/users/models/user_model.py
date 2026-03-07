from django.db import models
from django.contrib.auth.models import UserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
import random

# Create your models here.

class UserManager(UserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("No email provided")
        
        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)
    
    def create_superuser(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self._create_user(email, password, **extra_fields)
        
class User(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(blank=True, default="", unique=True)
    first_name = models.CharField(max_length=225, blank=True, default="")
    last_name = models.CharField(max_length=225, blank=True, default='')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)

    date_joined = models.DateTimeField(auto_now=True)

    # role = models.CharField(
    #     max_length=10, 
    #     choices=[('admin', 'admin'), ('manager', 'manager'), ('agent', 'agent')],
    #     default='agent'
    # )

    # phone_number = models.CharField(max_length=20,  blank=True, default='')

    otp = models.CharField(max_length=5, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    is_verified = models.BooleanField(default=False) # DEFAULT SHOULD BE FALSE | Set True to not use is_verified

    mfa_secret = models.CharField(max_length=50, blank=True, null=True)
    mfs_enabled = models.BooleanField(default=False)

    # Temporary token for MFA verification (issued after password check)
    mfa_token = models.CharField(max_length=64, blank=True, null=True)
    mfa_token_created_at = models.DateTimeField(blank=True, null=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)


    def __str__(self):
        return self.email
    

    def generate_otp(self):
        self.otp = str(random.randint(10_000, 99_999))
        self.otp_created_at = timezone.now()

        self.save()

    def generate_mfa_token(self):
        """Generate a temporary token after successful password verification.
        This token is required to complete MFA verification."""
        self.mfa_token = secrets.token_urlsafe(32)
        self.mfa_token_created_at = timezone.now()
        self.save()
        return self.mfa_token

    def verify_mfa_token(self, token):
        """Verify the temporary MFA token. Token expires after 5 minutes."""
        if not self.mfa_token or not self.mfa_token_created_at:
            return False

        # Token expires after 5 minutes (300 seconds)
        elapsed = (timezone.now() - self.mfa_token_created_at).total_seconds()
        if elapsed > 300:
            self.clear_mfa_token()
            return False

        if self.mfa_token != token:
            return False

        return True

    def clear_mfa_token(self):
        """Clear the MFA token after successful verification or expiration."""
        self.mfa_token = None
        self.mfa_token_created_at = None
        self.save()



        subject = "Please Verify this OTP code"
        message = f"Thank you for verification. Your OTP code is {self.otp}"
        from_email = settings.EMAIL_HOST_USER
        recipient = [self.email]

        if settings.DEBUG:
            return True
        
        response = send_mail(subject, message, from_email, recipient)
        if str(response) == '1':
            return True
        else:
            return False
    
    def verify_otp(self, otp, with_time = True):
        if settings.DEBUG:
            if otp == '12345':
                self.is_verified = True
                self.save()
                return True
        if self.otp and self.otp_created_at and with_time==True:
            time = (timezone.now() - self.otp_created_at).total_seconds()
            if time < 300 and self.otp == str(otp):
                self.is_verified = True
                self.save()
                return True
        elif self.otp and self.otp_created_at and with_time==False:
            if self.otp == str(otp):
                return True
        
        return False
