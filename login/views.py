from decimal import Decimal
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser

from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from django.shortcuts import redirect
from django.core.mail import send_mail
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q

from .models import Match, Like, Notification, Payment, BlockedUser
from .models_photos import UserPhoto
from .ws import notify_user
from .razorpay_client import client

from login.serializers import CreateUserReportSerializer, NotificationSerializer
from login.mysql_managers import (
    MySQLChatManager,
    MySQLLikeManager as MySQLLikeManager,
    MySQLMatchManager as MySQLMatchManager,
)

from admin_panel.models import PremiumPlan, PromoCode, UserReport
from profiles.models import UserProfile

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

import hmac
import hashlib
import urllib.parse
import requests
import random
import string
from math import radians, sin, cos, asin, sqrt

User = get_user_model()


# ============================================================
# HELPERS
# ============================================================

def get_premium_status(user) -> bool:
    """Fetch premium status from SQL UserProfile."""
    if not user or not user.is_authenticated:
        return False
    try:
        return UserProfile.objects.get(user=user).premium
    except UserProfile.DoesNotExist:
        return False


def generate_otp(length: int = 6) -> str:
    return "".join(random.choice(string.digits) for _ in range(length))


def get_user_profile_data(user) -> dict:
    """
    Return a flat profile dict from SQL UserProfile,
    shaped to match what the frontend expects.
    Returns {} if no profile exists yet.
    """
    try:
        p = UserProfile.objects.get(user=user)
        photos = p.photos or []
        return {
            "firstName":    p.first_name,
            "age":          p.age,
            "gender":       p.gender,
            "bio":          p.bio,
            "photos":       photos,
            "location":     p.location,
            "interests":    p.interests or [],
            "premium":      p.premium,
            "verified":     p.verified,
            "last_active":  p.last_active,
            "distance":     p.distance,
            "drinking":     p.drinking,
            "smoking":      p.smoking,
            "workout":      p.workout,
            "pets":         p.pets,
            "communication_style": p.communication_style,
            "response_pace":       p.response_pace,
            "conversation_starter": p.conversation_starter,
        }
    except UserProfile.DoesNotExist:
        return {}


def is_blocked(sender: str, receiver: str) -> bool:
    return BlockedUser.objects.filter(
        blocker=receiver, blocked=sender
    ).exists()


# ============================================================
# EMAIL HELPERS
# ============================================================

def send_otp_email(email: str, otp: str):
    subject = "The Dating App: your sign-in code"
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", settings.EMAIL_HOST_USER)
    otp_digits = " ".join(list(str(otp)))

    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your Sign-In Code</title>
    </head>
    <body style="margin:0;padding:0;font-family:Helvetica,Arial,sans-serif;background-color:#ffffff;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr><td align="center" style="padding:40px 20px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;margin:0 auto;">
                    <tr><td style="padding:0 0 30px 0;">
                        <h1 style="margin:0;font-size:28px;font-weight:700;background:linear-gradient(90deg,#0095E0 0%,#00C98B 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">The Dating App</h1>
                    </td></tr>
                    <tr><td style="padding:0 0 30px 0;">
                        <h2 style="margin:0 0 20px 0;color:#000;font-size:24px;font-weight:700;">Enter this code to sign in</h2>
                        <div style="margin:30px 0;">
                            <span style="display:inline-block;color:#000;font-size:48px;font-weight:700;letter-spacing:12px;padding:20px 0;">{otp_digits}</span>
                        </div>
                        <p style="margin:0 0 20px 0;color:#000;font-size:16px;line-height:1.5;">Enter the code above on your device to sign in to The Dating App.</p>
                        <p style="margin:0 0 20px 0;color:#000;font-size:16px;line-height:1.5;">This code will expire in <strong>5 minutes</strong>.</p>
                        <p style="margin:0 0 20px 0;color:#737373;font-size:14px;line-height:1.5;">If you didn't send this request, you can ignore this email.</p>
                        <p style="margin:0;color:#737373;font-size:14px;">To help security, please don't share this code with anyone.</p>
                    </td></tr>
                    <tr><td style="padding:20px 0 40px 0;">
                        <p style="margin:0;color:#000;font-size:16px;font-weight:600;">The Dating App team</p>
                    </td></tr>
                    <tr><td style="padding:20px 0 0 0;border-top:1px solid #e6e6e6;">
                        <p style="margin:0 0 15px 0;color:#737373;font-size:13px;">
                            <a href="#" style="color:#0095E0;text-decoration:none;">Help Centre</a> |
                            <a href="#" style="color:#0095E0;text-decoration:none;">Terms of Use</a> |
                            <a href="#" style="color:#0095E0;text-decoration:none;">Privacy</a>
                        </p>
                        <p style="margin:0;color:#737373;font-size:11px;">This message was emailed to {email} by The Dating App.</p>
                        <p style="margin:10px 0 0 0;color:#737373;font-size:11px;">Made with ❤️ in Hyderabad</p>
                    </td></tr>
                </table>
            </td></tr>
        </table>
    </body>
    </html>
    """

    plain_message = f"""
The Dating App — Enter this code to sign in

{otp_digits}

This code will expire in 5 minutes.
If you didn't send this request, you can ignore this email.
Do not share this code with anyone.

— The Dating App team
    """.strip()

    send_mail(subject, plain_message, from_email, [email], html_message=html_message)
    cache.set(f"login_otp_{email}", otp, timeout=300)


def send_password_reset_email(email: str, otp: str):
    subject = "Reset Your Password - The Dating App"
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", settings.EMAIL_HOST_USER)
    otp_digits = " ".join(list(str(otp)))

    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
    </head>
    <body style="margin:0;padding:0;font-family:Helvetica,Arial,sans-serif;background-color:#ffffff;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr><td align="center" style="padding:40px 20px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;margin:0 auto;">
                    <tr><td style="padding:0 0 30px 0;">
                        <h1 style="margin:0;font-size:28px;font-weight:700;background:linear-gradient(90deg,#0095E0 0%,#00C98B 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">The Dating App</h1>
                    </td></tr>
                    <tr><td style="padding:0 0 30px 0;">
                        <h2 style="margin:0 0 20px 0;color:#000;font-size:24px;font-weight:700;">Reset your password</h2>
                        <p style="margin:0 0 20px 0;color:#000;font-size:16px;line-height:1.5;">We received a request to reset your password. Enter this code to continue:</p>
                        <div style="margin:30px 0;">
                            <span style="display:inline-block;color:#000;font-size:48px;font-weight:700;letter-spacing:12px;padding:20px 0;">{otp_digits}</span>
                        </div>
                        <p style="margin:0 0 20px 0;color:#000;font-size:16px;line-height:1.5;">This code will expire in <strong>5 minutes</strong>.</p>
                        <p style="margin:0 0 20px 0;color:#737373;font-size:14px;line-height:1.5;">If you didn't request a password reset, you can safely ignore this email.</p>
                        <p style="margin:0;color:#737373;font-size:14px;">For security, please don't share this code with anyone.</p>
                    </td></tr>
                    <tr><td style="padding:20px 0 40px 0;">
                        <p style="margin:0;color:#000;font-size:16px;font-weight:600;">The Dating App team</p>
                    </td></tr>
                    <tr><td style="padding:20px 0 0 0;border-top:1px solid #e6e6e6;">
                        <p style="margin:0 0 15px 0;color:#737373;font-size:13px;">
                            <a href="#" style="color:#0095E0;text-decoration:none;">Help Centre</a> |
                            <a href="#" style="color:#0095E0;text-decoration:none;">Terms of Use</a> |
                            <a href="#" style="color:#0095E0;text-decoration:none;">Privacy</a>
                        </p>
                        <p style="margin:0;color:#737373;font-size:11px;">This message was emailed to {email} by The Dating App.</p>
                        <p style="margin:10px 0 0 0;color:#737373;font-size:11px;">Made with ❤️ in Hyderabad</p>
                    </td></tr>
                </table>
            </td></tr>
        </table>
    </body>
    </html>
    """

    plain_message = f"""
The Dating App — Reset your password

We received a request to reset your password. Enter this code to continue:

{otp_digits}

This code will expire in 5 minutes.
If you didn't request this, you can safely ignore this email.
Do not share this code with anyone.

— The Dating App team
    """.strip()

    send_mail(subject, plain_message, from_email, [email], html_message=html_message)


# ============================================================
# AUTH VIEWS
# ============================================================

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"detail": "Username and password required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"detail": "Username already exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(
            username=username,
            email=username,
            password=password,
        )

        return Response(
            {
                "message": "User created successfully",
                "user_id": user.id,
                "username": user.username,
                "is_verified": False,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    """Username + password login. Staff must use /api/admin/login/."""
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"detail": "Username and password required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if user.is_staff:
            return Response(
                {"detail": "Staff users must use admin login endpoint"},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        profile = get_user_profile_data(user)

        return Response(
            {
                "access":  str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id":          user.id,
                    "email":       user.username,
                    "is_verified": profile.get("verified", False),
                    "profile":     profile,
                },
            },
            status=status.HTTP_200_OK,
        )


class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        params = {
            "client_id":     settings.GOOGLE_CLIENT_ID,
            "redirect_uri":  settings.GOOGLE_CALLBACK_URL,
            "response_type": "code",
            "scope":         "openid email profile",
            "access_type":   "offline",
            "prompt":        "consent",
        }
        url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
        return Response({"auth_url": url}, status=status.HTTP_200_OK)


class GoogleCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return redirect(f"{settings.FRONTEND_URL}/login?error=oauth_no_code")

        token_res = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri":  settings.GOOGLE_CALLBACK_URL,
                "grant_type":    "authorization_code",
            },
        )
        google_access_token = token_res.json().get("access_token")
        if not google_access_token:
            return redirect(f"{settings.FRONTEND_URL}/login?error=oauth_no_tokens")

        userinfo = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {google_access_token}"},
        ).json()

        email         = userinfo.get("email")
        name          = userinfo.get("name", "")
        google_user_id = userinfo.get("sub")

        if not email:
            return redirect(f"{settings.FRONTEND_URL}/login?error=oauth_no_email")

        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                "email":      email,
                "first_name": name.split()[0] if name else "",
                "last_name":  " ".join(name.split()[1:]) if name else "",
            },
        )

        # Mark verified in UserProfile if it exists
        UserProfile.objects.filter(user=user).update(verified=True)

        refresh = RefreshToken.for_user(user)

        redirect_url = (
            f"{settings.FRONTEND_HOME_URL}"
            f"?access_token={urllib.parse.quote(str(refresh.access_token))}"
            f"&refresh_token={urllib.parse.quote(str(refresh))}"
            f"&email={urllib.parse.quote(email)}"
            f"&name={urllib.parse.quote(name)}"
            f"&google_id={urllib.parse.quote(google_user_id or '')}"
            f"&is_new_user={created}"
        )
        return redirect(redirect_url)


class AuthStatusView(APIView):
    """Returns profile existence + premium status for the authenticated user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = get_user_profile_data(request.user)

        return Response(
            {
                "email":          request.user.username,
                "profile_exists": bool(profile.get("firstName")),
                "has_profile":    bool(profile.get("firstName")),
                "is_verified":    profile.get("verified", False),
                "profile":        profile,
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# PROFILE VIEWS
# ============================================================

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Save / update onboarding profile fields."""
        data = request.data

        try:
            step = int(data.get("onboarding_step", 0))
        except (TypeError, ValueError):
            step = 0

        TOTAL_STEPS = 10
        step = max(0, min(step, TOTAL_STEPS))
        completion_percentage = round(step / TOTAL_STEPS * 100, 1) if step else 0

        # Upsert into SQL UserProfile
        profile_obj, _ = UserProfile.objects.get_or_create(user=request.user)

        # Map incoming keys to model fields — extend as your onboarding grows
        field_map = {
            "firstName":           "first_name",
            "age":                 "age",
            "gender":              "gender",
            "bio":                 "bio",
            "location":            "location",
            "interests":           "interests",
            "distance":            "distance",
            "drinking":            "drinking",
            "smoking":             "smoking",
            "workout":             "workout",
            "pets":                "pets",
            "communication_style": "communication_style",
            "response_pace":       "response_pace",
            "conversation_starter":"conversation_starter",
            "sexual_orientation":  "sexual_orientation",
            "relationship_goals":  "relationship_goals",
        }

        for incoming_key, model_field in field_map.items():
            if incoming_key in data:
                setattr(profile_obj, model_field, data[incoming_key])

        # Normalise photos
        photos = data.get("photos")
        if photos is not None:
            if isinstance(photos, str):
                photos = [photos]
            profile_obj.photos = [str(p) for p in photos]

        profile_obj.onboarding_step        = step
        profile_obj.completion_percentage  = completion_percentage
        profile_obj.save()

        updated_profile = get_user_profile_data(request.user)

        return Response(
            {
                "message":               "Profile saved",
                "step":                  step,
                "completion_percentage": completion_percentage,
                "profile":               updated_profile,
            },
            status=status.HTTP_200_OK,
        )


class ProfileDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, email):
        try:
            user_obj = User.objects.get(
                Q(username=email) | Q(email=email)
            )
            profile = get_user_profile_data(user_obj)
            return Response(profile, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {"error": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


# ============================================================
# PHOTO UPLOAD
# ============================================================

class PhotoUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file_obj = request.FILES.get("file")
        if not file_obj:
            return Response(
                {"detail": "No file uploaded"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        photo = UserPhoto.objects.create(user=request.user, image=file_obj)
        url = request.build_absolute_uri(photo.url)

        # Append URL to SQL UserProfile.photos
        profile_obj, _ = UserProfile.objects.get_or_create(user=request.user)
        photos = profile_obj.photos or []
        photos.append(url)
        profile_obj.photos = photos
        profile_obj.save(update_fields=["photos"])

        return Response({"url": url}, status=status.HTTP_201_CREATED)


# ============================================================
# OTP — EMAIL VERIFICATION & LOGIN
# ============================================================

class SendLoginOTPView(APIView):
    """Send OTP to an email that is not yet verified."""
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        if not username:
            return Response(
                {"detail": "Username (email) required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Block re-send if already verified
        try:
            if UserProfile.objects.get(user=user).verified:
                return Response(
                    {"detail": "Email already verified. Use normal login."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except UserProfile.DoesNotExist:
            pass

        otp = generate_otp()
        send_otp_email(username, otp)

        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)


class VerifyEmailOTPView(APIView):
    """Verify email after registration — marks UserProfile.verified = True."""
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        otp      = request.data.get("otp")

        if not username or not otp:
            return Response(
                {"detail": "Username (email) and OTP are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cache_key = f"login_otp_{username}"
        saved_otp = cache.get(cache_key)

        if not saved_otp:
            return Response(
                {"detail": "OTP expired or not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(saved_otp) != str(otp):
            return Response(
                {"detail": "Invalid OTP"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cache.delete(cache_key)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        UserProfile.objects.filter(user=user).update(verified=True)

        return Response(
            {
                "message":     "Email verified successfully",
                "user_id":     user.id,
                "is_verified": True,
            },
            status=status.HTTP_200_OK,
        )


class VerifyLoginOTPView(APIView):
    """OTP-based login for unverified users — returns JWT on success."""
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        otp      = request.data.get("otp")

        if not username or not otp:
            return Response(
                {"detail": "Username (email) and OTP are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cache_key = f"login_otp_{username}"
        saved_otp = cache.get(cache_key)

        if not saved_otp:
            return Response(
                {"detail": "OTP expired or not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(saved_otp) != str(otp):
            return Response(
                {"detail": "Invalid OTP"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cache.delete(cache_key)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Check if already verified
        try:
            if UserProfile.objects.get(user=user).verified:
                return Response(
                    {"detail": "Email already verified. Use normal login."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except UserProfile.DoesNotExist:
            pass

        # Mark verified
        UserProfile.objects.filter(user=user).update(verified=True)

        refresh = RefreshToken.for_user(user)
        profile = get_user_profile_data(user)

        return Response(
            {
                "access":  str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id":          user.id,
                    "email":       username,
                    "is_verified": True,
                    "profile":     profile,
                },
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# PASSWORD RESET
# ============================================================

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response(
                {"detail": "Email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Always return 200 to prevent user enumeration
        try:
            User.objects.get(username=email)
            otp = generate_otp()
            send_password_reset_email(email, otp)
            cache.set(f"reset_otp_{email}", otp, timeout=300)
        except User.DoesNotExist:
            pass

        return Response(
            {"message": "If this email exists, a password reset code has been sent"},
            status=status.HTTP_200_OK,
        )


class VerifyResetOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp   = request.data.get("otp")

        if not email or not otp:
            return Response(
                {"detail": "Email and OTP are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        saved_otp = cache.get(f"reset_otp_{email}")
        if not saved_otp:
            return Response(
                {"detail": "OTP expired or not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(saved_otp) != str(otp):
            return Response(
                {"detail": "Invalid OTP"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reset_token = generate_otp(length=32)
        cache.set(f"reset_token_{email}", reset_token, timeout=600)

        return Response(
            {"message": "OTP verified", "reset_token": reset_token, "email": email},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email            = request.data.get("email")
        reset_token      = request.data.get("reset_token")
        new_password     = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not all([email, reset_token, new_password, confirm_password]):
            return Response(
                {"detail": "All fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_password:
            return Response(
                {"detail": "Passwords do not match"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if len(new_password) < 8:
            return Response(
                {"detail": "Password must be at least 8 characters"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        saved_token = cache.get(f"reset_token_{email}")
        if not saved_token or saved_token != reset_token:
            return Response(
                {"detail": "Invalid or expired reset token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        user.set_password(new_password)
        user.save()

        cache.delete(f"reset_token_{email}")
        cache.delete(f"reset_otp_{email}")

        return Response(
            {"message": "Password reset successful. You can now login with your new password."},
            status=status.HTTP_200_OK,
        )


# ============================================================
# MATCHING
# ============================================================

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return R * 2 * asin(sqrt(a))


def list_overlap(a, b):
    a, b = a or [], b or []
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb)


def categorical_exact(a, b):
    return 1.0 if a and b and a == b else 0.0


def distance_similarity_km(distance_km, hard_limit_km):
    if not hard_limit_km or hard_limit_km <= 0:
        return 0.0
    return max(0.0, 1.0 - distance_km / hard_limit_km)


WEIGHTS = {
    "sexual_orientation": 0.30,
    "relationship_goals": 0.25,
    "communication":      0.15,
    "lifestyle":          0.15,
    "interests":          0.10,
    "distance_soft":      0.05,
}


def normalize_gender(label: str | None) -> str | None:
    if not label:
        return None
    label = label.lower().strip()
    if label in ("male", "man", "m"):
        return "man"
    if label in ("female", "woman", "f"):
        return "woman"
    return None


def profile_similarity(u, v, distance_km, max_dist_km):
    s_orientation = list_overlap(u.get("sexual_orientation"), v.get("sexual_orientation"))
    s_goals       = list_overlap(u.get("relationship_goals"),  v.get("relationship_goals"))

    s_comm = (
        0.7 * list_overlap(u.get("preferred_connect"), v.get("preferred_connect")) +
        0.3 * categorical_exact(u.get("response_pace"), v.get("response_pace"))
    )

    s_lifestyle = (
        0.25 * categorical_exact(u.get("drinking"), v.get("drinking")) +
        0.25 * categorical_exact(u.get("smoking"),  v.get("smoking"))  +
        0.25 * categorical_exact(u.get("workout"),  v.get("workout"))  +
        0.25 * categorical_exact(u.get("pets"),     v.get("pets"))
    )

    s_interests = list_overlap(u.get("interests"), v.get("interests"))

    if distance_km is None or max_dist_km is None:
        dist_weight, s_dist = 0.0, 0.0
    else:
        dist_weight = WEIGHTS["distance_soft"]
        s_dist = distance_similarity_km(distance_km, max_dist_km)

    return (
        WEIGHTS["sexual_orientation"] * s_orientation +
        WEIGHTS["relationship_goals"] * s_goals +
        WEIGHTS["communication"]      * s_comm +
        WEIGHTS["lifestyle"]          * s_lifestyle +
        WEIGHTS["interests"]          * s_interests +
        dist_weight                   * s_dist
    )


def serialize_profile(profile: UserProfile) -> dict:
    """
    ✅ FIXED: Safely serialize UserProfile with proper field handling.
    """
    return {
        # Core profile data (always present)
        "id":                   profile.user.id,
        "email":                profile.user.email or profile.user.username,
        "username":             profile.user.username,
        "first_name":           profile.first_name or "",
        "age":                  profile.age,
        "gender":               profile.gender or "",
        "distance":             profile.distance or 50,
        
        # Lifestyle fields (with safe defaults)
        "lifestyle": {
            "drinking": profile.drinking or "Never",
            "smoking":  profile.smoking or "Never",
            "workout":  profile.workout or "Sometimes",
            "pets":     profile.pets or "None",
        },
        
        # Communication fields (with safe defaults)
        "communication": {
            "style":         profile.communication_style or [],
            "response_pace": profile.response_pace or "Chill",
        },
        
        # Other profile data
        "interests":            profile.interests or [],
        "location":             profile.location or "",
        "photos":               profile.photos or [],
        "bio":                  profile.bio or "",
        "conversation_starter": profile.conversation_starter or "",
        "verified":             profile.verified or False,
        "premium":              profile.premium or False,
        "last_active":          profile.last_active,
        
        # ✅ CRITICAL FIX: Use getattr() for fields that might not exist
        "sexual_orientation":   getattr(profile, 'sexual_orientation', []) or getattr(profile, 'orientation', []) or [],
        "relationship_goals":   getattr(profile, 'relationship_goals', []) or getattr(profile, 'relationship_type', []) or [],
        
        # For matching algorithm
        "preferred_connect":    profile.communication_style or [],
        "response_pace":        profile.response_pace or "Chill",
    }


class MatchRecommendationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email = (request.user.email or request.user.username).lower()

        # Get current user's profile
        try:
            me_profile = UserProfile.objects.select_related("user").get(
                Q(user__email=email) | Q(user__username=email)
            )
        except UserProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found. Please complete your profile first."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Normalize gender
        my_gender = normalize_gender(me_profile.gender)
        if not my_gender:
            return Response(
                {"detail": "Please set your gender in your profile."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Determine target gender
        if my_gender == "man":
            target_gender_db = "Woman"
        elif my_gender == "woman":
            target_gender_db = "Man"
        else:
            target_gender_db = None

        # Get exclusions (matched, liked, blocked)
        matched_qs = Match.objects.filter(
            Q(user_a=email) | Q(user_b=email), status="active"
        ).values_list("user_a", "user_b")

        matched_emails = {e.lower() for pair in matched_qs for e in pair} - {email}
        liked_emails = set(Like.objects.filter(from_email=email).values_list("to_email", flat=True))
        blocked_emails = set(BlockedUser.objects.filter(blocker=email).values_list("blocked", flat=True))
        exclude_emails = matched_emails | liked_emails | blocked_emails

        # Build queryset
        others_qs = (
            UserProfile.objects
            .select_related("user")
            .filter(account_status="active")
            .exclude(user=me_profile.user)
            .exclude(Q(user__email__in=exclude_emails) | Q(user__username__in=exclude_emails))
        )

        if target_gender_db:
            others_qs = others_qs.filter(gender=target_gender_db)

        # ✅ SAFE: Serialize with error handling
        try:
            me_data = serialize_profile(me_profile)
        except Exception as e:
            import traceback
            print(f"❌ Error serializing user profile: {traceback.format_exc()}")
            return Response(
                {"detail": "Error loading your profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Calculate similarity scores
        results = []
        for other_profile in others_qs:
            try:
                other_data = serialize_profile(other_profile)
                similarity = profile_similarity(me_data, other_data, None, None)
                results.append({
                    "similarity": round(similarity * 100, 1),
                    "profile": other_data,
                })
            except Exception as e:
                # Skip profiles that fail
                print(f"⚠️ Skipping profile: {str(e)}")
                continue

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return Response(results, status=status.HTTP_200_OK)


# ============================================================
# LIKES
# ============================================================

class LikeProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from_email = (request.user.email or request.user.username).lower()
        to_email   = request.data.get("to_email", "").lower()

        if not to_email:
            return Response({"error": "to_email is required"}, status=status.HTTP_400_BAD_REQUEST)

        if from_email == to_email:
            return Response({"error": "You cannot like yourself"}, status=status.HTTP_400_BAD_REQUEST)

        result = MySQLLikeManager.send_like(from_email=from_email, to_email=to_email)

        if result.get("status") == "matched":
            match_data = result["match"]

            with transaction.atomic():
                match = Match.objects.get(id=match_data["match_id"])

                Notification.objects.bulk_create([
                    Notification(
                        user=from_email, type="MATCH_CREATED",
                        match=match, chat_id=match_data["chat_id"]
                    ),
                    Notification(
                        user=to_email, type="MATCH_CREATED",
                        match=match, chat_id=match_data["chat_id"]
                    ),
                ])

            for user_email, other in [(from_email, to_email), (to_email, from_email)]:
                notify_user(user_email, {
                    "type":       "MATCH_CREATED",
                    "match_id":   match.id,
                    "chat_id":    match.chat_id,
                    "other_user": other,
                })

            return Response(
                {"status": "matched", "match_id": match.id, "chat_id": match.chat_id},
                status=status.HTTP_200_OK,
            )

        return Response({"status": "liked", "message": "Like sent successfully"}, status=status.HTTP_200_OK)


# ============================================================
# CHATS
# ============================================================

class MatchedChatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        my_email = (request.user.email or request.user.username).lower()

        matches = Match.objects.filter(
            Q(user_a=my_email) | Q(user_b=my_email)
        ).select_related("chat")

        # Bulk-fetch all relevant UserProfiles in one query
        other_emails = [
            (m.user_b if m.user_a == my_email else m.user_a).lower()
            for m in matches
        ]
        profiles_qs = UserProfile.objects.select_related("user").filter(
            Q(user__email__in=other_emails) | Q(user__username__in=other_emails)
        )
        profile_map = {}
        for p in profiles_qs:
            key = (p.user.email or p.user.username).lower()
            profile_map[key] = p

        # Bulk-fetch block relationships
        blocked_by_me = set(
            BlockedUser.objects.filter(blocker=my_email, blocked__in=other_emails)
            .values_list("blocked", flat=True)
        )
        blocked_me = set(
            BlockedUser.objects.filter(blocker__in=other_emails, blocked=my_email)
            .values_list("blocker", flat=True)
        )

        chats = []
        for match in matches:
            other_email = (match.user_b if match.user_a == my_email else match.user_a).lower()
            profile     = profile_map.get(other_email)
            photos      = (profile.photos or []) if profile else []

            chats.append({
                "chat_id":       match.chat.id if match.chat else None,
                "match_id":      match.id,
                "status":        match.status,
                "created_at":    match.created_at.isoformat(),
                "user_email":    my_email,
                "email":         other_email,
                "first_name":    profile.first_name if profile else None,
                "profile_photo": photos[0] if photos else None,
                "blocked_by_me": other_email in blocked_by_me,
                "blocked_me":    other_email in blocked_me,
            })

        return Response(chats, status=status.HTTP_200_OK)


class ChatMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, chat_id):
        user_email = (request.user.email or request.user.username).lower()
        chat = MySQLChatManager.get_chat(chat_id)

        if not chat:
            return Response({"detail": "Chat not found"}, status=status.HTTP_404_NOT_FOUND)

        if user_email not in chat["participants"]:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        return Response(MySQLChatManager.get_messages(chat_id), status=status.HTTP_200_OK)


class SendChatMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id):
        sender  = (request.user.email or request.user.username).lower()
        content = request.data.get("content", "").strip()

        if not content:
            return Response({"detail": "Message content cannot be empty"}, status=status.HTTP_400_BAD_REQUEST)

        chat = MySQLChatManager.get_chat(chat_id)
        if not chat or sender not in chat["participants"]:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        receiver = next(e for e in chat["participants"] if e != sender)

        if BlockedUser.objects.filter(
            Q(blocker=receiver, blocked=sender) |
            Q(blocker=sender,   blocked=receiver)
        ).exists():
            return Response(
                {"detail": "You cannot send messages to this user", "blocked": True},
                status=status.HTTP_403_FORBIDDEN,
            )

        MySQLChatManager.add_message(
            chat_id=chat_id, sender=sender, receiver=receiver, content=content
        )

        async_to_sync(get_channel_layer().group_send)(
            f"chat_{chat_id}",
            {"type": "chat.message", "message": {"sender": sender, "receiver": receiver, "content": content}},
        )

        return Response({"status": "sent"}, status=status.HTTP_201_CREATED)


class MarkChatReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, chat_id):
        user_email = (request.user.email or request.user.username).lower()
        chat = MySQLChatManager.get_chat(chat_id)

        if not chat or user_email not in chat["participants"]:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        MySQLChatManager.mark_read(chat_id=chat_id, receiver_email=user_email)
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


# ============================================================
# BLOCK / UNBLOCK
# ============================================================

class BlockUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        blocker = (request.user.email or request.user.username).lower()
        blocked = request.data.get("email", "").lower()

        if not blocked:
            return Response({"detail": "Blocked email required"}, status=status.HTTP_400_BAD_REQUEST)

        BlockedUser.objects.get_or_create(blocker=blocker, blocked=blocked)
        return Response({"status": "blocked"}, status=status.HTTP_200_OK)


class UnblockUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        blocker = (request.user.email or request.user.username).lower()
        blocked = request.data.get("email", "").lower()

        BlockedUser.objects.filter(blocker=blocker, blocked=blocked).delete()
        return Response({"status": "unblocked"}, status=status.HTTP_200_OK)


# ============================================================
# REPORTS
# ============================================================

class CreateUserReportView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CreateUserReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        chat_id = serializer.validated_data["chat_id"]
        match   = Match.objects.filter(chat_id=chat_id).first()

        if not match:
            return Response({"error": "Invalid chat"}, status=status.HTTP_400_BAD_REQUEST)

        my_email = (request.user.email or request.user.username).lower()

        if match.user_a.lower() == my_email:
            reported_email = match.user_b
        elif match.user_b.lower() == my_email:
            reported_email = match.user_a
        else:
            return Response({"error": "You are not part of this chat"}, status=status.HTTP_403_FORBIDDEN)

        try:
            reported_user = User.objects.get(
                Q(email=reported_email) | Q(username=reported_email)
            )
        except User.DoesNotExist:
            return Response({"error": "Reported user not found"}, status=status.HTTP_404_NOT_FOUND)

        if reported_user == request.user:
            return Response({"error": "You cannot report yourself"}, status=status.HTTP_400_BAD_REQUEST)

        if UserReport.objects.filter(
            reporter=request.user, reported_user=reported_user, status="pending"
        ).exists():
            return Response({"error": "You already reported this user"}, status=status.HTTP_400_BAD_REQUEST)

        UserReport.objects.create(
            reporter=request.user,
            reported_user=reported_user,
            reason=serializer.validated_data["reason"],
            description=serializer.validated_data.get("description", ""),
        )

        return Response({"message": "Report submitted successfully"}, status=status.HTTP_201_CREATED)


# ============================================================
# PAYMENTS
# ============================================================

class CreateOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        plan_id    = request.data.get("plan_id")
        promo_code = request.data.get("promo_code")

        if not plan_id:
            return Response({"error": "plan_id required"}, status=status.HTTP_400_BAD_REQUEST)

        plan = PremiumPlan.objects.filter(plan_id=plan_id, active=True).first()
        if not plan:
            return Response({"error": "Invalid plan"}, status=status.HTTP_400_BAD_REQUEST)

        amount = Decimal(plan.price)

        if promo_code:
            promo = PromoCode.objects.filter(code=promo_code, active=True).first()
            if promo:
                amount = promo.apply_discount(amount)

        order = client.order.create({
            "amount":          int(amount * 100),
            "currency":        "INR",
            "payment_capture": 1,
        })

        return Response({
            "order_id":     order["id"],
            "amount":       order["amount"],
            "currency":     "INR",
            "razorpay_key": settings.RAZORPAY_KEY_ID,
            "plan_name":    plan.name,
        })


class VerifyPaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        order_id   = request.data.get("razorpay_order_id")
        payment_id = request.data.get("razorpay_payment_id")
        signature  = request.data.get("razorpay_signature")

        expected = hmac.new(
            settings.RAZORPAY_KEY_SECRET.encode(),
            f"{order_id}|{payment_id}".encode(),
            hashlib.sha256,
        ).hexdigest()

        if expected != signature:
            return Response({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)

        UserProfile.objects.filter(user=request.user).update(premium=True)

        plan = PremiumPlan.objects.filter(
            plan_id=request.data.get("plan_id", "")
        ).first()

        if plan:
            Payment.objects.create(
                user=request.user,
                plan=plan,
                razorpay_order_id=order_id,
                razorpay_payment_id=payment_id,
                amount=0,
                status="SUCCESS",
            )

        return Response({"status": "success"})
    


# ============================================================
# NOTIFICATIONS
# ============================================================

class NotificationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email = (request.user.email or request.user.username).lower()
        notifications = (
            Notification.objects
            .filter(user=email, is_read=False)
            .select_related("match")
        )
        return Response(NotificationSerializer(notifications, many=True).data)


class MarkNotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        notification_id = request.data.get("notification_id")
        email = (request.user.email or request.user.username).lower()

        Notification.objects.filter(id=notification_id, user=email).update(is_read=True)
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class MarkAllNotificationsReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email = (request.user.email or request.user.username).lower()
        Notification.objects.filter(user=email, is_read=False).update(is_read=True)
        return Response({"status": "all_read"})


class UnreadNotificationCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email = (request.user.email or request.user.username).lower()
        count = Notification.objects.filter(user=email, is_read=False).count()
        return Response({"unread_count": count})