from rest_framework import generics, permissions, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response

from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.middleware.csrf import get_token, CsrfViewMiddleware
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

import jwt

from .models import User, BlacklistedToken
from .serializers import (
    RegisterSerializer,
    ChangePasswordSerializer,
    ResetPasswordEmailSerializer,
    ResetPasswordConfirmSerializer,
    ProfileUpdateSerializer,
)
from .utils import generate_access_token, generate_refresh_token


def blacklist_token_by_cookie(token_str, token_type):
    """Декодирует токен без верификации и добавляет его jti в blacklist."""
    try:
        payload = jwt.decode(
            token_str,
            settings.JWT_SETTINGS["SIGNING_KEY"],
            algorithms=[settings.JWT_SETTINGS["ALGORITHM"]],
            options={"verify_exp": False},  # токен мог уже истечь — всё равно блокируем
        )
        jti = payload.get("jti")
        if jti:
            BlacklistedToken.objects.get_or_create(jti=jti, defaults={"token_type": token_type})
    except Exception:
        pass


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]


# Brute-force: 5 попыток в минуту по IP И по email (ключ user_or_ip)
@method_decorator(
    ratelimit(key="ip", rate="5/m", method="POST", block=True),
    name="post"
)
@method_decorator(
    ratelimit(key="post:email", rate="10/m", method="POST", block=True),
    name="post"
)
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user_obj = User.objects.get(email=email)

            # Проверяем блокировку аккаунта
            if user_obj.locked_until and timezone.now() < user_obj.locked_until:
                return Response(
                    {"detail": "Hesab müvəqqəti bloklanıb. Bir az sonra yenidən cəhd edin."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        except User.DoesNotExist:
            user_obj = None

        user = authenticate(request, email=email, password=password)

        if not user:
            # Увеличиваем счётчик неудачных попыток
            if user_obj:
                user_obj.failed_login_attempts += 1
                # После 5 неудачных попыток — блокировка на 15 минут
                if user_obj.failed_login_attempts >= 5:
                    from datetime import timedelta
                    user_obj.locked_until = timezone.now() + timedelta(minutes=15)
                    user_obj.failed_login_attempts = 0
                user_obj.save(update_fields=["failed_login_attempts", "locked_until"])

            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Успешный вход — сбрасываем счётчик
        if user_obj:
            user_obj.failed_login_attempts = 0
            user_obj.locked_until = None
            user_obj.save(update_fields=["failed_login_attempts", "locked_until"])

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        response = Response({"success": True})

        response.set_cookie(
            key="access",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=300,
        )

        response.set_cookie(
            key="refresh",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=60 * 60 * 24 * 30,
        )

        response.set_cookie(
            key="csrftoken",
            value=get_token(request),
            secure=True,
            samesite="None",
        )

        return response


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone": user.phone,
            "birth_date": user.birth_date,
            "gender": user.gender,
        })

    def patch(self, request):
        serializer = ProfileUpdateSerializer(
            request.user,
            data=request.data,
            partial=True
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"detail": "Köhnə parol yanlışdır."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Parol uğurla dəyişdirildi."})


class ResetPasswordEmailView(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        # try/except — email olmasa belə eyni cavab qaytarılır (enumeration yoxdur)
        try:
            user = User.objects.get(email=email)

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            reset_link = f"http://your-domain.com/reset-password-confirm/{uid}/{token}/"

            send_mail(
                subject="Parolun sıfırlanması",
                message=f"Parolunuzu sıfırlamaq üçün keçid: {reset_link}",
                from_email="no-reply@your-domain.com",
                recipient_list=[email],
            )

        except User.DoesNotExist:
            pass

        return Response(
            {"detail": "If the account exists, email was sent."}
        )


class ResetPasswordConfirmView(generics.GenericAPIView):
    serializer_class = ResetPasswordConfirmSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response(
                {"detail": "Keçid etibarsızdır."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response(
                {"detail": "Token etibarsız və ya vaxtı bitib."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Parol uğurla yeniləndi."})


class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # CSRF проверка для незащищённого эндпоинта
        csrf_middleware = CsrfViewMiddleware(lambda req: None)
        csrf_middleware.process_request(request)
        reason = csrf_middleware.process_view(request, None, (), {})
        if reason:
            return Response({"detail": "CSRF Failed"}, status=403)

        refresh_token = request.COOKIES.get("refresh")

        if not refresh_token:
            return Response({"detail": "No refresh token"}, status=401)

        try:
            payload = jwt.decode(
                refresh_token,
                settings.JWT_SETTINGS["SIGNING_KEY"],
                algorithms=[settings.JWT_SETTINGS["ALGORITHM"]],
            )
        except jwt.ExpiredSignatureError:
            return Response({"detail": "Refresh expired"}, status=401)
        except jwt.InvalidTokenError:
            return Response({"detail": "Invalid token"}, status=401)

        if payload.get("type") != "refresh":
            return Response({"detail": "Invalid token type"}, status=401)

        jti = payload.get("jti")
        if not jti:
            return Response({"detail": "Invalid token: missing jti"}, status=401)

        # Проверяем blacklist по jti
        if BlacklistedToken.objects.filter(jti=jti).exists():
            return Response({"detail": "Token revoked"}, status=401)

        user_id = payload.get("user_id")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=404)

        # Rotation: старый refresh в blacklist
        BlacklistedToken.objects.create(jti=jti, token_type="refresh")

        # Старый access token тоже блокируем немедленно
        old_access = request.COOKIES.get("access")
        if old_access:
            blacklist_token_by_cookie(old_access, "access")

        access_token = generate_access_token(user)
        new_refresh_token = generate_refresh_token(user)

        response = Response({"success": True})

        response.set_cookie(
            key="access",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=300,
        )

        response.set_cookie(
            key="refresh",
            value=new_refresh_token,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=60 * 60 * 24 * 30,
        )

        return response


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        access = request.COOKIES.get("access")
        refresh = request.COOKIES.get("refresh")

        # Блокируем оба токена по jti
        if access:
            blacklist_token_by_cookie(access, "access")

        if refresh:
            blacklist_token_by_cookie(refresh, "refresh")

        response = Response({"success": True})

        response.delete_cookie("access", samesite="None")
        response.delete_cookie("refresh", samesite="None")
        response.delete_cookie("csrftoken", samesite="None")

        return response