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
import uuid

from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

import jwt

from .models import User, BlacklistedToken, UserSession
from .serializers import (
    RegisterSerializer,
    ChangePasswordSerializer,
    ResetPasswordEmailSerializer,
    ResetPasswordConfirmSerializer,
    ProfileUpdateSerializer,
)
from .utils import generate_access_token, generate_refresh_token, get_device_name


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
            session_id = payload.get("session_id")

        BlacklistedToken.objects.get_or_create(
            jti=jti,
            defaults={
                "token_type": token_type,
                "session_id": session_id
            }
        )
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

            if user_obj.locked_until and timezone.now() < user_obj.locked_until:
                return Response(
                    {"detail": "Hesab müvəqqəti bloklanıb. Bir az sonra yenidən cəhd edin."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        except User.DoesNotExist:
            user_obj = None

        user = authenticate(request, email=email, password=password)

        if not user:
            if user_obj:
                user_obj.failed_login_attempts += 1

                if user_obj.failed_login_attempts >= 5:
                    from datetime import timedelta
                    user_obj.locked_until = timezone.now() + timedelta(minutes=15)
                    user_obj.failed_login_attempts = 0

                user_obj.save(update_fields=["failed_login_attempts", "locked_until"])

            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ✅ сброс брутфорса
        if user_obj:
            user_obj.failed_login_attempts = 0
            user_obj.locked_until = None
            user_obj.save(update_fields=["failed_login_attempts", "locked_until"])

        # ✅ НОВОЕ — session_id
        session_id = str(uuid.uuid4())
        family_id = uuid.uuid4()
        user_agent = request.META.get("HTTP_USER_AGENT")
        device_name = get_device_name(user_agent)

        UserSession.objects.create(
            user=user,
            session_id=session_id,
            token_family=family_id,   # ✅ ДОБАВИЛИ
            is_active=True,
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=user_agent,
            device_name=device_name,
            
        )

        # ✅ НОВОЕ — передаём session_id
        access_token = generate_access_token(user, session_id)
        refresh_token = generate_refresh_token(user, session_id)

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

        try:
            user = User.objects.get(email=email)
            # отправка email
        except User.DoesNotExist:
            pass

        return Response({
            "message": "If the email exists, reset link sent"
        })


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
        BlacklistedToken.objects.create(jti=jti,
    session_id=payload.get("session_id"), token_type="refresh")

        # Старый access token тоже блокируем немедленно
        old_access = request.COOKIES.get("access")
        if old_access:
            blacklist_token_by_cookie(old_access, "access")

        old_session_id = payload.get("session_id")

        try:
            old_session = UserSession.objects.get(session_id=old_session_id)
        except UserSession.DoesNotExist:
            return Response({"detail": "Session not found"}, status=401)

        if not old_session.is_active:
            UserSession.objects.filter(
                token_family=old_session.token_family
            ).update(is_active=False)

            return Response({"detail": "Token reuse detected"}, status=401)

        # создаём новую
        # деактивируем старую сессию
        old_session.is_active = False
        old_session.save(update_fields=["is_active"])

        new_session_id = str(uuid.uuid4())

        UserSession.objects.create(
            user=user,
            session_id=new_session_id,
            token_family=old_session.token_family,  
            is_active=True,
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT"),
        )

        # передаём новый session_id
        access_token = generate_access_token(user, new_session_id)
        new_refresh_token = generate_refresh_token(user, new_session_id)

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
            try:
                payload = jwt.decode(
                    access,
                    settings.JWT_SETTINGS["SIGNING_KEY"],
                    algorithms=[settings.JWT_SETTINGS["ALGORITHM"]],
                    options={"verify_exp": False},
                )
                session_id = payload.get("session_id")

                if session_id:
                    UserSession.objects.filter(session_id=session_id).update(
                        is_active=False,
                        revoked_at=timezone.now(),
                        revoked_reason="Logout"
                    )

            except Exception:
                pass

        if refresh:
            blacklist_token_by_cookie(refresh, "refresh")

        response = Response({"success": True})

        response.delete_cookie("access", samesite="None")
        response.delete_cookie("refresh", samesite="None")
        response.delete_cookie("csrftoken", samesite="None")

        return response
    

class UserSessionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = UserSession.objects.filter(user=request.user)

        current_session_id = request.auth.get("session_id")

        data = []
        for s in sessions:
            data.append({
                "session_id": s.session_id,
                "device": s.device_name,
                "location": getattr(s, "location", None),
                "last_activity": s.last_activity_at,
                "created_at": s.created_at,
                "is_active": s.is_active,
                "is_current": s.session_id == current_session_id
            })

        return Response(data)
    

class RevokeSessionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id):
        UserSession.objects.filter(
            user=request.user,
            session_id=session_id
        ).update(is_active=False)

        return Response({"success": True})
    

class LogoutAllView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current_session = request.auth.get("session_id")

        UserSession.objects.filter(user=request.user)\
            .exclude(session_id=current_session)\
            .update(
                is_active=False,
                revoked_at=timezone.now(),
                revoked_reason="Logout all devices"
            )

        return Response({"success": True})