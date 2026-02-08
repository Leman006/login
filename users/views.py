from rest_framework import generics, permissions
from .serializers import RegisterSerializer
from .models import User
from .serializers import ChangePasswordSerializer
from .serializers import ResetPasswordEmailSerializer
from .serializers import ResetPasswordConfirmSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import AllowAny
from .utils import generate_access_token, generate_refresh_token
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.middleware.csrf import get_token
from django.core.mail import send_mail
import jwt
from django.conf import settings
from datetime import datetime
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode



class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]


class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, email=email, password=password)
        if not user:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        response = Response(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        )

        response.set_cookie(
            "access",
            access_token,
            httponly=True,
            max_age=300,
            samesite="Lax",
        )

        response.set_cookie(
            "refresh",
            refresh_token,
            httponly=True,
            max_age=60 * 60 * 24 * 30,
            samesite="Lax",
        )

        response.set_cookie("csrftoken", get_token(request))

        return response


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "email": request.user.email,
            "id": request.user.id
        })
    

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
            return Response({"detail": "Köhnə parol yanlışdır."},
                            status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Parol uğurla dəyişdirildi."})
    


class ResetPasswordEmailView(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
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

        return Response({"detail": "Email göndərildi."})
    


class ResetPasswordConfirmView(generics.GenericAPIView):
    serializer_class = ResetPasswordConfirmSerializer

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except:
            return Response({"detail": "Keçid etibarsızdır."},
                            status=status.HTTP_400_BAD_REQUEST)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"detail": "Token etibarsız və ya vaxtı bitib."},
                            status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Parol uğurla yeniləndi."})
    


class RefreshTokenView(APIView):
    def post(self, request):
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

        if payload.get("type") != "refresh":
            return Response({"detail": "Invalid token"}, status=401)

        user_id = payload["user_id"]

        access_token = jwt.encode(
            {
                "user_id": user_id,
                "type": "access",
                "exp": datetime.utcnow()
                + settings.JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"],
            },
            settings.JWT_SETTINGS["SIGNING_KEY"],
            algorithm=settings.JWT_SETTINGS["ALGORITHM"],
        )

        response = Response({"access_token": access_token})

        response.set_cookie(
            "access",
            access_token,
            httponly=True,
            max_age=300,
            samesite="Lax",
        )

        return response