import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, CSRFCheck
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from .models import User, BlacklistedToken, UserSession

class CookieJWTAuthentication(BaseAuthentication):

    def enforce_csrf(self, request):
        check = CSRFCheck(request)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise PermissionDenied(f"CSRF Failed: {reason}")

    def authenticate(self, request):
        token = request.COOKIES.get("access")

        if not token:
            return None

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            self.enforce_csrf(request)

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SETTINGS["SIGNING_KEY"],
                algorithms=[settings.JWT_SETTINGS["ALGORITHM"]],
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")

        if payload.get("type") != "access":
            raise AuthenticationFailed("Invalid token type")

        jti = payload.get("jti")
        if not jti:
            raise AuthenticationFailed("Invalid payload: missing jti")

        # Проверяем blacklist по jti (быстро, индексировано)
        if BlacklistedToken.objects.filter(jti=jti).exists():
            raise AuthenticationFailed("Token revoked")
        
        session_id = payload.get("session_id")

        if not session_id:
            raise AuthenticationFailed("Invalid payload: missing session_id")

        if not UserSession.objects.filter(session_id=session_id, is_active=True).exists():
            raise AuthenticationFailed("Session expired")

        user_id = payload.get("user_id")
        if not user_id:
            raise AuthenticationFailed("Invalid payload")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, payload)