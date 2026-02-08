import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import User


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        access_token = request.COOKIES.get("access")

        if not access_token:
            return None 

        try:
            payload = jwt.decode(
                access_token,
                settings.JWT_SETTINGS["SIGNING_KEY"],
                algorithms=[settings.JWT_SETTINGS["ALGORITHM"]],
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")

        if payload.get("type") != "access":
            raise AuthenticationFailed("Invalid token type")

        try:
            user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, None)
