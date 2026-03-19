import jwt
import uuid
from django.conf import settings
from django.utils import timezone


def generate_access_token(user):
    now = timezone.now()
    payload = {
        "user_id": user.id,
        "type": "access",
        "jti": str(uuid.uuid4()),       # уникальный ID токена
        "iat": int(now.timestamp()),     # время выдачи
        "exp": now + settings.JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"],
    }

    return jwt.encode(
        payload,
        settings.JWT_SETTINGS["SIGNING_KEY"],
        algorithm=settings.JWT_SETTINGS["ALGORITHM"],
    )


def generate_refresh_token(user):
    now = timezone.now()
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),       # уникальный ID токена
        "iat": int(now.timestamp()),     # время выдачи
        "exp": now + settings.JWT_SETTINGS["REFRESH_TOKEN_LIFETIME"],
    }

    return jwt.encode(
        payload,
        settings.JWT_SETTINGS["SIGNING_KEY"],
        algorithm=settings.JWT_SETTINGS["ALGORITHM"],
    )


def get_tokens_for_user(user):
    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    return {
        "access": access_token,
        "refresh": refresh_token,
    }