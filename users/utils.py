import jwt
from datetime import datetime
from django.conf import settings


def generate_access_token(user):
    payload = {
        "user_id": user.id,
        "type": "access",
        "exp": datetime.utcnow()
        + settings.JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"],
    }

    return jwt.encode(
        payload,
        settings.JWT_SETTINGS["SIGNING_KEY"],
        algorithm=settings.JWT_SETTINGS["ALGORITHM"],
    )


def generate_refresh_token(user):
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "exp": datetime.utcnow()
        + settings.JWT_SETTINGS["REFRESH_TOKEN_LIFETIME"],
    }

    return jwt.encode(
        payload,
        settings.JWT_SETTINGS["SIGNING_KEY"],
        algorithm=settings.JWT_SETTINGS["ALGORITHM"],
    )
