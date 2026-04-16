import jwt
import uuid
from django.conf import settings
from django.utils import timezone
from user_agents import parse
import requests


def generate_access_token(user, session_id):
    now = timezone.now()
    payload = {
        "user_id": user.id,
        "type": "access",
        "jti": str(uuid.uuid4()),       # уникальный ID токена
        "session_id": session_id,
        "iat": int(now.timestamp()),     # время выдачи
        "exp": now + settings.JWT_SETTINGS["ACCESS_TOKEN_LIFETIME"],
    }

    return jwt.encode(
        payload,
        settings.JWT_SETTINGS["SIGNING_KEY"],
        algorithm=settings.JWT_SETTINGS["ALGORITHM"],
    )


def generate_refresh_token(user, session_id):
    now = timezone.now()
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),       # уникальный ID токена
        "session_id": session_id,
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

def get_device_name(user_agent_string):
    if not user_agent_string:
        return "Unknown device"

    ua = parse(user_agent_string)

    device = ua.device.family or "Unknown device"
    browser = ua.browser.family or "Unknown browser"

    return f"{device} - {browser}"

def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        city = res.get("city")
        country = res.get("country")
        return f"{city}, {country}"
    except:
        return "Unknown"