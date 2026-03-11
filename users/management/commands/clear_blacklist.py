from django.core.management.base import BaseCommand
from users.models import BlacklistedToken
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = "Clear old blacklisted tokens"

    def handle(self, *args, **kwargs):
        limit = timezone.now() - timedelta(days=2)
        BlacklistedToken.objects.filter(created_at__lt=limit).delete()