from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email mütləqdir")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        user.set_password(password)
        user.is_staff = False
        user.is_superuser = False
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser is_staff=True olmalıdır")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser is_superuser=True olmalıdır")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = None

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)

    phone = models.CharField(max_length=20)
    birth_date = models.DateField()
    gender = models.CharField(
        max_length=10,
        choices=[
            ("qadin", "Qadın"),
            ("kisi", "Kişi"),
            ("diger", "Digər"),
        ],
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
