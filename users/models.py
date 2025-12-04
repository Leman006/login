from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    username = None  # удаляем username

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)

    phone = models.CharField(max_length=20)
    birth_date = models.DateField()
    gender = models.CharField(max_length=10, choices=[
        ('qadin', 'Qadın'),
        ('kisi', 'Kişi'),
        ('diger', 'Digər'),
    ])

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # т.к. логин по email

    def __str__(self):
        return self.email
