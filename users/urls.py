from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ProfileView,
    ChangePasswordView,
    ResetPasswordEmailView,
    ResetPasswordConfirmView,
    RefreshTokenView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path("change-password/", ChangePasswordView.as_view()),
    path("password-reset/", ResetPasswordEmailView.as_view()),
    path("password-reset-confirm/<uidb64>/<token>/", ResetPasswordConfirmView.as_view()),
    path("refresh/", RefreshTokenView.as_view()),
]