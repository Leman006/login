from django.urls import path
from .views import RegisterView, LoginView, ChangePasswordView, ResetPasswordEmailView, ResetPasswordConfirmView , RefreshTokenView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path("change-password/", ChangePasswordView.as_view()),
    path("password-reset/", ResetPasswordEmailView.as_view()),
    path("password-reset-confirm/<uidb64>/<token>/", ResetPasswordConfirmView.as_view()),
    path("refresh/", RefreshTokenView.as_view()),
]
