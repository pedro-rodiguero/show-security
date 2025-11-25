from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    """
    Modelo de usuário estendido para incluir funcionalidades de segurança.
    """

    failed_attempts = models.IntegerField(
        default=0, help_text="Contador de tentativas de login falhas."
    )
    lockout_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Data e hora até quando o usuário está bloqueado.",
    )
    two_factor_secret = models.CharField(
        max_length=255,
        blank=True,
        help_text="Segredo para autenticação de dois fatores (TOTP).",
    )

    def __str__(self):
        return self.username
