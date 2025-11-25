from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser
import pyotp

# Constantes para o bloqueio
LOCKOUT_ATTEMPTS = 5
LOCKOUT_TIME_MINUTES = 5


def login_level1(request):
    """
    Nível 1: Vulnerabilidade de Força Bruta.
    A senha é verificada diretamente como texto plano.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            # Consulta direta e insegura
            user = CustomUser.objects.get(username=username, password=password)
            login(request, user)
            messages.success(request, f"Bem-vindo, {user.username}! (Login Nível 1)")
            return redirect("home")  # Crie uma view 'home' simples
        except CustomUser.DoesNotExist:
            messages.error(request, "Usuário ou senha inválidos.")

    return render(request, "login.html", {"level": 1})


def login_level2(request):
    """
    Nível 2: Proteção com Rate Limiting e Hashing (Bcrypt).
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            messages.error(request, "Usuário ou senha inválidos.")
            return render(request, "login.html", {"level": 2})

        # 1. Verificar se o usuário está bloqueado
        if user.lockout_time and user.lockout_time > timezone.now():
            remaining = (user.lockout_time - timezone.now()).seconds // 60
            messages.warning(
                request, f"Conta bloqueada. Tente novamente em {remaining+1} minutos."
            )
            return render(request, "login.html", {"level": 2})

        # 2. Autenticar usando o sistema seguro do Django
        authenticated_user = authenticate(request, username=username, password=password)

        if authenticated_user is not None:
            # 3. Sucesso: resetar contadores e fazer login
            user.failed_attempts = 0
            user.lockout_time = None
            user.save()
            login(request, authenticated_user)
            messages.success(request, f"Bem-vindo, {user.username}! (Login Nível 2)")
            return redirect("home")
        else:
            # 4. Falha: incrementar contador e bloquear se necessário
            user.failed_attempts += 1
            if user.failed_attempts >= LOCKOUT_ATTEMPTS:
                user.lockout_time = timezone.now() + timedelta(
                    minutes=LOCKOUT_TIME_MINUTES
                )
                messages.error(
                    request,
                    f"Usuário ou senha inválidos. A conta foi bloqueada por {LOCKOUT_TIME_MINUTES} minutos.",
                )
            else:
                remaining_attempts = LOCKOUT_ATTEMPTS - user.failed_attempts
                messages.error(
                    request,
                    f"Usuário ou senha inválidos. {remaining_attempts} tentativas restantes.",
                )
            user.save()

    return render(request, "login.html", {"level": 2})


def login_level3(request):
    """
    Nível 3: Login com senha que redireciona para verificação 2FA.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Senha correta. Não faz login ainda.
            # Armazena o ID do usuário na sessão para a próxima etapa.
            request.session["2fa_user_id"] = user.id
            return redirect("verify_2fa")
        else:
            messages.error(request, "Usuário ou senha inválidos.")

    return render(request, "login.html", {"level": 3})


def verify_2fa(request):
    """
    Verifica o código TOTP após o login com senha bem-sucedido.
    """
    user_id = request.session.get("2fa_user_id")
    if not user_id:
        return redirect("login_level3")  # Redireciona se não houver usuário na sessão

    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return redirect("login_level3")

    if request.method == "POST":
        token = request.POST.get("token")
        totp = pyotp.TOTP(user.two_factor_secret)

        if totp.verify(token):
            # Código 2FA correto. Limpa a sessão e faz o login.
            del request.session["2fa_user_id"]
            login(request, user)
            messages.success(
                request, f"Bem-vindo, {user.username}! (Login Nível 3 com 2FA)"
            )
            return redirect("home")
        else:
            messages.error(request, "Código de verificação inválido.")

    return render(request, "verify_2fa.html")


# Uma view simples para a página inicial após o login
def home(request):
    return render(request, "home.html")
