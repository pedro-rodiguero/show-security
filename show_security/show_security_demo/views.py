# show_security_demo/views.py

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.views.decorators.http import require_http_methods
import pyotp
import time
import os

CustomUser = get_user_model()

# --- Helpers e Rotas Padrão ---


def get_client_ip(request):
    """
    Obtém o IP real do cliente.
    Em ambiente de desenvolvimento, verifica a sessão para o IP simulado.
    """
    if "simulated_ip" in request.session:
        return request.session["simulated_ip"]

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")

    if "original_ip" not in request.session:
        request.session["original_ip"] = ip

    return ip


@require_http_methods(["GET", "POST"])
def home(request):
    """
    Página inicial com os botões de seleção de nível e controle de IP.
    """
    if request.method == "POST":
        # Lógica de simulação de IP
        new_ip = request.POST.get("new_ip_address")
        if new_ip:
            request.session["simulated_ip"] = new_ip
            messages.info(request, f"IP simulado alterado com sucesso para: {new_ip}.")
            return redirect("home")

    current_ip = get_client_ip(request)

    context = {
        "current_ip": current_ip,
        "is_authenticated": request.user.is_authenticated,
    }
    return render(request, "home.html", context)


def dashboard(request):
    """Página de sucesso após login."""
    if not request.user.is_authenticated:
        return redirect("home")

    current_ip = get_client_ip(request)

    return render(
        request,
        "dashboard.html",
        {"username": request.user.username, "current_ip": current_ip},
    )


def user_logout(request):
    logout(request)
    # Limpar IP simulado ao sair
    if "simulated_ip" in request.session:
        del request.session["simulated_ip"]
    messages.success(request, "Sessão encerrada com sucesso.")
    return redirect("home")


# --- NÍVEL 1: INSEGURO (BRUTE FORCE) ---


@require_http_methods(["GET", "POST"])
def login_level1(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            messages.error(request, "Usuário ou senha inválidos.")
            return render(request, "login.html", {"level": 1})

        # VULNERABILIDADE: Verifica a senha em texto simples!
        if password == user.insecure_password_plaintext:
            login(request, user)
            messages.success(request, "Login Nível 1 bem-sucedido (VULNERÁVEL!).")
            return redirect("dashboard")
        else:
            # Não há limite de tentativas; o atacante pode tentar infinitamente.
            messages.error(request, "Senha inválida. Tente novamente.")

    return render(request, "login.html", {"level": 1})


# --- NÍVEL 2: INTERMEDIÁRIO (RATE LIMIT) ---


@require_http_methods(["GET", "POST"])
def login_level2(request):
    # Valores de segurança definidos no models.py
    LOCKOUT_DURATION_MINUTES = 5
    MAX_FAILED_ATTEMPTS = 5

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            messages.error(request, "Credenciais inválidas.")
            time.sleep(1)
            return render(request, "login.html", {"level": 2})

        # 1. VERIFICAÇÃO DE BLOQUEIO (LOCKOUT)
        if user.is_locked_out():
            wait_time = int((user.lockout_time - timezone.now()).total_seconds())
            messages.warning(
                request, f"Conta bloqueada. Tente novamente em {wait_time} segundos."
            )
            return render(request, "login.html", {"level": 2})

        # 2. AUTENTICAÇÃO SEGURA (Usando check_password do Django)
        if user.check_password(password):
            # Login bem-sucedido: Reseta o contador
            user.failed_attempts = 0
            user.lockout_time = None
            user.save()

            login(request, user)
            messages.success(request, "Login Nível 2 bem-sucedido (Seguro!).")
            return redirect("dashboard")
        else:
            # Login falhou: Incrementa o contador
            user.failed_attempts += 1

            # 3. BLOQUEIO DE CONTA (LOCKOUT LOGIC)
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.lockout_time = timezone.now() + timedelta(
                    minutes=LOCKOUT_DURATION_MINUTES
                )
                messages.error(
                    request,
                    f"Muitas tentativas. Conta bloqueada por {LOCKOUT_DURATION_MINUTES} minutos.",
                )
            else:
                messages.error(
                    request,
                    f"Senha inválida. Tentativas restantes: {MAX_FAILED_ATTEMPTS - user.failed_attempts}.",
                )

            user.save()
            time.sleep(1)  # Adiciona um atraso fixo

    return render(request, "login.html", {"level": 2})


# --- NÍVEL 3: AVANÇADO (2FA) ---


@require_http_methods(["GET", "POST"])
def login_level3(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            messages.error(request, "Credenciais inválidas.")
            return render(request, "login.html", {"level": 3})

        # 1. Verificação de Senha (Primeiro Fator)
        if user.check_password(password):
            # Armazena temporariamente o ID do usuário na sessão
            request.session["2fa_user_id"] = user.id
            request.session["2fa_authenticated"] = True

            messages.info(request, "Primeiro fator bem-sucedido. Insira o código 2FA.")
            return redirect("verify_2fa")
        else:
            messages.error(request, "Senha inválida.")

    return render(request, "login.html", {"level": 3})


@require_http_methods(["GET", "POST"])
def verify_2fa(request):
    user_id = request.session.get("2fa_user_id")

    if not user_id or not request.session.get("2fa_authenticated"):
        messages.warning(request, "Acesso negado. Por favor, faça login novamente.")
        return redirect("home")

    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        messages.error(request, "Erro na sessão. Usuário não encontrado.")
        return redirect("home")

    if request.method == "POST":
        token = request.POST.get("token")

        if not user.two_factor_secret:
            messages.error(
                request,
                "2FA não configurado para este usuário. Entre em contato com o suporte.",
            )
            return redirect("home")

        # 1. VERIFICAÇÃO DO CÓDIGO TOTP
        totp = pyotp.TOTP(user.two_factor_secret)

        if totp.verify(token):
            # 2. Login Final e Limpeza da Sessão
            login(request, user)

            # Limpa chaves de 2FA
            if "2fa_user_id" in request.session:
                del request.session["2fa_user_id"]
            if "2fa_authenticated" in request.session:
                del request.session["2fa_authenticated"]

            messages.success(request, "Login Nível 3 bem-sucedido (2FA Ativo!).")
            return redirect("dashboard")
        else:
            messages.error(request, "Código 2FA inválido.")

    return render(request, "verify_2fa.html")
