from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from django.views.decorators.http import require_http_methods
from django.apps import apps  # IMPORTANTE: Para obter o modelo dinamicamente
import pyotp
import time
import os

# --- NÃO USAR AQUI: Deixe a busca do modelo para dentro das views ---
# CustomUser = get_user_model()

# --- Constantes (Em produção, estas estariam no settings.py) ---
LOCKOUT_DURATION_MINUTES = 5
MAX_FAILED_ATTEMPTS = 5
# -----------------------------------------------------------------


# Helper para obter o modelo customizado (Busca dinâmica)
def get_custom_user_model():
    # Isso resolve o modelo a partir do registro de apps do Django (Settings)
    return apps.get_model("show_security_demo", "CustomUser")


# Restante do get_client_ip, home, dashboard, logout: (sem alterações na estrutura)
def get_client_ip(request):
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
    if request.method == "POST":
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
    if "simulated_ip" in request.session:
        del request.session["simulated_ip"]
    messages.success(request, "Sessão encerrada com sucesso.")
    return redirect("home")


# --- VIEW DE REGISTRO DE USUÁRIO ---


@require_http_methods(["GET", "POST"])
def register_user(request):
    User = get_custom_user_model()  # Busca o modelo aqui
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        email = request.POST.get("email", f"{username}@demo.com")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Nome de usuário já existe.")
            return render(request, "register.html")

        try:
            # Usa o CustomUser.objects.create_user para hashear a senha
            user = User.objects.create_user(
                username=username, password=password, email=email
            )

            # Preenche o campo de texto simples
            user.insecure_password_plaintext = password

            # Para Nível 3 (Futuro): Cria um segredo 2FA básico
            user.two_factor_secret = pyotp.random_base32()
            user.save()

            messages.success(
                request,
                "Conta criada com sucesso! Você pode usar as credenciais nos Níveis de Login.",
            )
            return redirect("home")

        except Exception as e:
            messages.error(request, f"Erro ao criar conta: {e}")
            return render(request, "register.html")

    return render(request, "register.html")


# --- VIEWS DE LOGIN ---


@require_http_methods(["GET", "POST"])
def login_level1(request):
    User = get_custom_user_model()  # Busca o modelo aqui
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Usuário ou senha inválidos.")
            return render(request, "login.html", {"level": 1})

        # VULNERABILIDADE: Verifica a senha em texto simples!
        # Agora o erro SÓ pode ocorrer se a tabela não foi migrada ou se o usuário não tem o campo
        if password == user.insecure_password_plaintext:
            login(request, user)
            messages.success(request, "Login Nível 1 bem-sucedido (VULNERÁVEL!).")
            return redirect("dashboard")
        else:
            messages.error(request, "Senha inválida. Tente novamente.")

    return render(request, "login.html", {"level": 1})


@require_http_methods(["GET", "POST"])
def login_level2(request):
    User = get_custom_user_model()  # Busca o modelo aqui
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Credenciais inválidas.")
            time.sleep(1)
            return render(request, "login.html", {"level": 2})

        if user.is_locked_out():
            wait_time = int((user.lockout_time - timezone.now()).total_seconds())
            messages.warning(
                request, f"Conta bloqueada. Tente novamente em {wait_time} segundos."
            )
            return render(request, "login.html", {"level": 2})

        if user.check_password(password):
            user.failed_attempts = 0
            user.lockout_time = None
            user.save()

            login(request, user)
            messages.success(request, "Login Nível 2 bem-sucedido (Seguro!).")
            return redirect("dashboard")
        else:
            user.failed_attempts += 1
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
            time.sleep(1)

    return render(request, "login.html", {"level": 2})


@require_http_methods(["GET", "POST"])
def login_level3(request):
    # Usando authenticate, que usa get_user_model() internamente
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(
                request, "Login Nível 3 bem-sucedido (2FA ignorado na demo)."
            )
            return redirect("dashboard")
        else:
            messages.error(request, "Credenciais inválidas.")

    return render(request, "login.html", {"level": 3})


@require_http_methods(["GET", "POST"])
def verify_2fa(request):
    messages.info(request, "Funcionalidade 2FA desabilitada na demo atual.")
    return redirect("home")
