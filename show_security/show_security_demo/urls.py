from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("logout/", views.user_logout, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    # Níveis de Login
    path("login/level1/", views.login_level1, name="login_level1"),
    path("login/level2/", views.login_level2, name="login_level2"),
    path("login/level3/", views.login_level3, name="login_level3"),
    path("verify_2fa/", views.verify_2fa, name="verify_2fa"),
]
