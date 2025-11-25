from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("show_security_demo.urls")),  # Inclui as URLs do nosso app
]
