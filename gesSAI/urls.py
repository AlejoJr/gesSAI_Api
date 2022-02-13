"""gesSAI URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework.documentation import include_docs_urls

urlpatterns = [
    # Administración y autorizacion de la api
    path('admin/', admin.site.urls, name='admin'),
    path('docs/', include_docs_urls(title='GesSAI API')),
    path('api-auth/', include('rest_framework.urls'), name='rest_framework'),

    # Rutas de la API
    path('gessaiapi/v1/', include('gesSAI.router'), name='base_api'),
]
