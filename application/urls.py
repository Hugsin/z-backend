"""backend URL Configuration

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
from django.conf.urls.static import static
from django.urls import path, include, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

from application import dispatch
from application import settings
from src.system.views.dictionary import InitDictionaryViewSet
from src.system.views.login import (
    LoginView,
    QrLoginView,
    CaptchaView,
    ApiLogin,
    LogoutView,

)
from src.system.views.system_config import InitSettingsViewSet
from src.utils.swagger import CustomOpenAPISchemaGenerator

# =========== 初始化系统配置 =================
dispatch.init_system_config()
dispatch.init_dictionary()
# =========== 初始化系统配置 =================

schema_view = get_schema_view(
    openapi.Info(
        title="ZORG API",
        default_version="v3",
        description="在美好的路上不期而遇",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="only_tigerhu@163.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    generator_class=CustomOpenAPISchemaGenerator,
)

urlpatterns = (
    [
        re_path(
            r"^swagger(?P<format>\.json|\.yaml)$",
            schema_view.without_ui(cache_timeout=0),
            name="schema-json",
        ),
        path(
            "",
            schema_view.with_ui("swagger", cache_timeout=0),
            name="schema-swagger-ui",
        ),
        path(
            r"redoc",
            schema_view.with_ui("redoc", cache_timeout=0),
            name="schema-redoc",
        ),
        path("system", include("src.system.urls")),
        path("open", include("src.open.urls")),
        path("login", LoginView.as_view(), name="token_obtain_pair"),
        path("logout", LogoutView.as_view(), name="token_obtain_pair"),
        path("token/refresh", TokenRefreshView.as_view(),
             name="token_refresh"),
        re_path(
            r"^api-auth", include("rest_framework.urls",
                                   namespace="rest_framework")
        ),
        path("captcha", CaptchaView.as_view()),
        path("qrlogin", QrLoginView.as_view()),
        # path("qrlogin/", CaptchaView.as_view({'get', 'qrlogin'})),
        path("init/dictionary", InitDictionaryViewSet.as_view()),
        path("init/settings", InitSettingsViewSet.as_view()),
        path("apiLogin", ApiLogin.as_view()),
        re_path(r'^admin', admin.site.urls),
    ]
    + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    + static(settings.STATIC_URL, document_root=settings.STATIC_URL))
