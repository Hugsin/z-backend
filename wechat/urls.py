from django.urls import *
from rest_framework.routers import *
from .views import WechatViewset

router = DefaultRouter()

urlpatterns = [
    re_path(r'auth', WechatViewset.as_view(
        {'get': 'auth'})),
]

urlpatterns += router.urls
