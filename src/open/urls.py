from django.urls import re_path, path
from rest_framework import routers

from src.open.views.projects import ProjectsViewSet
from src.open.views.wehcat import WechatViewSet

system_url = routers.SimpleRouter()
system_url.register(r'projects', ProjectsViewSet)

urlpatterns = [
    re_path(r'^wechatpay(/.*)?$', WechatViewSet.as_view({
        'get': 'pay_requeset',
        'post': 'pay_requeset',
        'put': 'pay_requeset',
        'patch': 'pay_requeset',
        'delete': 'pay_requeset',
    })),
    re_path(r'^wechatmp(/.*)?$', WechatViewSet.as_view({
        'get': 'mp_request',
        'post': 'mp_request',
        'put': 'mp_request',
        'patch': 'mp_request',
        'delete': 'mp_request',
    })),
    path(r'notify', WechatViewSet.as_view({
        'get': 'pay_notify',
        'post': 'pay_notify',
        'put': 'pay_notify',
        'patch': 'pay_notify',
        'delete': 'pay_notify',
    })),
]
urlpatterns += system_url.urls
