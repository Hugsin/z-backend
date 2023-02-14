# -*- coding: utf-8 -*-
from django.urls import path
from application.websocketConfig import MegCenter

websocket_urlpatterns = [
    path('ws/<str:service_uid>/', MegCenter.as_asgi()), #consumers.srcWebSocket 是该路由的消费者
]

