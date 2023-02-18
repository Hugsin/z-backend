# -*- coding: utf-8 -*-
import requests
import json
from rest_framework.viewsets import ModelViewSet
from src.utils.json_response import DetailResponse, SuccessResponse, ErrorResponse
from rest_framework.response import Response
from src.utils.serializers import CustomModelSerializer
from src.open.models import WechatPayOrder
from django.http import HttpResponse
from src.utils.wechat_util import we_chat_pay_request, we_chat_pay_verify_notify, we_chat_mp_request, we_chat_mp_assess_token_task


class WeChatPaySerializer(CustomModelSerializer):
    """
    -序列化器
    """
    class Meta:
        model = WechatPayOrder
        fields = "__all__"


class WechatViewSet(ModelViewSet):
    """
    """
    permission_classes = []
    serializer_class = WeChatPaySerializer

    def mp_message(self, request, path):
        """微信公众号消息"""
        echostr = request.query_params.get('echostr')
        if echostr:
            return HttpResponse(echostr)
        else:
            # TODO 处理消息
            # resposne = we_chat_mp_request(request)
            return DetailResponse('')

    def mp_request(self, request, path):
        """微信公众号"""
        resposne = we_chat_mp_request(request)
        return DetailResponse(resposne)

    def pay_requeset(self, request, path):
        """微信支付API"""
        authorization = we_chat_pay_request(request)
        return DetailResponse(authorization)

    def pay_message(self, request):
        """微信支付消息"""
        result = we_chat_pay_verify_notify(request)
        if result and result.get('event_type') == 'TRANSACTION.SUCCESS':
            resp = result.get('resource')
            appid = resp.get('appid')
            mchid = resp.get('mchid')
            out_trade_no = resp.get('out_trade_no')
            transaction_id = resp.get('transaction_id')
            trade_type = resp.get('trade_type')
            trade_state = resp.get('trade_state')
            trade_state_desc = resp.get('trade_state_desc')
            bank_type = resp.get('bank_type')
            attach = resp.get('attach')
            success_time = resp.get('success_time')
            payer = resp.get('payer')
            amount = resp.get('amount').get('total')
            # TODO
            return Response({'code': 'SUCCESS', 'message': '成功'})
        else:
            return Response({'code': 'FAILED', 'message': '失败'})
