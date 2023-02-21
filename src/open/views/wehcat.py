# -*- coding: utf-8 -*-
import requests
import json
import time
from xmltodict import parse, unparse
from rest_framework.viewsets import ModelViewSet
from src.utils.json_response import DetailResponse, SuccessResponse, ErrorResponse
from rest_framework.response import Response
from django.http import HttpResponse
from src.utils.serializers import CustomModelSerializer
from src.open.models import WechatPayOrder
from src.system.views.user import Users, UserCreateSerializer
from captcha.views import CaptchaStore
from src.utils.wechat_util import we_chat_pay_request, we_chat_pay_verify_notify, we_chat_mp_request, verify_mp_config
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView


class WeChatPaySerializer(CustomModelSerializer):
    """
    -序列化器
    """
    class Meta:
        model = WechatPayOrder
        fields = "__all__"


class WechatMessageViewSet(ModelViewSet):
    """
    """
    permission_classes = []
    serializer_class = WeChatPaySerializer

    def msg_adapter(self, msg):
        msg = parse(msg)
        msg_type = msg['xml']['MsgType']
        result = ({
            "xml": {
                "ToUserName": msg['xml']['FromUserName'],
                "FromUserName": msg['xml']['ToUserName'],
                "CreateTime": f'${int(time.time())}',
                "MsgType": "text",
            }
        })
        if (msg_type == 'event'):
            # 事件消息
            event_type = msg['xml']['Event']
            if (event_type == 'SCAN'):
                openid = msg['xml']['FromUserName']
                instance = Users.objects.filter(username=openid).first()
                if (instance):
                    # 登录
                    print(instance)
                    result['xml']['Content'] = '登录成功！'
                else:
                    # 注册
                    user_serializer = UserCreateSerializer(data={
                        'username': openid,
                        'openid': openid,
                        'name': '普通会员'
                    })
                    if (user_serializer.is_valid()):
                        user_serializer.save()
                        result['xml']['Content'] = '恭喜，注册成功！'
                # CaptchaStore.objects.filter(hashkey='').first().delete()
                # Users.objects.filter()
        else:
            # 普通消息
            result['xml']['Content'] = '嫩哇犀利哦，提昂北洞哟'
        return unparse(result)

    def mp_message(self, request):
        """微信公众号消息"""
        is_verify, echostr = verify_mp_config(request)
        if is_verify:
            if echostr:
                # 认证处理
                return HttpResponse(echostr)
            else:
                # 消息处理
                return HttpResponse(self.msg_adapter(request.body))

        else:
            return ErrorResponse(msg='验证不通过')

    def pay_message(self, request):
        """微信支付消息"""       
        result = we_chat_pay_verify_notify(request)
        print(result)
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


class WechatViewSet(ModelViewSet):
    """
    """
    serializer_class = WeChatPaySerializer

    def mp_request(self, request, path):
        """微信公众号"""
        data = we_chat_mp_request(request)
        if isinstance(data, str):
            data = json.loads(data)
        return DetailResponse(data=data)

    def pay_requeset(self, request, path):
        """微信支付API"""
        data = we_chat_pay_request(request)
        return DetailResponse(data=json.loads(data))
