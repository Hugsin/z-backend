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
from src.open.models import PayOrder
from src.system.views.user import Users, UserCreateSerializer
from captcha.views import CaptchaStore
from src.utils.wechat_util import wechat_instance
from src.utils.request_util import save_login_log
from django.contrib.auth import authenticate, login, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
UserModel = get_user_model()


class WeChatPaySerializer(CustomModelSerializer):
    """
    -序列化器
    """
    class Meta:
        model = PayOrder
        fields = "__all__"


class WechatMessageViewSet(ModelViewSet):
    """
    """
    permission_classes = []
    serializer_class = WeChatPaySerializer

    def valid_hashkey(self, hashkey):
        return CaptchaStore.objects.filter(hashkey=hashkey).first()

    def repley_event_message(self, request, msg):
        event_type = msg['xml']['Event']
        result = f'{event_type}了 收到啦，收到啦！'
        if (event_type == 'SCAN'):
            openid = msg['xml']['FromUserName']
            hashkey = msg['xml']['EventKey']
            result = '登录成功！'
            valid_hashkey_row = self.valid_hashkey(hashkey=hashkey)
            if valid_hashkey_row:
                valid_hashkey_row.delete()
                instance, created = UserModel.objects.get_or_create(
                    openid=openid,
                    defaults={
                        'username': openid,
                        'openid': openid,
                        'name': '普通会员',
                    })
                if created:
                    result = '注册成功'
                # 登录
                instance.last_login = timezone.now()
                instance.save()
                refresh = RefreshToken.for_user(instance)
                login(request, instance)
                save_login_log(request)
                result = f'{result}！refresh:{str(refresh)} access:{str(refresh.access_token)}'
            else:
                result = '二维码已过期！'
        return result

    def msg_adapter(self, request):
        msg = parse(request.body)
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
            result['xml']['Content'] = self.repley_event_message(
                request, msg=msg)
        else:
            # 普通消息
            result['xml']['Content'] = '嫩哇犀利哦，提昂北洞哟'
        return unparse(result)

    def mp_message(self, request):
        """微信公众号消息"""
        is_verify, echostr = wechat_instance.verify_mp_config(request)
        if is_verify:
            if echostr:
                # 认证处理
                return HttpResponse(echostr)
            else:
                # 消息处理
                return HttpResponse(self.msg_adapter(request))

        else:
            return ErrorResponse(msg='验证不通过')

    def pay_message(self, request):
        """微信支付消息"""
        result = wechat_instance.pay_verify_notify(request)
        result = json.loads(result)
        if result:
            appid = result.get('appid')
            mchid = result.get('mchid')
            out_trade_no = result.get('out_trade_no')
            transaction_id = result.get('transaction_id')
            trade_type = result.get('trade_type')
            trade_state = result.get('trade_state')
            trade_state_desc = result.get('trade_state_desc')
            bank_type = result.get('bank_type')
            attach = result.get('attach')
            success_time = result.get('success_time')
            payer = result.get('payer').get('openid')
            total = result.get('amount').get('total')
            PayOrder.objects.update_or_create(
                out_trade_no=out_trade_no,
                defaults={
                    'appid': appid,
                    'mchid': mchid,
                    'out_trade_no': out_trade_no,
                    'transaction_id': transaction_id,
                    'trade_type': trade_type,
                    'trade_state': trade_state,
                    'trade_state_desc': trade_state_desc,
                    'bank_type': bank_type,
                    'attach': attach,
                    'success_time': success_time,
                    'payer': payer,
                    'total': total,
                })
            return Response({'code': 'SUCCESS', 'message': '成功'})
        else:
            return Response({'code': 'FAILED', 'message': '失败'})


class WechatViewSet(ModelViewSet):
    """
    """
    serializer_class = WeChatPaySerializer
    permission_classes = []

    def mp_request(self, request, path):
        """微信公众号"""
        data = wechat_instance.mp_request(request)
        if isinstance(data, str):
            data = json.loads(data)
        return DetailResponse(data=data)

    def pay_requeset(self, request, path):
        """微信支付API"""
        data = wechat_instance.pay_request(request)
        if isinstance(data, str):
            return DetailResponse(data=json.loads(data))
        else:
            return DetailResponse(data=data.data)
