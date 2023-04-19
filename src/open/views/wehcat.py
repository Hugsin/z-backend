# -*- coding: utf-8 -*-
import time
import logging
import json
from application.settings import *

from rest_framework.viewsets import ModelViewSet
from src.utils.json_response import DetailResponse, SuccessResponse, ErrorResponse
from rest_framework.response import Response
from django.http.response import HttpResponse
from src.utils.serializers import CustomModelSerializer
from src.open.models import PayOrder
from captcha.views import CaptchaStore

from src.utils.chat_gpt import chat_bot
from src.utils.request_util import save_login_log
from django.contrib.auth import authenticate, login, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

from src.lib.wechatpy.crypto import WeChatCrypto
from src.lib.wechatpy import parse_message, create_reply
from src.lib.wechatpy.utils import check_signature
from src.lib.wechatpy.exceptions import InvalidSignatureException, WeChatClientException
from src.lib.wechatpy.exceptions import InvalidAppIdException
from src.lib.wechatpy.client import WeChatClient
from src.lib.wechatpy.oauth import WeChatOAuth
from django.core.cache import cache
from concurrent.futures import ThreadPoolExecutor
from src.lib.wechatpayv3 import WeChatPay, WeChatPayType


UserModel = get_user_model()


class Singleton:
    client = None
    auth_client = None
    executor = None
    wxpay = None

    def __new__(self):
        if self.client is None:
            self.client = WeChatClient(
                WECHAT_MP_APPID,
                WECHAT_MP_SECRET,
                session=cache
            )
        if self.auth_client is None:
            self.auth_client = WeChatOAuth(app_id=WECHAT_MP_APPID,
                                           secret=WECHAT_MP_SECRET,
                                           redirect_uri=WECHAT_MP_REDIRECT_URI)
        if self.wxpay is None:
            cert_path = f'{BASE_DIR}/conf/cert'
            with open(f'{cert_path}/apiclient_key.pem') as f:
                PRIVATE_KEY = f.read()
            self.wxpay = WeChatPay(
                wechatpay_type=WeChatPayType.NATIVE,
                mchid=WECHAT_PAY_MCHID,
                private_key=PRIVATE_KEY,
                cert_serial_no=WECHAT_PAY_CERT_NO,
                apiv3_key=WECHAT_PAY_V3KEY,
                appid=WECHAT_PAY_APPID,
                notify_url=WECHAT_PAY_NOTIFY_URL,
                cert_dir=cert_path,
                logger=logging.getLogger("wxpay"),
                partner_mode=False,
                proxy=None)
        if self.executor is None:
            self.executor = ThreadPoolExecutor(max_workers=100)
        return self


class WeChatPaySerializer(CustomModelSerializer):
    """
    -序列化器
    """
    class Meta:
        model = PayOrder
        fields = "__all__"


class WechatViewSet(ModelViewSet):
    """
    """
    serializer_class = WeChatPaySerializer
    permission_classes = []
    client = None
    auth_client = None
    executor = None
    wxpay = None

    def __init__(self, **kwargs) -> None:
        singleton = Singleton()
        self.client = singleton.client
        self.auth_client = singleton.auth_client
        self.executor = singleton.executor
        self.wxpay = singleton.wxpay

    def pay_requeset(self, requests, oar):
        out_trade_no = '26a4435196871ff30d2023021612502'
        description = '测试'
        amount = 1
        order = {
            'out_trade_no': out_trade_no,
            'trade_type': WeChatPayType.NATIVE.name,
            'trade_state': 'NOTPAY',
            'trade_state_desc': '',
            'bank_type': '',
            'attach': '',
            'success_time': '',
            'payer': '',
            'total': 1,
        }
        instance, created = PayOrder.objects.update_or_create(
            out_trade_no=out_trade_no, defaults=order)
        try:
            code, response = self.wxpay.pay(
                description=description,
                out_trade_no=instance.out_trade_no,
                amount={'total': instance.total},
                pay_type=WeChatPayType.NATIVE
            )
            result = json.loads(response)
            if code == 200:
                code_url = result.get('code_url', '')
                return SuccessResponse(data={
                    'out_trade_no': out_trade_no,
                    'code_url': code_url,
                })
            else:
                result = json.loads(response)
                return ErrorResponse(msg=result.get('message'), data=result)
        except BaseException as e:
            return ErrorResponse(msg=str(e))


class WechatMessageViewSet(ModelViewSet):
    """
    """
    permission_classes = []
    serializer_class = WeChatPaySerializer
    client = None
    auth_client = None
    executor = None
    wxpay = None

    def __init__(self, **kwargs) -> None:
        singleton = Singleton()
        self.client = singleton.client
        self.auth_client = singleton.auth_client
        self.executor = singleton.executor
        self.wxpay = singleton.wxpay

    # menu = client.menu.create({
    #     "button": [
    #         {
    #             "name": "门店·目录",
    #             "sub_button": [
    #                 {
    #                     "type": "view",
    #                     "name": "淘宝小店",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "view",
    #                     "name": "小红书小店",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "view",
    #                     "name": "抖音小店",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "miniprogram",
    #                     "name": "微信小商店",
    #                     "appid": "wx4d53dd0e53dd5527",
    #                     "pagepath": "/pages/index/index",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 }, {
    #                     "type": "view",
    #                     "name": "拼多多店铺",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #             ]
    #         },
    #         {
    #             "name": "新品·热卖",
    #             "sub_button": [

    #                 {
    #                     "type": "view",
    #                     "name": "饰品元件",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "view",
    #                     "name": "最热单品",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "view",
    #                     "name": "轻奢主义",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 },
    #                 {
    #                     "type": "view",
    #                     "name": "最新单品",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 }, {
    #                     "type": "view",
    #                     "name": "私人定制",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 }
    #             ]
    #         },
    #         {
    #             "name": "会员·福利",
    #             "sub_button": [
    #                 {
    #                     "type": "view",
    #                     "name": "福利商场",
    #                     "url": "https://x2111n2k.jutuike.cn/#/?code=X2111N2k"
    #                 }, {
    #                     "type": "miniprogram",
    #                     "name": "福利小程序",
    #                     "appid": "wxc06f08cd947ff16a",
    #                     "pagepath": "/pages/index/index",
    #                     "url": "http://shop0016.cn/9Io13M"
    #                 }, {
    #                     "type": "view",
    #                     "name": "推荐好礼",
    #                     "url": "https://www.tigerzh.com/shiniya/xxx"
    #                 }, {
    #                     "type": "view",
    #                     "name": "积分充值",
    #                     "url": "https://www.tigerzh.com/shiniya/xxx"
    #                 }, {
    #                     "type": "view",
    #                     "name": "我的会员",
    #                     "url": "https://www.tigerzh.com/shiniya/xxx"
    #                 }
    #             ]
    #         },
    #     ]
    # })

    def valid_hashkey(self, hashkey):
        return CaptchaStore.objects.filter(hashkey=hashkey).first()

    def mp_message(self, request):
        """微信公众号消息"""
        try:
            signature = request.GET.get("signature", "")
            timestamp = request.GET.get("timestamp", "")
            nonce = request.GET.get("nonce", "")
            echo_str = request.GET.get("echostr", "")
            encrypt_type = request.GET.get("encrypt_type", "")
            msg_signature = request.GET.get("msg_signature", "")
            check_signature(WECHAT_MP_TOKEN, signature, timestamp, nonce)
        except InvalidSignatureException:
            return ErrorResponse(msg='签名失败')
        if request.method == 'GET':
            return HttpResponse(echo_str)
        else:
            crypto = WeChatCrypto(
                WECHAT_MP_TOKEN, WECHAT_MP_AES, WECHAT_MP_APPID)
            msg = request.body.decode('utf-8')
            try:
                msg = crypto.decrypt_message(
                    request.body.decode('utf-8'), msg_signature, timestamp, nonce)
            except (InvalidSignatureException, InvalidAppIdException) as e:
                return ErrorResponse(msg='签名失败', data={})
            msg = parse_message(msg)
            if msg.type == "text":
                reply = create_reply('', msg)
            elif msg.type == "event":
                if msg.event == 'unsubscribe':
                    return ErrorResponse(msg='取消关注', data={})
                elif msg.event == 'subscribe':
                    def sendsubscribe(user_id, content, delay):
                        time.sleep(delay)
                        self.client.message.send_text(
                            user_id=user_id, content=content)
                    message = '💖 小主，欢迎关注饰你呀\n\n 👉 <a href="http://shop0016.cn/9Io13M">淘宝小店</a>　\n\n<a  href="https://x2111n2k.jutuike.cn/#/?code=X2111N2k">更多福利>></a>'
                    # self.executor.submit(sendsubscribe, msg.source,
                    #                      '输入咒语 轻松成为GPT高级玩家\n\n例如\n充当全栈软件开发人员咒语\n\n我想让你充当软件开发人员。我将提供一些关于 Web 应用程序要求的具体信息，您的工作是提出用于使用 Golang 和 Angular 开发安全应用程序的架构和代码。我的第一个要求是"我想要一个允许用户根据他们的角色注册和保存他们的车辆信息的系统，并且会有管理员，用户和公司角色。我希望系统使用 JWT 来确保安全。"\n\n 更多咒语请探索<a href="https://ai.tigerzh.com/document/chatGPT/%E9%A2%84%E8%AE%BE%E8%A7%92%E8%89%B2%E5%92%92%E8%AF%AD.html">文档</a>', 1)
                elif msg.event == 'subscribe_scan':
                    message = login(
                        msg.scene_id, msg._data['FromUserName'], request=request)
                elif msg.event == 'scan':
                    message = login(
                        msg.scene_id, msg._data['FromUserName'], request=request)
                else:
                    return HttpResponse(create_reply(None))
                reply = create_reply(message, msg)
            else:
                reply = create_reply(
                    "Sorry, can not handle this for now", msg)
            # message = reply
            message = crypto.encrypt_message(
                reply.render(), nonce, timestamp)
            return HttpResponse(message)

    def pay_message(self, request):
        """微信支付消息"""
        headers = {}
        headers.update(
            {'Wechatpay-Signature': request.META.get('HTTP_WECHATPAY_SIGNATURE')})
        headers.update(
            {'Wechatpay-Timestamp': request.META.get('HTTP_WECHATPAY_TIMESTAMP')})
        headers.update(
            {'Wechatpay-Nonce': request.META.get('HTTP_WECHATPAY_NONCE')})
        headers.update(
            {'Wechatpay-Serial': request.META.get('HTTP_WECHATPAY_SERIAL')})
        result = self.wxpay.callback(request.headers, request.body)
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
            payer = resp.get('payer').get('openid')
            amount = resp.get('amount').get('total')
            order = PayOrder.objects.filter(out_trade_no=out_trade_no).first()
            order.appid = appid
            order.mchid = mchid
            order.transaction_id = transaction_id
            order.trade_type = trade_type
            order.trade_state = trade_state
            order.trade_state_desc = trade_state_desc
            order.bank_type = bank_type
            order.attach = attach
            order.success_time = success_time
            order.payer = payer
            order.total = amount
            order.save()
            return Response({'code': 'SUCCESS', 'message': '成功'})
        else:
            return Response({'code': 'FAILED', 'message': '失败'})
