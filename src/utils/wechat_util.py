"""
微信工具类
"""
import json
import requests
import uuid
import time
import hashlib
from copy import deepcopy
from datetime import datetime
from urllib.parse import urlencode
from user_agents import parse
from base64 import b64decode, b64encode
from logging import getLogger
from django.core.cache import cache  # 引入缓存模块
from src.utils.json_response import ErrorResponse
from application.settings import WECHAT_PAY_URL, WECHAT_PAY_MCHID, WECHAT_MP_APPID, BASE_DIR, WECHAT_PAY_CERT_NO, WECHAT_PAY_V3KEY, WECHAT_MP_URL, WECHAT_MP_SECRET
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP, PKCS1v15
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SM3, Hash
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
global _PRIVATE_KEY
global _PUBLIC_KEY
logger = getLogger(__name__)

with open(str(BASE_DIR)+'/cert/apiclient_key.pem') as f:
    _PRIVATE_KEY = f.read()
    f.close()
with open(str(BASE_DIR)+'/cert/apiclient_cert.pem') as f:
    _PUBLIC_KEY = f.read()
    f.close()


# 微信公众号相关


def do_request(**keywords):
    """请求base"""
    response = requests.request(**keywords)
    if response.status_code == 200:
        return response.text if 'application/json' in response.headers.get('Content-Type') else response.content
    else:
        return ErrorResponse(msg=response.text)


def verify_mp_config(request):
    """微信公众号配置验证"""
    signature = request.query_params.get('signature')
    timestamp = request.query_params.get('timestamp')
    nonce = request.query_params.get('nonce')
    echostr = request.query_params.get('echostr')
    auth_list = [WECHAT_PAY_V3KEY, timestamp, nonce]
    auth_list.sort()
    signature_str = (''.join(auth_list))
    sha = hashlib.sha1(signature_str.encode('utf-8'))
    encrypts = sha.hexdigest()
    if encrypts == signature:
        return True, echostr
    else:
        return False


def we_chat_mp_access_token_task():
    """获取access token"""
    params = {
        'grant_type': 'client_credential',
        'appid': WECHAT_MP_APPID,
        'secret': WECHAT_MP_SECRET
    }
    headers = {
        'Content-Type': 'application/json; encoding=utf-8'
    }
    try:
        data = do_request(method='GET', url=f'{WECHAT_MP_URL}/cgi-bin/token',
                          params=params, headers=headers, data=None)
        data = json.loads(data)
        access_token = data.get('access_token')
        expires_in = data.get('expires_in')
        cache.set('access_token', access_token, expires_in)
        return data
    except Exception as e:
        return e


def we_chat_mp_request(request):
    """微信公公众号集成"""
    try:
        access_token = cache.get('access_token')
        if not access_token:
            data = we_chat_mp_access_token_task()
            access_token = cache.get('access_token')
        if access_token:
            headers = request.headers
            data = request.data 
            print(data)
            data = json.dumps(data)
            method = request.method
            params = deepcopy(request.GET)
            params['access_token'] = cache.get('access_token')
            path = str(request.path).rsplit('wechatmp', 1)[-1]
            url = f'{WECHAT_MP_URL}{path}'
            return do_request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers)
        else:
            return data
    except Exception as e:
        print(e)
        # 处理异常情况
        return ErrorResponse(msg=e)


# 微信支付相关
def get_order_string(include_timestamp=True):
    "生产订单号"
    now = datetime.now().strftime('%Y%m%d%H%M%S')
    unique_id = str(uuid.uuid4()).replace('-', '') + now
    unique_id = unique_id[-32:]
    return unique_id


def we_chat_pay_verify_notify(request):
    """校验微信通知"""
    headers = request.headers
    print('headers',request.headers)
    print('data',request.data)
    body = request.data
    signature = headers.get('Wechatpay-Signature')
    timestamp = headers.get('Wechatpay-Timestamp')
    nonce = headers.get('Wechatpay-Nonce')
    serial_no = headers.get('Wechatpay-Serial')
    is_verify = rsa_verify(timestamp, nonce, body, signature)
    if is_verify:
        data = json.loads(body)
        resource_type = data.get('resource_type')
        if resource_type != 'encrypt-resource':
            return None
        resource = data.get('resource')
        if not resource:
            return None
        algorithm = resource.get('algorithm')
        if algorithm != 'AEAD_AES_256_GCM':
            raise Exception('does not support this algorithm')
        nonce = resource.get('nonce')
        ciphertext = resource.get('ciphertext')
        associated_data = resource.get('associated_data')
        if not (nonce and ciphertext):
            return None
        if not associated_data:
            associated_data = ''
        result = aes_decrypt(
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=associated_data,
        )
        return result


def we_chat_pay_request(request):
    """
    请求微信支付的接口
    使用方法修改请求地址转发到对应的微信支付地址
    https://api.mch.weixin.qq.com/v3/pay/transactions/native
    http://localhost:8000/open/wechatpay/v3/pay/transactions/native
    http://localhost:8000/open/wechatpay 为当前接口地址
    /v3/pay/transactions/native 转发地址
    处理公告参数
    转发数据地址
    """
    PRIVATE_KEY = load_private_key(_PRIVATE_KEY)
    try:
        # 获取请求参数
        params = request.GET
        # 获取请求方法 . (GET or POST)
        method = request.method
        if (method == 'POST'):
            # 获取完整的请求报文
            data = json.loads((request.body)) if request.body else {}
            data['mchid'] = WECHAT_PAY_MCHID
            data['appid'] = WECHAT_MP_APPID
            data = json.dumps(data)
        elif (method == 'GET'):
            data = None
        # 获取请求地址 别截取后半部分
        path = request.path
        path = str(path).rsplit('wechatpay', 1)[-1]
        # url 拼接
        params_str = f'?{urlencode(params)}' if urlencode(params) else ''
        url = f'{WECHAT_PAY_URL}{path}'
        search = path+params_str
        # 签名
        authorization = build_authorization(search, method,
                                            WECHAT_PAY_MCHID, WECHAT_PAY_CERT_NO, PRIVATE_KEY, data)
        # 设置签名到header
        headers = {
            'Authorization': authorization,
            'Content-Type': request.headers['Content-Type']
        }
        # 请求微信支付接口
        return do_request(
            method=method, url=url, headers=headers, params=params, data=data)
        # return response.status_code, response.text if 'application/json' in response.headers.get('Content-Type') else response.content
    except Exception as e:
        # 处理异常情况
        return 'Fail Request %s' % (e)

# 构造签名信息

# 对应v3版微信支付api文档的[签名生成](https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_0.shtml)部分。


def build_authorization(path,
                        method,
                        mchid,
                        serial_no,
                        private_key,
                        data=None,
                        nonce_str=None):
    timeStamp = str(int(time.time()))
    nonce_str = nonce_str or ''.join(str(uuid.uuid4()).split('-')).upper()
    body = data if isinstance(data, str) else json.dumps(data) if data else ''
    sign_str = '%s\n%s\n%s\n%s\n%s\n' % (
        method, path, timeStamp, nonce_str, body)
    signature = rsa_sign(private_key=private_key, sign_str=sign_str)
    authorization = 'WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"' % (
        mchid, nonce_str, signature, timeStamp, serial_no)
    return authorization

# ## 验证签名

# 对应v3版微信支付api文档的[签名验证](https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_1.shtml)部分。


def rsa_sign(private_key, sign_str):
    message = sign_str.encode('UTF-8')
    signature = private_key.sign(
        data=message, padding=PKCS1v15(), algorithm=SHA256())
    sign = b64encode(signature).decode('UTF-8').replace('\n', '')
    return sign

# ## 回调信息解密

# 对应v3版微信支付api文档的[证书和回调报文解密](https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_2.shtml)部分。


def aes_decrypt(nonce, ciphertext, associated_data):
    key_bytes = WECHAT_PAY_V3KEY.encode('UTF-8')
    nonce_bytes = nonce.encode('UTF-8')
    associated_data_bytes = associated_data.encode('UTF-8')
    data = b64decode(ciphertext)
    aesgcm = AESGCM(key=key_bytes)
    try:
        result = aesgcm.decrypt(nonce=nonce_bytes, data=data,
                                associated_data=associated_data_bytes).decode('UTF-8')
    except InvalidTag:
        result = None
    return result


def format_private_key(private_key_str):
    pem_start = '-----BEGIN PRIVATE KEY-----\n'
    pem_end = '\n-----END PRIVATE KEY-----'
    if not private_key_str.startswith(pem_start):
        private_key_str = pem_start + private_key_str
    if not private_key_str.endswith(pem_end):
        private_key_str = private_key_str + pem_end
    return private_key_str


def load_certificate(certificate_str):
    try:
        return load_pem_x509_certificate(data=certificate_str.encode('UTF-8'), backend=default_backend())
    except:
        return None


def load_private_key(private_key_str):
    try:
        return load_pem_private_key(data=format_private_key(private_key_str).encode('UTF-8'), password=None, backend=default_backend())
    except:
        raise Exception('failed to load private key.')

# ## 敏感信息加密

# 对应v3版微信支付api文档的[敏感信息加解密](https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_3.shtml)的加密部分。


def rsa_verify(timestamp, nonce, body, signature):
    certificate = load_certificate(_PUBLIC_KEY)
    sign_str = '%s\n%s\n%s\n' % (timestamp, nonce, body)
    public_key = certificate.public_key()
    print(public_key)
    print(public_key)
    message = sign_str.encode('UTF-8')
    signature = b64decode(signature)
    try:
        public_key.verify(signature, message, PKCS1v15(), SHA256())
    except InvalidSignature:
        return False
    return True


def rsa_encrypt(text, certificate):
    certificate = load_certificate(_PUBLIC_KEY)
    data = text.encode('UTF-8')
    public_key = certificate.public_key()
    cipherbyte = public_key.encrypt(
        plaintext=data,
        padding=OAEP(mgf=MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None)
    )
    return b64encode(cipherbyte).decode('UTF-8')


# ## 敏感信息解密

# 对应v3版微信支付api文档的[敏感信息加解密](https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay4_3.shtml)的解密部分。

def rsa_decrypt(ciphertext, private_key):
    data = private_key.decrypt(
        ciphertext=b64decode(ciphertext),
        padding=OAEP(mgf=MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None)
    )
    result = data.decode('UTF-8')
    return result


def hmac_sign(key, sign_str):
    hmac = HMAC(key.encode('UTF-8'), SHA256())
    hmac.update(sign_str.encode('UTF-8'))
    sign = hmac.finalize().hex().upper()
    return sign


def sha256(data):
    hash = Hash(SHA256())
    hash.update(data)
    return hash.finalize().hex()


def sm3(data):
    hash = Hash(SM3())
    hash.update(data)
    return hash.finalize().hex()
