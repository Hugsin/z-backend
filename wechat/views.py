from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
import hashlib
# Create your views here.


class WechatViewset(ModelViewSet):
    def auth(self, request, *args, **kwargs):
        signature = request.query_params.get('signature')
        timestamp = request.query_params.get('timestamp')
        nonce = request.query_params.get('nonce')
        echostr = request.query_params.get('echostr')
        if signature:
            auth_list = ['iPHb20xtvBo6rIACXaFg13LTnSRD9Yez', timestamp, nonce]
            auth_list.sort()
            signature_str = (''.join(auth_list))
            sha = hashlib.sha1(signature_str.encode('utf-8'))
            encrypts = sha.hexdigest()
            return Response(encrypts == signature)
        else:
            return Response()
        