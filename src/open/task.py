from celery import shared_task
from src.utils.wechat_util import we_chat_mp_assess_token_task
from django.core.cache import cache  # 引入缓存模块


@shared_task
def get_we_chat_mp_assess_token_task():
    response = we_chat_mp_assess_token_task()
    if response.text:
        data = response.json()
        access_token = data.get('access_token')
        expires_in = data.get('expires_in')
        cache.set('access_token', access_token, expires_in)
        return True
