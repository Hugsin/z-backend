from apps.celery import *
import time
from .do_fetch_nunu_tabs import *
from .do_fetch_nunu_detail import *
from .models import *
from .serializers import *


@app.task
def do_fetch_tabs():
    """运行测试的定时任务"""
    main()
    return "用例执行完成"


@app.task
def do_fetch_detail():
    """运行测试的定时任务"""
    nunu_detail_main()
    return "用例执行完成"
