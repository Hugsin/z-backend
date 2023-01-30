from rest_framework.response import *
from .models import *
from .serializers import *
from .filter import *
from .tasks import *

from rest_framework.viewsets import ModelViewSet
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend



class MovieViewset(ModelViewSet):
    queryset = MovieModel.objects.all()
    serializer_class = MoiveSeriaizers
    filter_backends = (DjangoFilterBackend,OrderingFilter)
    filterset_class = MovieFilter
    filterset_fields = ['name']
    # search_fields = ['name']
    values_queryset = None
    ordering_fields = '__all__'
    ordering = ['-release_date']

    def do_task(self, request, *args, **kwargs):
        '''
        get: 执行任务
        input:
        - func: string
        '''
        do_fetch_tabs.delay()
        do_fetch_detail.delay()
        # 异步任务
        # do_fetch_one.delay()
        # func = request.get['func']
        # response= globals()[func].delay()
        # print(response)
        # print(response)
        # 提交定时异步任务
        # t = datetime(2022, 7, 21, 11, 13, 00)
        # t = datetime.utcfromtimestamp(t.timestamp())
        # send_sms.apply_async(args=["小联盟",], eta=t)

        return Response('')


class MovieTypeViewset(ModelViewSet):
    queryset = MovieTypeModel.objects.all()
    serializer_class = MoiveTypeSeriaizers
    pagination_class = None


class MovieActorViewset(ModelViewSet):
    queryset = MovieActorModel.objects.all()
    serializer_class = MoiveActorSeriaizers


class MovieDirectorViewset(ModelViewSet):
    queryset = MovieDirectorModel.objects.all()
    serializer_class = MoiveDirectorSeriaizers


class MovieAreaViewset(ModelViewSet):
    queryset = MovieAreaModel.objects.all()
    serializer_class = MoiveAreaSeriaizers
    pagination_class = None
