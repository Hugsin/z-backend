from rest_framework.response import *
from ..models.movies import *
from rest_framework.serializers import *
from rest_framework.viewsets import ModelViewSet
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from django_filters.rest_framework import FilterSet
import django_filters


class MovieFilter(FilterSet):
    name = django_filters.CharFilter(
        field_name='name', lookup_expr='icontains')
    description = django_filters.CharFilter(
        field_name='description', lookup_expr='icontains')
    menu = django_filters.CharFilter(
        field_name='detail', lookup_expr='icontains')

    class Meta:
        model = MovieModel
        fields = '__all__'


class SourcePlayListSeriaizers(ModelSerializer):
    class Meta:
        model = MoviePlayListModel
        fields = '__all__'


class MoiveSourceSeriaizers(ModelSerializer):
    myplaylist = SourcePlayListSeriaizers(
        source="playlist", read_only=True, many=True)

    class Meta:
        model = MovieSourceModel
        fields = '__all__'


class MoiveTypeSeriaizers(ModelSerializer):
    class Meta:
        model = MovieTypeModel
        fields = '__all__'


class MoiveActorSeriaizers(ModelSerializer):
    class Meta:
        model = MovieActorModel
        fields = '__all__'


class MoiveDirectorSeriaizers(ModelSerializer):
    class Meta:
        model = MovieDirectorModel
        fields = '__all__'


class MoiveAreaSeriaizers(ModelSerializer):
    class Meta:
        model = MovieAreaModel
        fields = '__all__'


class MoiveSeriaizers(ModelSerializer):
    mytypes = MoiveTypeSeriaizers(source="types", read_only=True, many=True)
    myactors = MoiveActorSeriaizers(source="actors", read_only=True, many=True)
    mydirectors = MoiveDirectorSeriaizers(
        source="directors", read_only=True, many=True)
    myareas = MoiveAreaSeriaizers(source="areas", read_only=True, many=True)
    mysource = MoiveSourceSeriaizers(
        source="source", read_only=True, many=True)

    class Meta:
        model = MovieModel
        fields = ['id', 'name', 'alias', 'release_date',
                  'cover', 'score', 'detail', 'description',
                  'mytypes', 'myactors', 'mydirectors',
                  'myareas', 'mysource']


class MovieViewset(ModelViewSet):
    queryset = MovieModel.objects.all()
    serializer_class = MoiveSeriaizers
    filter_backends = (DjangoFilterBackend, OrderingFilter)
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
        # do_fetch_tabs.delay()
        # do_fetch_detail.delay()
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
