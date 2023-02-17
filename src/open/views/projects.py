# -*- coding: utf-8 -*-
from django.db.models import Q
from rest_framework import serializers

from src.open.models import Projects
from src.utils.json_response import SuccessResponse
from src.utils.serializers import CustomModelSerializer
from src.utils.viewset import CustomModelViewSet


class ProjectsSerializer(CustomModelSerializer):
    """
    项目-序列化器
    """
    class Meta:
        model = Projects
        fields = "__all__"
        read_only_fields = ["id"]  


class ProjectsViewSet(CustomModelViewSet):
    """
    项目管理接口
    list:查询
    create:新增
    update:修改
    retrieve:单例
    destroy:删除
    """
    queryset = Projects.objects.all()
    serializer_class = ProjectsSerializer
    extra_filter_backends = []
    permission_classes = []
