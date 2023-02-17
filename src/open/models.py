from django.db import models
from application import dispatch
from src.utils.models import CoreModel, table_prefix


class Projects(CoreModel):
    name = models.CharField(max_length=100, verbose_name='名称')
    desc = models.CharField(max_length=2000, verbose_name='描述')
    image = models.CharField(max_length=200, verbose_name='图片地址')
    order_num = models.IntegerField(
        default=1, verbose_name="显示排序", null=True, blank=True, help_text="显示排序")
    url = models.CharField(
        max_length=2000, verbose_name='链接', help_text="岗位状态")
    STATUS_CHOICES = (
        (0, "网站"),
        (1, "图片"),
        (2, "小程序"),
        (2, "公众号"),
    )
    type = models.IntegerField(
        choices=STATUS_CHOICES, default=1, verbose_name="岗位状态", help_text="岗位状态")

    class Meta:
        db_table = table_prefix + "projects"
        verbose_name = "项目表"
        verbose_name_plural = verbose_name
        ordering = ("order_num",)


class WechatPayOrder(CoreModel):
    desc = models.CharField(max_length=2000, verbose_name='描述')
    class Meta:
        db_table = table_prefix + "order"
        verbose_name = "订单表"
        verbose_name_plural = verbose_name
