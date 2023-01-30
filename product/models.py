from django.db.models import *

# Create your models here.


class ProductModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    desc = CharField(max_length=2000,
                     verbose_name='描述', default='')
    image = CharField(max_length=200,
                      verbose_name='图片地址', default='')
    name = CharField(max_length=200,
                     verbose_name='名称', default='')
    order_num = CharField(max_length=200,
                          verbose_name='排序', default='')
    url = CharField(max_length=2000,
                    verbose_name='链接', default='')
    type = CharField(max_length=200,
                    verbose_name='类型', default='')

    class Meta:
        db_table = 'products'
