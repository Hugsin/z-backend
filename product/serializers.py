from rest_framework.serializers import *
from .models import *


class ProductModelSeriaizers(ModelSerializer):
    class Meta:
        model = ProductModel
        fields = '__all__'
