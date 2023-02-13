from rest_framework.viewsets import ModelViewSet
from ..models.products import ProductModel
from rest_framework.serializers import *

# Create your views here.

class ProductModelSeriaizers(ModelSerializer):
    class Meta:
        model = ProductModel
        fields = '__all__'


class ProductsViewset(ModelViewSet):
    queryset = ProductModel.objects.all()
    serializer_class = ProductModelSeriaizers
    pagination_class = None
