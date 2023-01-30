from rest_framework.viewsets import ModelViewSet
from .models import ProductModel
from .serializers import ProductModelSeriaizers
# Create your views here.


class ProductsViewset(ModelViewSet):
    queryset = ProductModel.objects.all()
    serializer_class = ProductModelSeriaizers
    pagination_class = None
