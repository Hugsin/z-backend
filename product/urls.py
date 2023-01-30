from django.urls import *
from rest_framework.routers import *
from .views import ProductsViewset

router = DefaultRouter()

router.register(r'products', ProductsViewset)
urlpatterns = []

urlpatterns += router.urls
