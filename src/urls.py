from django.urls import *
from rest_framework.routers import *
from .views.products import ProductsViewset
from .views.movies import *
from .views.wechat import WechatViewset

router = DefaultRouter()

router.register(r'products', ProductsViewset)
router.register(r'movie', MovieViewset)
router.register(r'type', MovieTypeViewset)
router.register(r'actor', MovieActorViewset)
router.register(r'director', MovieDirectorViewset)
router.register(r'area', MovieAreaViewset)
urlpatterns = [
    re_path(r'wechat', WechatViewset.as_view(
        {'get': 'auth'})),
]

urlpatterns += router.urls
