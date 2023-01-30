from django.urls import *
from rest_framework.routers import *
from .views import *

router = DefaultRouter()

router.register(r'movie', MovieViewset)
router.register(r'type', MovieTypeViewset)
router.register(r'actor', MovieActorViewset)
router.register(r'director', MovieDirectorViewset)
router.register(r'area', MovieAreaViewset)

urlpatterns = [
    re_path(r'task', MovieViewset.as_view(
        {'get': 'do_task'})),
]

urlpatterns += router.urls
