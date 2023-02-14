from django.urls import path
from rest_framework import routers

from src.open.views.projects import ProjectsViewSet

system_url = routers.SimpleRouter()
system_url.register(r'projects', ProjectsViewSet)

urlpatterns = [
    # path('projects/', Projects.as_view({'post': 'projects', })),
]
urlpatterns += system_url.urls
