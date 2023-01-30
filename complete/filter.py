from django_filters.rest_framework import FilterSet
import django_filters 
from .models import *

class MovieFilter(FilterSet):
    name = django_filters.CharFilter(field_name='name',lookup_expr='icontains')
    description = django_filters.CharFilter(field_name='description',lookup_expr='icontains')
    menu = django_filters.CharFilter(field_name='detail',lookup_expr='icontains')

    class Meta:
        model = MovieModel
        fields = '__all__'