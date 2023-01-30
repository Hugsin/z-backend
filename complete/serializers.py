from rest_framework.serializers import *
from .models import *


class SourcePlayListSeriaizers(ModelSerializer):
    class Meta:
        model = MoviePlayListModel
        fields = '__all__'


class MoiveSourceSeriaizers(ModelSerializer):
    myplaylist = SourcePlayListSeriaizers(
        source="playlist", read_only=True, many=True)

    class Meta:
        model = MovieSourceModel
        fields = '__all__'


class MoiveTypeSeriaizers(ModelSerializer):
    class Meta:
        model = MovieTypeModel
        fields = '__all__'


class MoiveActorSeriaizers(ModelSerializer):
    class Meta:
        model = MovieActorModel
        fields = '__all__'


class MoiveDirectorSeriaizers(ModelSerializer):
    class Meta:
        model = MovieDirectorModel
        fields = '__all__'


class MoiveAreaSeriaizers(ModelSerializer):
    class Meta:
        model = MovieAreaModel
        fields = '__all__'


class MoiveSeriaizers(ModelSerializer):
    mytypes = MoiveTypeSeriaizers(source="types", read_only=True, many=True)
    myactors = MoiveActorSeriaizers(source="actors", read_only=True, many=True)
    mydirectors = MoiveDirectorSeriaizers(
        source="directors", read_only=True, many=True)
    myareas = MoiveAreaSeriaizers(source="areas", read_only=True, many=True)
    mysource = MoiveSourceSeriaizers(
        source="source", read_only=True, many=True)

    class Meta:
        model = MovieModel
        fields = ['id', 'name', 'alias', 'release_date',
                  'cover', 'score', 'detail', 'description',
                  'mytypes', 'myactors', 'mydirectors',
                  'myareas', 'mysource']
