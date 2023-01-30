from django.db.models import *

# Create your models here.


class MovieActorModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')

    class Meta:
        db_table = 'actor'


class MovieDirectorModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')

    class Meta:
        db_table = 'director'


class MovieAreaModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')

    class Meta:
        db_table = 'area'


class MovieTypeModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')

    class Meta:
        db_table = 'type'


class MoviePlayListModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    url = CharField(max_length=200, unique=True,
                    verbose_name='链接地址', default='')
    name = CharField(max_length=200, unique=True,
                     verbose_name='名称', default='')

    class Meta:
        db_table = 'play_list'


class MovieSourceModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')
    playlist = ManyToManyField(
        MoviePlayListModel, verbose_name='播放列表', blank=True,)

    class Meta:
        db_table = 'source'


class MovieModel(Model):
    id = AutoField(auto_created=True, primary_key=True)
    name = CharField(max_length=200, unique=True,
                     verbose_name='名字', default='')
    alias = CharField(max_length=500, verbose_name='别名',
                      blank=True, null=True)
    release_date = CharField(max_length=200,
                             verbose_name='发行时间', default='')
    cover = CharField(max_length=200, verbose_name='封面', default='')
    score = FloatField(verbose_name='评分', blank=True, null=True)
    detail = TextField(max_length=500, verbose_name='页面地址',
                       blank=True, null=True)
    description = TextField(max_length=5000, verbose_name='简介',
                            blank=True, null=True)
    actors = ManyToManyField(
        MovieActorModel, verbose_name='导演', related_name='actors_set', blank=True,)
    areas = ManyToManyField(
        MovieAreaModel, verbose_name='地区', related_name='areas_set', blank=True,)
    directors = ManyToManyField(
        MovieDirectorModel, verbose_name='主演', related_name='directors_set', blank=True,)
    types = ManyToManyField(
        MovieTypeModel, verbose_name='类型', related_name='types_set', blank=True,)
    source = ManyToManyField(
        MovieSourceModel, related_name='source_set', verbose_name='资源', blank=True,)

    class Meta:
        db_table = 'movie'
        
