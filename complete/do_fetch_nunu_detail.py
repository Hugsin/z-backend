from .models import *
from .serializers import *
from .do_fetch_nunu_tabs import *


def update_or_create_type(data):
    obj = MovieTypeModel.objects.get_or_create(name=data['name'])[0]
    return obj.id


def update_or_create_actor(data):
    obj = MovieActorModel.objects.get_or_create(name=data['name'])[0]
    return obj.id


def update_or_create_director(data):
    obj = MovieDirectorModel.objects.get_or_create(name=data['name'])[0]
    return obj.id


def update_or_create_area(data):
    obj = MovieAreaModel.objects.get_or_create(name=data['name'])[0]
    return obj.id


def update_movie(data):
    movie_type_ser = MoiveSeriaizers(data=data)
    if(movie_type_ser.is_valid()):
        result = MovieModel.objects.get_or_create(
            **movie_type_ser.validated_data)
        if(result):
            MovieModel.objects.update_or_create(result)


def fetch_nunu_detail(url, Movie):
    """
    获取summary
    获取blob地址
    新增分类
    """
    print(url)
    try:
        headers = {"User-Agent": get_ua_random()}
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            selector = Selector(response.text)
            # description = selector.css("meta[property='og:description']").xpath('.//@content').get()
            description = selector.css(
                "meta[property='og:description']").xpath('.//@content').get()

            actor = selector.css(
                "meta[property='og:video:actor']").xpath('.//@content').get()

            director = selector.css(
                "meta[property='og:video:director']").xpath('.//@content').get()

            release_date = selector.css(
                "meta[property='og:video:release_date']").xpath('.//@content').get()

            alias = selector.css(
                "meta[property='og:video:alias']").xpath('.//@content').get()

            area = selector.css(
                "meta[property='og:video:area']").xpath('.//@content').get()

            score = selector.css(
                "meta[property='og:video:score']").xpath('.//@content').get()

            types = selector.css(
                "meta[property='og:video:class']").xpath('.//@content').get()
            types_id = []
            actor_id = []
            director_id = []
            are_id = []
            if types:
                types_id = [
                    update_or_create_type({'name': type}) for type in types.split(',') if type != '' and len(types.split(',')) >= 1
                ]
            if actor:
                actor_id = [
                    update_or_create_actor({'name': act}) for act in actor.split(',') if act != '' and len(actor.split(',')) >= 1
                ]
            if director:
                director_id = [
                    update_or_create_director({'name': dire}) for dire in director.split(',') if dire != '' and len(director.split(',')) >= 1
                ]
            if area:
                are_id = [
                    update_or_create_area({'name': are}) for are in area.split(',') if are != '' and len(area.split(',')) >= 1
                ]
            Movie.release_date = release_date
            Movie.description = description
            Movie.alias = alias

            Movie.areas.set(are_id)
            Movie.types.set(types_id)
            Movie.directors.set(director_id)
            Movie.actors.set(actor_id)
            Movie.save()
    except BaseException as e:
        print(e)
        pass
        # fetch_nunu_detail(url)


def nunu_detail_main():
    quertset = MovieModel.objects.filter(description__regex=r'^\d{0}$')
    try:
        print('========={}'.format(len(quertset)))
        for Movie in quertset:
            moive_seriaizers = MoiveSeriaizers(Movie)
            detail = moive_seriaizers.data['detail']
            description = moive_seriaizers.data['description']
            if detail != '' and description == '':
                executor.submit(fetch_nunu_detail, detail, Movie)
            else:
                continue
        return 'done'
    except BaseException as e:
        print(e)


if __name__ == '__main__':
    nunu_detail_main()
