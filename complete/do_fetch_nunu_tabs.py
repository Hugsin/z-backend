import httpx
import time
from parsel import Selector
from fake_useragent import UserAgent
import csv
from concurrent.futures import ThreadPoolExecutor
from .models import *
from .serializers import *


uri = 'https://www.nunuyy1.org'
types = ['dianying', 'dianshiju', 'dongman', 'zongyi']

executor = ThreadPoolExecutor(max_workers=500)


def get_ua_random():
    ua = UserAgent().random
    return ua

def write_mysql(data):
    model_serializer = MoiveSeriaizers(data=data)
    if(model_serializer.is_valid()):
        MovieModel.objects.get_or_create(
            **model_serializer.validated_data)

def write_file(data, filename=int(time.time())):
    with open('{}.csv'.format(filename), 'a+') as f:
        csv_write = csv.writer(f)
        row = []
        for it in dict.keys(data):
            row.append(data[it])
        csv_write.writerow(row)
        f.close()

def do_fetch_nunu_detail(path, movie, filename):
    headers = {"User-Agent": get_ua_random()}
    try:
        response = httpx.get(uri+path, headers=headers)
        if response.status_code == 200:
            selector = Selector(response.text)
            image = selector.css('.product-header img').xpath('.//@src').get()
            name = selector.css('.product-title::text').get()
            rate = selector.css('.product-title .rate::text').get()
            excerpt = selector.css('.product-excerpt')
            details = ''
            for it in excerpt:
                detail_text = it.css('span::text').get()
                if detail_text:
                    details += detail_text
            video_src = selector.css('video').xpath('@src').get()
            result = {
                'name': name or movie['name'],
                'cover': image or movie['image'],
                'rate': rate or movie['rate'],
                'detail': video_src or uri+path,
                'summary': details,
                "blob": ''
            }
            # write_file(result, filename)
            write_mysql(result)
    except httpx.HTTPError as e:
        print(e)
        do_fetch_nunu_detail(path, movie, filename)

def do_fetch_page_data(url, filename):
    try:
        headers = {"User-Agent": get_ua_random()}
        print(url)
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            selector = Selector(response.text)
            list = selector.css('li')
            t_list = []
            for it in list:
                img = it.css('img')
                if len(img) > 0:
                    image = (img.xpath('.//@src').get())
                    href = (it.css('a').xpath('.//@href').get())
                    name = (it.css('h2 a::text').get())
                    note = (it.css('.note span::text').get())
                    rate = (it.css('.rate::text').get())
                    # executor.submit(do_fetch_nunu_detail, href, {
                    #     'image': image,
                    #     'name': name,
                    #     'note': note,
                    #     'rate': rate,
                    # }, filename)
                    result = {
                        'name': name,
                        'cover': image,
                        'rate': rate,
                        'detail':  uri+href,
                        'summary': '',
                        "blob": ''
                    }
                    # write_file(result, filename)
                    write_mysql(result)
            #         t = threading.Thread(target=do_fetch_nunu_detail, args=(href, {
            #             'image': image,
            #             'name': name,
            #             'note': note,
            #             'rate': rate,
            #         }, filename))

            #         t_list.append(t)
            # for t in t_list:
            #     t.start()

            # for t in t_list:
            #     t.join()

    except BaseException as e:
        print(e)
        do_fetch_page_data(url, filename)


def do_fetch_tab_data(type):
    try:
        # t_list = []
        headers = {"User-Agent": get_ua_random()}
        tap_url = '{}/{}/'.format(uri, type)
        response = httpx.get(tap_url, headers=headers)
        if response.status_code == 200:
            selector = Selector(response.text)
            list = selector.css('.pagination ul li')
            href = list[-1].css('a').attrib['href']
            max_page = href.split('_')[1].split('.')[0]
            max_page = int(max_page)
            for (i, it) in enumerate(range(max_page)):
                page_url = tap_url if i == 0 else '{0}index_{1}.html'.format(
                    tap_url, i+1)
                executor.submit(
                    do_fetch_page_data, page_url, type)
                # t = threading.Thread(
                #     target=do_fetch_page_data, args=(page_url, type))
        #             t_list.append(t)
        # print(len(t_list))
        # for t in t_list:
        #     t.start()

        # for t in t_list:
        #     t.join()
    except httpx.HTTPError as e:
        print(e)
        do_fetch_tab_data(type)


def main():
    for type in types:
        do_fetch_tab_data(type)


if __name__ == '__main__':
    main()
