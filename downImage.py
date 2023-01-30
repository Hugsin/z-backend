import json
from concurrent.futures import ThreadPoolExecutor
import httpx
executor = ThreadPoolExecutor(max_workers=500)


def readFile():
    with open('./data.json') as f:
        data = json.load(f)
        for it in data:
            executor.submit(downimage, it['url'], it['name'])


def downimage(url, name):
    print(url)
    response = httpx.get(url)
    if response.status_code == 200:
        with open('image/'+name, 'wb') as f:
            f.write(response.read())
            print(name)
            f.close()


if __name__ == '__main__':
    readFile()
