import requests
from concurrent.futures import ThreadPoolExecutor
import time
import re
from fake_useragent import UserAgent


pool = ThreadPoolExecutor(max_workers=100)
ua = UserAgent()


class Bilibili():
    def __init__(self) -> None:
        self.url = "https://api.bilibili.com/x/space/wbi/arc/search"
        self.querystring = {"mid": "50329118",
                            "ps": "30",
                            "tid": "0",
                            "pn": "3",
                            "keyword": "",
                            "order": "pubdate",
                            "platform": "web",
                            "web_location": "1550101",
                            "order_avoided": "true",
                            "w_rid": "72be08450198edf4d37bf3d1daefa0ef",
                            "wts": "1681696160"
                            }
        self.headers = {
            'user-agent': ua.random,
            'authority': "api.bilibili.com",
            'accept': "application/json, text/plain, */*",
            'accept-language': "zh-CN,zh;q=0.9,en;q=0.8,de;q=0.7",
            'cache-control': "no-cache",
            '$cookie': r"buvid3=EC0259E8-59DA-6A33-6472-0154188AF6FE19072infoc; b_nut=1678354419; CURRENT_FNVAL=4048; _uuid=66D4E9C1-1F9A-C6106-3C5F-5646EF610AF6819353infoc; buvid_fp=51663f4e506080acdd5dc5296405676e; rpdid=|()kkll~)Yk0J\uY~)JlRRku;"
        }
        self.result = []

    def do_request(self, params, i):
        try:
            time.sleep(i*0.1)
            self.headers.update({'user-agent': ua.random})
            response = requests.request(
                "GET", self.url, headers=self.headers, params=params)
            if response.status_code == 200:
                response = response.json()
                data = response.get('data')
                code = response.get('code')
                if code == 200:
                    page = data.get('page')
                    olist = data.get('list')
                    count = page.get('page')
                    vlist = olist.get('vlist')
                    print(params.get('pn'))
                    for it in vlist:
                        description = it.get('description')
                        if description.startswith('【LPL春季赛TOP5】'):
                            match = re.search(r'：(.*)$', description)
                            if match:
                                verse = (match.group(1))
                                print(verse)
                else:
                    print(response)
        except BaseException as e:
            print(str(e))

    def fetch_all(self):
        for i in range(int(4838/30)):
            params = self.querystring
            params.update({'pn': i+1})
            params.update({'wts': int(time.time())})
            pool.submit(self.do_request, params, i)


# b = Bilibili()
# b.fetch_all()
n = 99999
# while(True):
url = f"https://www.gushidaquan.com.cn/lishi/{n}.html"
response = requests.request('GET', url, headers={
    'user-agent': ua.random,
})
if response.status_code == 200:
    print(response.text)

