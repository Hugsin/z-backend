# setup
``` 
1. 进入项目目录 cd backend
2. cd conf/env.py
3. 在 env.py 中配置数据库信息
	mysql数据库版本建议：8.0
	mysql数据库字符集：utf8mb4
4. 安装依赖环境
	pip3 install -r requirements.txt
5. 执行迁移命令：
	python3 manage.py makemigrations
	python3 manage.py migrate
6. 初始化数据
	python3 manage.py init
7. 初始化省市县数据:
	python3 manage.py init_area
8. 启动项目
	python3 manage.py runserver 0.0.0.0:8000
或使用 daphne :
  daphne -b 0.0.0.0 -p 8000 application.asgi:application
```
# command
```
# 命令行调试
python manage.py shell
from django.core.cache import cache #引入缓存模块 
cache.set('key','value',3600) # 写入key缓存一小时
cache.get('key') # 获取key  => value
cache.has_key('key') #是否存在key => True
# 启动周期性任务
Celery -A application beat -l info
# 去重生成requirements.txt文件
pip3 freeze | sort | uniq > requirements.txt

https://dashboard.cpolar.com/
./cpolar authtoken NWMyZjVmZmMtZTM0MC00ODFmLWJhMWQtOWI4NTlkYzI2NDhj
```
