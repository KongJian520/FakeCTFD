import pymysql

from tools import read_json


def db_init(path):
    config = read_json(path)
    try:
        conn = pymysql.connect(host=config['dbhosts'],
                               user=config['dbuser'],
                               password=config['dbpass'],
                               database=config['dbname'])
        print("数据库连接成功")
    except pymysql.MySQLError as e:
        print(f"数据库连接失败: {e}")
        conn = None  # 确保 db 变量在异常情况下也被定义
    return conn
