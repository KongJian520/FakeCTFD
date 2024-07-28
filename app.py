import json

import pymysql
from flask import Flask, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import mysql

app = Flask(__name__,
            static_url_path='/static',
            static_folder='static',
            template_folder='templates')


def read_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        config = json.load(file)
    return config


config = read_json('./.config.json')
try:
    db = pymysql.connect(host=config['dbhosts'],
                         user=config['dbuser'],
                         password=config['dbpass'],
                         database=config['dbname'])
    print("数据库连接成功")
except pymysql.MySQLError as e:
    print(f"数据库连接失败: {e}")
    db = None  # 确保 db 变量在异常情况下也被定义


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    username = db.Column(db.String(20))  # 用户名
    password_hash = db.Column(db.String(128))  # 密码散列值

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值


@app.route('/')
def index():
    user_logged_in = request.cookies.get('user_logged_in')
    if not user_logged_in:
        return redirect(url_for('login'))
    return 'Welcome to the homepage!'


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)
