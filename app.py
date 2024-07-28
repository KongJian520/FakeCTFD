from flask import Flask, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import databases
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__,
            static_url_path='/static',
            static_folder='static',
            template_folder='templates')

conn = databases.db_init('./.config.json')
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/dbname'
db = SQLAlchemy(app)


class User(db.CTF):
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
