from werkzeug.security import generate_password_hash, check_password_hash
import databases

from flask import Flask, request, redirect, url_for, flash, render_template, jsonify, make_response

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from manage import *

app = Flask(__name__,
            static_url_path='/static',
            static_folder='static',
            template_folder='./templates')

conn = databases.db_init('./.config.json')
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://CTF:11223344@localhost/CTF'
app.secret_key = 'GEEKGEEK'
# app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')  # 从环境变量中获取密钥
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    username = db.Column(db.String(20))  # 用户名
    password_hash = db.Column(db.String(255))  # 确保长度一致

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


login_manager = LoginManager(app)  # 实例化扩展类


def create_model_class(name):
    return type(
        name, (db.Model, ), {
            'id': db.Column(db.Integer, primary_key=True),
            'docker_name': db.Column(db.String(255)),
            'difficulty': db.Column(db.Integer),
            'tips': db.Column(db.String(255))
        })


Web = create_model_class('Web')
Pwn = create_model_class('Pwn')
Crypto = create_model_class('Crypto')
Reverse = create_model_class('Reverse')
Misc = create_model_class('Misc')


@login_manager.user_loader
def load_user(user_id):  # 创建用户加载回调函数，接受用户 ID 作为参数
    user = User.query.get(int(user_id))  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return jsonify({'success': False, 'message': '用户名或密码错误'})
            # return redirect(url_for('login'))

        user = User.query.first()
        # 验证用户名和密码是否一致
        if username == user.username and user.validate_password(password):
            login_user(user)  # 登入用户
            return jsonify({'success': True, 'message': '登录成功'})
            # return redirect(url_for('index'))  # 重定向到主页

        return jsonify({'success': False, 'message': '用户名或密码错误'})
        # return redirect(url_for('login'))  # 重定向回登录页面

    return render_template('login.html')


@app.route('/')
def index():
    if current_user.is_authenticated:
        user_name = current_user.username
    else:
        user_name = '游客'
    return render_template('index.html', user_name=user_name)


@app.errorhandler(404)
def err404(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(401)
def err401(e):
    return render_template('errors/401.html'), 401


@app.route('/overview')
def over_view():
    content = "这是大纲。"
    return render_template('CTF/menu.html', content=content)


@app.route('/web')
@login_required
def web():
    content = "Web"
    results = Web.query.all()
    return render_template('CTF/menu.html', content=content)


@app.route('/misc')
@login_required
def misc():
    content = "Misc"
    results = Misc.query.all()
    return render_template('CTF/menu.html', content=content)


@app.route('/reverse')
@login_required
def reverse():
    content = "Reverse"
    results = Reverse.query.all()
    return render_template('CTF/menu.html', content=content)


@app.route('/pwn')
@login_required
def pwn():
    content = "Pwn"
    results = Pwn.query.all()
    return render_template('CTF/menu.html', content=content)


@app.route('/crypto')
@login_required
def crypto():
    content = "Crypto"
    results = Crypto.query.all()
    return render_template('CTF/menu.html', content=content)


if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()
    app.run('0.0.0.0', 5000, debug=True)
