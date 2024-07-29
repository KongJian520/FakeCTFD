from werkzeug.security import generate_password_hash, check_password_hash
import databases
import click
from flask import Flask, request, redirect, url_for, flash, render_template, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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


class Web(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    docker_name = db.Column(db.String(255))
    difficulty = db.Column(db.Integer)


class Misc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    docker_name = db.Column(db.String(255))
    difficulty = db.Column(db.Integer)


class Reverse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    docker_name = db.Column(db.String(255))
    difficulty = db.Column(db.Integer)


class Pwn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    docker_name = db.Column(db.String(255))
    difficulty = db.Column(db.Integer)


class Crypto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    docker_name = db.Column(db.String(255))
    difficulty = db.Column(db.Integer)


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


@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password',
              prompt=True,
              hide_input=True,
              confirmation_prompt=True,
              help='The password used to login.')
def admin(username, password):
    """Create user."""
    db.create_all()

    user = User.query.first()
    if user is not None:
        click.echo('Updating user...')
        user.username = username
        user.set_password(password)  # 设置密码
    else:
        click.echo('Creating user...')
        user = User(username=username, name='Admin')
        user.set_password(password)  # 设置密码
        db.session.add(user)

    db.session.commit()  # 提交数据库会话
    click.echo('Done.')


@app.errorhandler(404)
def err404(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(401)
def err401(e):
    return render_template('errors/401.html'), 401


@app.route('/query', methods=['GET'])
@login_required
def query():
    category = request.args.get('category')
    if category == 'Web':
        results = Web.query.all()
    elif category == 'Misc':
        results = Misc.query.all()
    elif category == 'Reverse':
        results = Reverse.query.all()
    elif category == 'Pwn':
        results = Pwn.query.all()
    elif category == 'Crypto':
        results = Crypto.query.all()
    else:
        return jsonify([])

    data = [{
        'id': result.id,
        'docker_name': result.docker_name,
        'difficulty': result.difficulty,
    } for result in results]

    return jsonify(data)


@app.route('/action')
def action():
    category = request.args.get('category')
    item_id = request.args.get('id')
    # # 模拟执行动作并返回结果
    result = f'Action executed for category {category} and item {item_id}'
    response = make_response(result)
    # response.set_cookie('result', result)
    return response


@app.route('/overview')
def over_view():
    content = "这是大纲。"
    return render_template('CTF/menu.html', page='web', content=content)


@app.route('/web')
def web():
    content = "这是Web页面的内容。"
    return render_template('CTF/menu.html', page='web', content=content)


@app.route('/misc')
def misc():
    content = "这是Misc页面的内容。"
    return render_template('CTF/menu.html', page='misc', content=content)


@app.route('/reverse')
def reverse():
    content = "这是Reverse页面的内容。"
    return render_template('CTF/menu.html', page='reverse', content=content)


@app.route('/pwn')
def pwn():
    content = "这是Pwn页面的内容。"
    return render_template('CTF/menu.html', page='pwn', content=content)


@app.route('/crypto')
def crypto():
    content = "这是Crypto页面的内容。"
    return render_template('CTF/menu.html', page='crypto', content=content)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run('0.0.0.0', 5000, debug=True)
