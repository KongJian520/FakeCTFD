from werkzeug.security import generate_password_hash, check_password_hash
import databases
import click
from flask import Flask, request, redirect, url_for, flash, render_template, jsonify
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


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)
