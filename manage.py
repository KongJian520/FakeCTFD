import os

import click
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://CTF:11223344@localhost/CTF'
app.secret_key = 'GEEKGEEK'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


def create_model_class(name):
    return type(
        name, (db.Model, ), {
            'id': db.Column(db.Integer, primary_key=True),
            'docker_name': db.Column(db.String(255)),
            'difficulty': db.Column(db.Integer),
            'tips': db.Column(db.String(255))
        })


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


Web = create_model_class('Web')
Pwn = create_model_class('Pwn')
Crypto = create_model_class('Crypto')
Reverse = create_model_class('Reverse')
Misc = create_model_class('Misc')


def run_migrations():
    if not os.path.exists('migrations'):
        os.system('flask db init')
    os.system('flask db migrate -m "自动迁移"')
    os.system('flask db upgrade')


if __name__ == '__main__':
    run_migrations()
