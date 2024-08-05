import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, init, migrate, upgrade

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://CTF:11223344@localhost/CTF'
app.secret_key = 'GEEKGEEK'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


def run_migrations():
    if not os.path.exists('migrations'):
        init()
    migrate(message="自动迁移")
    upgrade()


if __name__ == '__main__':
    run_migrations()
