from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = '7e158f52147dd91eb8853151dea4da9a'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

from catalog_app import routes
