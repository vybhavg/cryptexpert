from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
import urllib.parse
import os


app = Flask(__name__)

# Database Configuration
db_user = "postgres"
db_password = "Gvbh@1781"
db_name = "cryptexpert"
db_host = "/cloudsql/cryptexpert:asia-southeast1:cryptexpert-db"

encoded_password = urllib.parse.quote_plus(db_password)

app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql+psycopg2://{db_user}:{encoded_password}@/{db_name}?host={db_host}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = os.urandom(24)
# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cryptexpert.v@gmail.com'
app.config['MAIL_PASSWORD'] = 'ujreujuqioixlqga'  # Remove spaces
app.config['MAIL_DEFAULT_SENDER'] = 'cryptexpert.v@gmail.com'

# Initializing Extensions
mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_form'
migrate = Migrate(app, db)  # Ensure this line is included

from mark import routes
