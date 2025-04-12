from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
import os
import urllib.parse  # Add this import
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Get environment variables
db_user = os.getenv("DB_USER", "postgres")
db_password = os.getenv("DB_PASSWORD", "Gvbh1781")  # Use env var in production
db_name = os.getenv("DB_NAME", "cryptexpert")
db_host = os.getenv("DB_HOST", "cryptexpert-db.cjs6a2mg6ff2.ap-southeast-1.rds.amazonaws.com")
db_port = os.getenv("DB_PORT", 5432)

# Safely encode special characters in password
encoded_password = urllib.parse.quote_plus(db_password)

# Setup the SQLAlchemy database URI
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://{db_user}:{encoded_password}@{db_host}:{db_port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))  # Load secret key from env

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'cryptexpert.v@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'ujreujuqioixlqga')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME', 'cryptexpert.v@gmail.com')

# Initializing Extensions
mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_form'
migrate = Migrate(app, db)  # Ensure this line is included

from mark import routes
