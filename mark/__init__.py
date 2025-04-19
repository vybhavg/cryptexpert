from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
import urllib.parse
import os
from dotenv import load_dotenv
from flask_socketio import SocketIO, emit



# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Get environment variables
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_NAME")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")

# Safely encode special characters in password
encoded_password = urllib.parse.quote_plus(db_password)

# Flask configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://{db_user}:{encoded_password}@{db_host}:{db_port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))  # Default to random if not set

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
# Configure upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_form'  # Adjust as needed
migrate = Migrate(app, db)
# Initialize SocketIO after your Flask app
socketio = SocketIO(app, cors_allowed_origins="*")

# Add this WebSocket handler
@socketio.on('new_message')
def handle_new_message(data):
    """Broadcast new messages to all clients"""
    emit('message_received', data, broadcast=True)
# Import routes
from mark import routes
