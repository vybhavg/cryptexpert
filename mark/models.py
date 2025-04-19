from mark import db, bcrypt, login_manager
from flask_login import UserMixin
from cryptography.fernet import Fernet
import os
from datetime import datetime
from dotenv import load_dotenv

# Load encryption key from environment variable (or generate one)
load_dotenv()
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
cipher = Fernet(ENCRYPTION_KEY.encode())
print(ENCRYPTION_KEY)
print(cipher)
def encrypt_data(data):
    """Encrypts sensitive data using AES-256 encryption."""
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data):
    """Decrypts data using AES-256 encryption."""
    return cipher.decrypt(encrypted_data).decode()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    """User model for authentication."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    authenticator_secret = db.Column(db.String(32), nullable=True)
    authenticator_enabled = db.Column(db.Boolean, default=False)

    api_keys = db.relationship("UserAPIKey", backref="user", lazy=True)

    @property
    def password(self):
        raise AttributeError("Password cannot be accessed directly.")

    @password.setter
    def password(self, plain_password):
        """Hashes the password before storing it."""
        self.password_hash = bcrypt.generate_password_hash(plain_password).decode("utf-8")

    def check_password(self, entered_password):
        """Checks if the entered password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, entered_password)

class UserAPIKey(db.Model):
    """Stores encrypted API keys for users."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    exchange = db.Column(db.String(50), nullable=False)
    api_key_enc = db.Column(db.LargeBinary, nullable=False)
    api_secret_enc = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, user_id, exchange, api_key, api_secret):
        self.user_id = user_id
        self.exchange = exchange
        self.api_key_enc = encrypt_data(api_key)
        self.api_secret_enc = encrypt_data(api_secret)

    def get_api_keys(self):
        """Returns decrypted API keys."""
        return decrypt_data(self.api_key_enc), decrypt_data(self.api_secret_enc)

class Item(db.Model):
    """Represents an item (possibly student-related)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll = db.Column(db.Integer, nullable=False)
    student_class = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<Item {self.name}>"

class CryptoAsset(db.Model):
    """Stores crypto asset details like name, symbol, and link."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=False)
    symbol = db.Column(db.String(50), nullable=False)  

    def __repr__(self):
        return f"<CryptoAsset {self.name}>"

class Exchange(db.Model):
    """Represents an exchange platform (e.g., Binance, Coinbase)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    section_id = db.Column(db.String(100), nullable=False)  

    def __repr__(self):
        return f"<Exchange {self.name}>"

class ForumCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    threads = db.relationship('ForumThread', backref='category', lazy=True)

class ForumThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('forum_category.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    posts = db.relationship('ForumPost', backref='thread', lazy=True, cascade='all, delete-orphan')
    user = db.relationship('User', backref=db.backref('threads', lazy=True, cascade='all, delete-orphan'))
    category = db.relationship('ForumCategory', backref=db.backref('forum_threads', lazy=True))  # Renamed backref to 'forum_threads'




class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
