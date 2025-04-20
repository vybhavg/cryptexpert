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
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
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
from datetime import datetime

class ForumCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    threads = db.relationship('ForumThread', backref='category', lazy=True, cascade='all, delete-orphan')

class ForumThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('forum_category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('ForumPost', backref='thread', lazy=True, cascade='all, delete-orphan')
    
    user = db.relationship('User', backref='threads')

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'), nullable=False)
    reply_to = db.Column(db.Integer, db.ForeignKey('forum_post.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(255))
    
    user = db.relationship('User', backref='posts')
    replies = db.relationship('ForumPost', backref=db.backref('parent_post', remote_side=[id]))
    likes = db.relationship('PostLike', backref='post', lazy=True, cascade='all, delete-orphan')

class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='post_likes')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('forum_post.id'))
    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'))
    content = db.Column(db.String(500))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notification_type = db.Column(db.String(20))  # 'mention', 'reply', 'like', etc.

    user = db.relationship('User', foreign_keys=[user_id])
    sender = db.relationship('User', foreign_keys=[sender_id])
    post = db.relationship('ForumPost')
    thread = db.relationship('ForumThread')

    def __repr__(self):
        return f'<Notification {self.id} for user {self.user_id}>'

class BlogCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.String(300), nullable=True)
    featured_image = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_published = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    
    # Relationships
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref=db.backref('blog_posts', lazy=True))
    category_id = db.Column(db.Integer, db.ForeignKey('blog_category.id'))
    category = db.relationship('BlogCategory', backref=db.backref('posts', lazy=True))

