from mark import db
from mark import bcrypt
from mark import login_manager
from flask_login import UserMixin
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String())
    email=db.Column(db.String())
    password_hash=db.Column(db.String())

    @property
    def password(self):
        return self.password
    @password.setter
    def password(self,plain_password):
        self.password_hash=bcrypt.generate_password_hash(plain_password).decode("utf-8")

    def check_password(self,entered_password):
        return bcrypt.check_password_hash(self.password_hash,entered_password)
    
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(length=100))
    Roll=db.Column(db.Integer())
    Class=db.Column(db.String())

    def __repr__(self):
        return f'Item {self.name}'