from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import Length, EqualTo, Email,DataRequired,ValidationError
from mark.models import User
class RegisterForm(FlaskForm):
    def validate_username(self, myusername):
        user=User.query.filter_by(username=myusername.data).first()
        if(user):
            raise ValidationError('Username is already taken')
    def validate_email(self, myemail):
        mail=User.query.filter_by(email=myemail.data).first()
        if(mail):
            raise ValidationError('Email is already registered')
    username= StringField(label="Username" , validators=[Length(max=10,min=3),DataRequired()])
    email=StringField(label="E-mail",validators=[Email(),DataRequired()])
    password1=PasswordField(label="Password 1",validators=[Length(max=10,min=3),DataRequired()])
    password2=PasswordField(label="Password 2",validators=[EqualTo('password1'),DataRequired()])
    submit=SubmitField(label="Create Account")

class LoginForm(FlaskForm):
    username= StringField(label="Username" , validators=[Length(max=10,min=3),DataRequired()])
    password=PasswordField(label="Password",validators=[Length(max=10,min=3),DataRequired()])
    submit=SubmitField(label="Log in")

class otpform(FlaskForm):
    email=StringField(label="E-mail",validators=[Email(),DataRequired()])
    submit=SubmitField(label="Get OTP")

class verifyform(FlaskForm):
    userotp=StringField(label="OTP",validators=[Length(max=6,min=6),DataRequired()])
    submit=SubmitField(label="SUBMIT OTP")