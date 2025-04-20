from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField
from wtforms.validators import Length, EqualTo, Email,DataRequired,ValidationError
from mark.models import User, UserAPIKey

from wtforms import BooleanField  # Add this import at the top

class RegisterForm(FlaskForm):
    def validate_username(self, myusername):
        user = User.query.filter_by(username=myusername.data).first()
        if user:
            raise ValidationError('Username is already taken')
    
    def validate_email(self, myemail):
        mail = User.query.filter_by(email=myemail.data).first()
        if mail:
            raise ValidationError('Email is already registered')
    
    username = StringField(label="Username", validators=[Length(max=10, min=3), DataRequired()])
    email = StringField(label="E-mail", validators=[Email(), DataRequired()])
    password1 = PasswordField(label="Password 1", validators=[Length(max=10, min=3), DataRequired()])
    password2 = PasswordField(label="Password 2", validators=[EqualTo('password1'), DataRequired()])
    accept_tos = BooleanField('I accept the Terms of Service', 
                            validators=[DataRequired(message="You must accept the terms and conditions")])
    submit = SubmitField(label="Create Account")

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

class Authenticationform(FlaskForm):
    authotp=StringField(label="OTP",validators=[Length(max=6,min=6),DataRequired()])
    submit=SubmitField(label="SUBMIT OTP")

class APIKeyForm(FlaskForm):
    """Form for storing API keys securely."""
    
    def validate_api_key(self, field):
        """Ensure the API key is unique per user and exchange."""
        existing_key = UserAPIKey.query.filter_by(user_id=self.user_id.data, exchange=self.exchange.data).first()
        if existing_key:
            raise ValidationError("API key for this exchange already exists.")

    user_id = StringField("User ID", validators=[DataRequired()])  # Should be hidden in frontend
    exchange = StringField("Exchange Name", validators=[DataRequired()])
    api_key = StringField("API Key", validators=[Length(min=10), DataRequired()])
    api_secret = StringField("API Secret", validators=[Length(min=10), DataRequired()])
    submit = SubmitField("Save API Key")

from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class ThreadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Thread')

class PostForm(FlaskForm):
    content = TextAreaField('Message', validators=[Length(max=2000)])
    submit = SubmitField('Post')

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, FileField
from wtforms.validators import DataRequired, Length

class BlogPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    slug = StringField('Slug', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    excerpt = TextAreaField('Excerpt', validators=[Length(max=300)])
    featured_image = FileField('Featured Image')
    is_published = BooleanField('Publish')
    category_id = SelectField('Category', coerce=int, validators=[DataRequired()])
