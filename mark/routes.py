from mark import app, db, mail
from mark.form import RegisterForm, LoginForm, otpform, verifyform,Authenticationform
from mark.models import User, Item
from flask import render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
import random, requests
from flask_mail import Message
from flask_socketio import SocketIO
import time
from threading import Thread
import pyotp
import qrcode
import io
from flask import send_file
# Initialize SocketIO
socketio = SocketIO(app)

# Fetch cryptocurrency prices
def fetch_crypto_prices():
    prices = {}
    
    # Binance API
    binance_url = "https://api.binance.com/api/v3/ticker/price"
    binance_response = requests.get(binance_url)
    if binance_response.status_code == 200:
        binance_prices = binance_response.json()
        prices['Binance'] = {item['symbol']: item['price'] for item in binance_prices}

    # Coinbase API
    coinbase_url = "https://api.coinbase.com/v2/exchange-rates"
    coinbase_response = requests.get(coinbase_url)
    if coinbase_response.status_code == 200:
        coinbase_prices = coinbase_response.json().get('data', {}).get('rates', {})
        prices['Coinbase'] = {symbol: rate for symbol, rate in coinbase_prices.items()}
    
    return prices

# Function to send price updates using WebSocket
def send_price_updates():
    while True:
        prices = fetch_crypto_prices()
        socketio.emit('price_update', prices)
        time.sleep(10)  # Update every 10 seconds

# Start the price update loop in a background thread
price_thread = Thread(target=send_price_updates)
price_thread.daemon = True
price_thread.start()

@socketio.on('connect')
def handle_connect():
    print("Client connected!")

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/crypto')
def crypto_prices():
    prices = fetch_crypto_prices()
    return render_template('crypto.html', prices=prices)

@app.route('/index')
@login_required
def index():
    items = Item.query.all()
    name = session.get('userid')
    email = session.get('email')
    return render_template('index.html', items=items, name=name, email=email)

@app.route('/register', methods=['GET', 'POST'])
def register_form():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password1.data)
        db.session.add(user)
        db.session.commit()
        session['userid'] = user.username
        return redirect(url_for('otp_form'))
    if form.errors:
        for err in form.errors.values():
            flash(err)
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_form():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password(entered_password=form.password.data):
            session['userid'] = attempted_user.username
            return redirect(url_for('otp_form'))
        else:
            flash('Username and password are incorrect')
    
    if form.errors:
        for err in form.errors.values():
            flash(err)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    session.clear()  # Clears all session variables
    flash('You have been logged out')
    return redirect(url_for('home'))

def generate_otp():
    return random.randint(100000, 999999)

@app.route('/otp', methods=['GET', 'POST'])
def otp_form():
    user = User.query.filter_by(username=session['userid']).first()
    email = user.email
    otp = generate_otp()
    session['email'] = email
    session['otp'] = otp
    try:
        msg = Message('Your OTP', recipients=[email])
        msg.body = f'Your OTP is {otp}'
        mail.send(msg)
        flash("OTP sent successfully")
        return redirect(url_for('verify_form'))
    except Exception as e:
        flash(f'Unable to send OTP: {e}')
        return redirect(url_for('register_form'))

@app.route('/verifyotp', methods=['GET', 'POST'])
def verify_form():
    form = verifyform()
    auth_form=Authenticationform()
    user = User.query.filter_by(username=session['userid']).first()
    if form.validate_on_submit():
        entered_otp = form.userotp.data
        if entered_otp and str(session.get('otp')) == entered_otp:
            session.pop('otp', None)
            if user:
                if user.authenticator_enabled !=1:
                    session.pop('userid', None)
                    login_user(user)
                    return redirect(url_for('setup_authenticator')) 
                else:
                    return render_template('verify_otp.html', form=auth_form, username=session['userid'], show_auth_form=True)
                    
        else:
            flash('Incorrect OTP')

    if auth_form.validate_on_submit():
        entered_code = auth_form.authotp.data
        totp = pyotp.TOTP(user.authenticator_secret)
        if totp.verify(entered_code):
            login_user(user) 
            flash(f'User logged in successfully: {user.username}') 
            return redirect(url_for('index'))
        else:
            flash("Invalid authenticator code. Please try again.")
            return render_template('verify_otp.html', form=auth_form, username=session['userid'], show_auth_form=True)


    if form.errors:
        for err in form.errors.values():
            flash(err)
    return render_template('verify_otp.html', form=form, username=session['userid'], show_auth_form=False)

@app.route('/setup-authenticator', methods=['GET', 'POST'])
def setup_authenticator():
    user = User.query.filter_by(username=current_user.username).first()
    if not user.authenticator_secret:
        user.authenticator_secret = pyotp.random_base32()
        db.session.commit()
    
    otp_uri = pyotp.totp.TOTP(user.authenticator_secret).provisioning_uri(
        name=user.username,
        issuer_name="CryptExpert"
    )
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer)
    buffer.seek(0)

    form = Authenticationform()  # Define this form with an `auth_code` field
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.authenticator_secret)
        if totp.verify(form.authotp.data):
            user.authenticator_enabled = True
            db.session.commit()
            flash("Authenticator set up successfully!")
            return redirect(url_for('index'))
        else:
            flash("Invalid authenticator code. Please try again.")

    return render_template(
        'setup_authenticator.html',
        qr_code=buffer,
        form=form,
    )

@app.route('/setup-authenticator/qr')
@login_required
def setup_authenticator_qr():
    user = User.query.filter_by(username=current_user.username).first()

    if not user or not user.authenticator_secret:
        flash("Invalid access.")
        return redirect(url_for('index'))

    otp_uri = pyotp.totp.TOTP(user.authenticator_secret).provisioning_uri(
        name=user.username,
        issuer_name="CryptExpert"
    )
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer)
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')