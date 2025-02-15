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
import requests
from binance.client import Client
from flask import send_file,jsonify

def get_specific_prices_from_binance():
    response = requests.get("https://api.binance.com/api/v3/ticker/24hr")
    
    if response.status_code != 200:
        print("Error fetching data:", response.status_code)
        return []
    
    data = response.json()

    # List of specific cryptocurrencies to display
    specific_coins = [
        "BTCUSDT", "ETHUSDT", "USDTUSDT", "XRPUSDT", "SOLUSDT", "BNBUSDT",
        "USDCUSDT", "DOGEUSDT", "ADAUSDT", "TRXUSDT", "LINKUSDT"
    ]
    dup=[ "AVAXUSDT",
        "PEPEUSDT", "SUIUSDT", "TONUSDT", "HBARUSDT", "BCHUSDT", "SHIBUSDT",
        "XMRUSDT", "DOTUSDT", "LTCUSDT"]

    # Filter Binance data for the required symbols
    filtered_prices = [
        {
            'symbol': crypto['symbol'],
            'price': f"{float(crypto['lastPrice']):,.2f}",
            'priceChangePercent': crypto['priceChangePercent']
        }
        for crypto in data if crypto['symbol'] in specific_coins
    ]

    return filtered_prices
import requests

def get_specific_prices_from_coinmarketcap():
    # List of specific cryptocurrencies to display
    specific_coins = [
        "BTC", "ETH", "USDT", "XRP", "SOL", "BNB",
        "USDC", "DOGE", "ADA", "TRX", "LINK"
    ]
    dup = [
        "AVAX", "PEPE", "SUI", "TON", "HBAR", "BCH", "SHIB",
        "XMR", "DOT", "LTC"
    ]

    # CoinMarketCap API endpoint and your API key
    api_url = 'https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest'
    headers = {
        'Accept': 'application/json',
        'X-CMC_PRO_API_KEY': '16eb4846-14d3-460f-a807-829071a43a49',  # Replace with your valid API key
    }

    # Request data from CoinMarketCap API
    params = {
        'symbol': ','.join(specific_coins),  # Join the symbols with commas (e.g., 'BTC,ETH,LTC')
        'convert': 'USD',  # Fetch prices in USD
    }

    prices = []

    try:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)

        data = response.json()

        # Extracting price and price change data
        if 'data' in data:
            for symbol in specific_coins:
                if symbol in data['data']:
                    crypto = data['data'][symbol]
                    price = f"{float(crypto['quote']['USD']['price']):,.2f}"
                    price_change_percent = f"{float(crypto['quote']['USD']['percent_change_24h']):.2f}"

                    prices.append({
                        'symbol': symbol,
                        'price': price,
                        'priceChangePercent': price_change_percent
                    })
                else:
                    print(f"Warning: {symbol} data is not available in the response.")
        else:
            print(f"Error: Missing 'data' key in response: {data}")

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except KeyError as e:
        print(f"Error processing the response: Missing key {e}")

    return prices


def get_specific_prices_from_coinbase():
    # List of specific cryptocurrencies to display
    specific_coins = [
        "BTC-USD", "ETH-USD", "USDT-USD", "XRP-USD", "SOL-USD", "BNB-USD",
        "USDC-USD", "DOGE-USD", "ADA-USD", "TRX-USD", "LINK-USD"
    ]
    dup = [
        "AVAX-USD", "PEPE-USD", "SUI-USD", "TON-USD", "HBAR-USD", "BCH-USD",
        "SHIB-USD", "XMR-USD", "DOT-USD", "LTC-USD"
    ]

    prices = []
    
    try:
        for symbol in specific_coins:
            response = requests.get(f"https://api.coinbase.com/v2/prices/{symbol}/spot")
            if response.status_code == 200:
                data = response.json()
                price = f"{float(data['data']['amount']):,.2f}"

                # Coinbase doesn't provide percentage change, so we'll set it as "N/A"
                prices.append({
                    'symbol': symbol.replace("-USD", ""),  # Remove "-USD" for consistency
                    'price': price,
                    'priceChangePercent': "N/A"
                })
            else:
                print(f"Error fetching {symbol}: {response.status_code}")
            print(f"Response for {symbol}: {response.json()}")

    
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")

    return prices


@app.route('/')
@app.route('/home')
def home():
    binance_prices = get_specific_prices_from_binance()
    coinmarketcap_prices = get_specific_prices_from_coinmarketcap()
    for ticker in binance_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in coinmarketcap_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])
    return render_template('index.html', binance_prices=binance_prices, coinmarketcap_prices=coinmarketcap_prices)


@app.route('/binance_prices')
def binance_prices():
    binance_prices = get_specific_prices_from_binance()  # Fetch the latest data from Binance
    return jsonify(binance_prices)  # Return Binance data as JSON

@app.route('/coinmarketcap_prices')
def coinmarketcap_prices():
    coinmarketcap_prices = get_specific_prices_from_coinmarketcap()  # Fetch the latest data from CoinMarketCap
    return jsonify(coinmarketcap_prices)  # Return CoinMarketCap data as JSON

@app.route('/coinbase_prices')
def coinbase_prices():
    coinbase_prices = get_specific_prices_from_coinbase()  # Fetch the latest data from Coinbase
    return jsonify(coinbase_prices)  # Return Coinbase data as JSON


@app.route('/index')
@login_required
def index():
    user = User.query.filter_by(username=current_user.username).first()
    name = user.username
    email = user.email
    binance_prices = get_specific_prices_from_binance()
    coinmarketcap_prices = get_specific_prices_from_coinmarketcap()
    for ticker in binance_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in coinmarketcap_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])
    return render_template('index.html', name=name, email=email, binance_prices=binance_prices, coinmarketcap_prices=coinmarketcap_prices)

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
        username=user.username
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

@app.route('/charts')
def charts():
    return render_template('charts.html')