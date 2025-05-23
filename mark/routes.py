from mark import app, db, mail
from mark.form import RegisterForm, LoginForm, otpform, verifyform,Authenticationform,ThreadForm,PostForm
from mark.models import User, Item, CryptoAsset, Exchange, UserAPIKey, ForumCategory, ForumThread, ForumPost, PostLike,Notification
from flask import render_template,request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
import random, requests
from flask_mail import Message
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_socketio import emit
import time
from threading import Thread
import pyotp
import qrcode
import io
import requests
from binance.client import Client
from flask import send_file,jsonify
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import matplotlib
import matplotlib.pyplot as plt
import io
import base64
from mark.models import ForumCategory, ForumThread, ForumPost
from datetime import datetime
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import asyncio
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import pandas as pd
import numpy as np
from mark import socketio

crypto_logos = {
    "BTC": "https://cryptologos.cc/logos/bitcoin-btc-logo.png",
    "ETH": "https://cryptologos.cc/logos/ethereum-eth-logo.png",
    "XRP": "https://cryptologos.cc/logos/xrp-xrp-logo.png",
    "BNB": "https://cryptologos.cc/logos/binance-coin-bnb-logo.png",
    "SOL": "https://cryptologos.cc/logos/solana-sol-logo.png",
    "USDC": "https://cryptologos.cc/logos/usd-coin-usdc-logo.png",
    "ADA": "https://cryptologos.cc/logos/cardano-ada-logo.png",
    "DOGE": "https://cryptologos.cc/logos/dogecoin-doge-logo.png",
    "TRX": "https://cryptologos.cc/logos/tron-trx-logo.png",
    "LINK": "https://cryptologos.cc/logos/chainlink-link-logo.png",
    "HBAR": "https://cryptologos.cc/logos/hedera-hbar-logo.png",
    "XLM": "https://cryptologos.cc/logos/stellar-xlm-logo.svg",
    "AVAX": "https://cryptologos.cc/logos/avalanche-avax-logo.png",
    "LEO": "https://cryptologos.cc/logos/unus-sed-leo-leo-logo.png",
    "SUI": "https://cryptologos.cc/logos/sui-sui-logo.png",
    "LTC": "https://cryptologos.cc/logos/litecoin-ltc-logo.png",
    "TON": "https://cryptologos.cc/logos/toncoin-ton-logo.png",
    "SHIB": "https://cryptologos.cc/logos/shiba-inu-shib-logo.png",
    "DOT": "https://cryptologos.cc/logos/polkadot-new-dot-logo.png",
    "BCH": "https://cryptologos.cc/logos/bitcoin-cash-bch-logo.png",
    "DAI": "https://cryptologos.cc/logos/multi-collateral-dai-dai-logo.png",
    "UNI": "https://cryptologos.cc/logos/uniswap-uni-logo.png",
    "XMR": "https://cryptologos.cc/logos/monero-xmr-logo.png",
    "NEAR": "https://cryptologos.cc/logos/near-protocol-near-logo.png",
    "APT": "https://cryptologos.cc/logos/aptos-apt-logo.png",
    "ICP": "https://cryptologos.cc/logos/internet-computer-icp-logo.png",
    "ETC": "https://cryptologos.cc/logos/ethereum-classic-etc-logo.png",
    "AAVE": "https://cryptologos.cc/logos/aave-aave-logo.png",
    "OKB": "https://cryptologos.cc/logos/okb-okb-logo.png",
    "VET": "https://cryptologos.cc/logos/vechain-vet-logo.png",
    "ALGO": "https://cryptologos.cc/logos/algorand-algo-logo.png",
    "CRO": "https://cryptologos.cc/logos/crypto-com-coin-cro-logo.png",
    "FIL": "https://cryptologos.cc/logos/filecoin-fil-logo.png",
    "ARB": "https://cryptologos.cc/logos/arbitrum-arb-logo.png",
    "KNC": "https://cryptologos.cc/logos/kyber-network-knc-logo.png",
    "BAL": "https://cryptologos.cc/logos/balancer-bal-logo.png",
    "YFI": "https://cryptologos.cc/logos/yearn-finance-yfi-logo.png",
    "SUSHI": "https://cryptologos.cc/logos/sushiswap-sushi-logo.png",
    "ZRX": "https://cryptologos.cc/logos/0x-zrx-logo.png",
    "UMA": "https://cryptologos.cc/logos/uma-uma-logo.png",
    "GRT": "https://cryptologos.cc/logos/the-graph-grt-logo.png",
    "1INCH": "https://cryptologos.cc/logos/1inch-1inch-logo.png",
    "LRC": "https://cryptologos.cc/logos/loopring-lrc-logo.png",
    "FET": "https://cryptologos.cc/logos/fetch-ai-fet-logo.png",
    "HNT": "https://cryptologos.cc/logos/helium-hnt-logo.png",
    "RUNE": "https://cryptologos.cc/logos/thorchain-rune-logo.png",
    "SAND": "https://cryptologos.cc/logos/the-sandbox-sand-logo.png",
    "CELO": "https://cryptologos.cc/logos/celo-celo-logo.png",
    "DASH": "https://cryptologos.cc/logos/dash-dash-logo.png",
    "REN":"https://cryptologos.cc/logos/ren-ren-logo.png",
    # Manually added (not found on cryptologos)
    "OM": "https://cryptologos.cc/logos/mantra-dao-om-logo.png",
    "HYPE": "https://cryptologos.cc/logos/hype-token-hype-logo.png",
    "USDe": "https://cryptologos.cc/logos/usde-usde-logo.png",
    "BGB": "https://cryptologos.cc/logos/bitget-token-bgb-logo.png",
    "ONDO": "https://cryptologos.cc/logos/ondo-ondo-logo.png",
    "PEPE": "https://cryptologos.cc/logos/pepe-pepe-logo.png",
    "TRUMP": "https://cryptologos.cc/logos/trumpcoin-trump-logo.png",
    "TAO": "https://cryptologos.cc/logos/lamden-tao-logo.png",
    "MNT": "https://cryptologos.cc/logos/mintcoin-mnt-logo.png",
    "POL": "https://cryptologos.cc/logos/proof-of-liquidity-pol-logo.png",
    "KAS": "https://cryptologos.cc/logos/kaspa-kas-logo.png",
    "RENDER": "https://cryptologos.cc/logos/render-token-render-logo.png",
    "FDUSD": "https://cryptologos.cc/logos/fd-usd-fdusd-logo.png",
    "TIA": "https://cryptologos.cc/logos/tiara-tia-logo.png",
    "JUP": "https://cryptologos.cc/logos/jupiter-jup-logo.png",
    "GT": "https://cryptologos.cc/logos/gatechain-token-gt-logo.png",
    "S": "https://cryptologos.cc/logos/sentinel-protocol-s-logo.png",
    "MK": "https://cryptologos.cc/logos/mk-mk-logo.png",
    "RARI": "https://cryptologos.cc/logos/rarible-rari-logo.png",
    "CVC": "https://cryptologos.cc/logos/civic-cvc-logo.png",
    "MITH": "https://cryptologos.cc/logos/mithril-mith-logo.png",
    "LOOM": "https://cryptologos.cc/logos/loom-network-loom-logo.png",
    "GNO": "https://cryptologos.cc/logos/gnosis-gno-logo.png",
    "DIA": "https://cryptologos.cc/logos/dia-dia-logo.png",
    "STMX": "https://cryptologos.cc/logos/stormx-stmx-logo.png",
    "PERL": "https://cryptologos.cc/logos/perlin-perl-logo.png",
    "REN": "https://cryptologos.cc/logos/ren-ren-logo.png",
    "DODO": "https://cryptologos.cc/logos/dodo-dodo-logo.png",
    "MTA": "https://cryptologos.cc/logos/meta-mta-logo.png"
}

def get_specific_prices_from_binance():
    response = requests.get("https://api.binance.com/api/v3/ticker/24hr")

    if response.status_code != 200:
        print("Error fetching data:", response.status_code)
        return []

    data = response.json()

    # List of specific cryptocurrencies to display
    specific_coins_usdt = [
        'BTCUSDT', 'ETHUSDT', 'XRPUSDT', 'BNBUSDT', 'SOLUSDT', 'USDCUSDT', 'ADAUSDT', 'DOGEUSDT', 'TRXUSDT',
        'LINKUSDT', 'HBARUSDT', 'XLMUSDT', 'AVAXUSDT', 'LEOUSDT', 'SUIUSDT', 'LTCUSDT', 'TONUSDT', 'SHIBUSDT',
        'DOTUSDT', 'OMUSDT', 'BCHUSDT',  'DAIUSDT', 'UNIUSDT', 'XMRUSDT', 'NEARUSDT',
        'APTUSDT',  'PEPEUSDT'
    ]



    # Filter Binance data for the required symbols
    filtered_prices = [
        {
            'symbol': crypto['symbol'],
            'price': f"{float(crypto['lastPrice']):,.2f}",
            'priceChangePercent': crypto['priceChangePercent']
        }
        for crypto in data if crypto['symbol'] in specific_coins_usdt
    ]

    return filtered_prices
import requests



def get_specific_prices_from_okx():
    # List of specific cryptocurrency pairs (adjust as needed)
    specific_coins = [
    'BTC-USDT', 'ETH-USDT', 'XRP-USDT', 'BNB-USDT', 'SOL-USDT', 'USDC-USDT', 'ADA-USDT', 'DOGE-USDT', 'TRX-USDT',
    'LINK-USDT', 'HBAR-USDT', 'XLM-USDT', 'AVAX-USDT', 'LEO-USDT', 'SUI-USDT', 'LTC-USDT', 'TON-USDT', 'SHIB-USDT',
    'DOT-USDT', 'OM-USDT', 'BCH-USDT', 'DAI-USDT', 'UNI-USDT', 'XMR-USDT', 'NEAR-USDT',
    'APT-USDT',  'PEPE-USDT'
]

    prices = []

    try:
        for symbol in specific_coins:
            # Make the API request to fetch price data from OKX
            url = f"https://www.okx.com/api/v5/market/ticker?instId={symbol}"
            response = requests.get(url)

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and len(data['data']) > 0:
                    ticker = data['data'][0]
                    price = f"{float(ticker['last']):,.2f}"  # Extract the last price

                    # Get the price change percentage, but ensure we handle invalid data correctly
                    price_change_percent = ticker.get('change24h', "N/A")

                    # If 'price_change_percent' is 'N/A' or not a number, set it to 0.0
                    try:
                        price_change_percent = float(price_change_percent) * 100 if price_change_percent != "N/A" else 0.0
                    except ValueError:
                        price_change_percent = 0.0  # Fallback in case of invalid value

                    prices.append({
                        'symbol': symbol.replace("-USDT", ""),  # Remove "-USDT" for consistency
                        'price': price,
                        'priceChangePercent': f"{price_change_percent:.2f}"
                    })
                else:
                    print(f"Error: Data not found for {symbol}")
            else:
                print(f"Error fetching {symbol}: {response.status_code}")

            print(f"Response for {symbol}: {response.json()}")

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")

    return prices


def get_specific_prices_from_coinbase():
    # List of specific cryptocurrencies to display
    specific_coins = [
        "BTC-USD", "ETH-USD", "USDT-USD", "XRP-USD", "SOL-USD", "BNB-USD",
        "USDC-USD", "DOGE-USD", "ADA-USD", "TRX-USD", "LINK-USD","AVAX-USD", "PEPE-USD", "SUI-USD", "TON-USD", "HBAR-USD", "BCH-USD",
        "SHIB-USD", "XMR-USD", "DOT-USD", "LTC-USD"
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
                    'priceChangePercent': 0
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
    return render_template('index.html')


@app.route('/binance_prices')
def binance_prices():
    binance_prices = get_specific_prices_from_binance()  # Fetch the latest data from Binance
    return jsonify(binance_prices)  # Return Binance data as JSON

@app.route('/okx_prices')
def okx_prices():
    okx_prices = get_specific_prices_from_okx()  # Fetch the latest data from okx
    return jsonify(okx_prices)  # Return okx data as JSON

@app.route('/coinbase_prices')
def coinbase_prices():
    coinbase_prices = get_specific_prices_from_coinbase()  # Fetch the latest data from Coinbase
    return jsonify(coinbase_prices)  # Return Coinbase data as JSON


@app.route('/index')
@login_required
def index():


    return render_template('index.html')

@app.route('/live_prices')
def live_prices():
    binance_prices = get_specific_prices_from_binance()
    okx_prices = get_specific_prices_from_okx()
    coinbase_prices = get_specific_prices_from_coinbase()

    for ticker in binance_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in okx_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in coinbase_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    return render_template('live_prices.html', binance_prices=binance_prices, okx_prices=okx_prices, coinbase_prices=coinbase_prices,crypto_logos=crypto_logos)


@app.route('/register', methods=['GET', 'POST'])
def register_form():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email is already registered. Please use a different email or login.', 'error')
            return redirect(url_for('register_form'))
            
        # Check if username already exists
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash('Username is already taken. Please choose another.', 'error')
            return redirect(url_for('register_form'))
            
        # Create new user if checks pass
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password1.data  # Make sure this hashes the password
        )
        db.session.add(user)
        db.session.commit()
        session['userid'] = user.username
        return redirect(url_for('otp_form'))
        
    # Handle form errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "warning")
                
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_form():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password(entered_password=form.password.data):
            session['userid'] = attempted_user.username
            next_page = request.args.get('next')  # Get the 'next' parameter
            return redirect(url_for('otp_form', next=next_page))  # Pass 'next' to OTP form
        else:
            flash('Username and password are incorrect', "error")

    if form.errors:
        for err in form.errors.values():
            flash(err, "warning")
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    session.clear()  # Clears all session variables
    flash('You have been logged out',"success")
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
    next_page = request.args.get('next')  # Get the 'next' parameter
    try:
        msg = Message('Cryptexpert OTP Verification', recipients=[email])
        msg.html = f'''
    <p>Dear Valued User,</p>

    <p>Your One-Time Password (OTP) for Cryptexpert authentication is: <b>{otp}</b></p>
    
    <p>This OTP is valid for a limited time. Please do not share it with anyone.</p>
    
    <p>If you did not request this OTP, please ignore this email.</p>
    
    <p>Best regards,<br>
    <b>Cryptexpert Team</b><br>
    Secure Your Crypto Investments with Confidence.</p>
'''

        mail.send(msg)
        flash("OTP sent successfully", "success")
        return redirect(url_for('verify_form', next=next_page))  # Pass 'next' to verify form
    except Exception as e:
        flash(f'Unable to send OTP: {e}', "error")
        return redirect(url_for('register_form'))

@app.route('/verifyotp', methods=['GET', 'POST'])
def verify_form():
    form = verifyform()
    auth_form = Authenticationform()
    user = User.query.filter_by(username=session['userid']).first()
    next_page = request.args.get('next')  # Get the 'next' parameter

    if form.validate_on_submit():
        entered_otp = form.userotp.data
        if entered_otp and str(session.get('otp')) == entered_otp:
            session.pop('otp', None)
            if user:
                if user.authenticator_enabled != 1:
                    session.pop('userid', None)
                    login_user(user)
                    return redirect(url_for('setup_authenticator', next=next_page))  # Pass 'next' to setup authenticator
                else:
                    return render_template('verify_otp.html', form=auth_form, username=session['userid'], show_auth_form=True, next=next_page)
        else:
            flash('Incorrect OTP', "error")

    if auth_form.validate_on_submit():
        entered_code = auth_form.authotp.data
        totp = pyotp.TOTP(user.authenticator_secret)
        if totp.verify(entered_code):
            login_user(user) 
            flash(f'User logged in successfully: {user.username}', "success") 
            if next_page:
                return redirect(next_page)  # Redirect to the 'next' page
            else:
                return redirect(url_for('index'))  # Default to the home page
        else:
            flash("Invalid authenticator code. Please try again.", "warning")
            return render_template('verify_otp.html', form=auth_form, username=session['userid'], show_auth_form=True, next=next_page)

    if form.errors:
        for err in form.errors.values():
            flash(err, "warning")
    return render_template('verify_otp.html', form=form, username=session['userid'], show_auth_form=False, next=next_page)

from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt="password-reset")

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt="password-reset", max_age=expiration)
        return email
    except:
        return None

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)

            #Send email
            msg = Message(
                subject="Cryptexpert - Password Reset Request",
                recipients=[email]
            )

            msg.body = f"""
            Dear {user.username},
            
            We received a request to reset the password for your Cryptexpert account.
            To proceed, please click the link below:
            
            {reset_url}
            
            If you did not request this reset, please ignore this email. Your account security is important to us.
            
            Best regards,  
            Cryptexpert Team  
            """

            mail.send(msg)


            flash('Password reset link has been sent to your email.', 'success')
            return redirect(url_for('login_form'))
        else:
            flash('No account found with this email.', 'error')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        new_password = request.form.get('password')
        user.password = new_password
        db.session.commit()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login_form'))

    return render_template('reset_password.html')


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
            flash("Authenticator set up successfully!","success")
            return redirect(url_for('index'))
        else:
            flash("Invalid authenticator code. Please try again.","error")

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
        flash("Invalid access.","error")
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

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', current_user=current_user)

@app.route('/charts')
def charts():
    # Pass the current_user object and the current path to the template
    return render_template('charts.html', user=current_user, next=request.path)


# Load the trained model
# Load the trained model
model = load_model("/home/ec2-user/cryptexpert/mark/model.keras")



# Initialize Binance Client (No API Key Required for Public Data)
client = Client()

import seaborn as sns
plt.style.use("dark_background")  # Apply dark mode
sns.set_palette("coolwarm")       # Use a stylish color scheme

def plot_to_html(fig):
    """Convert Matplotlib figure to HTML image."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    buf.seek(0)
    data = base64.b64encode(buf.getbuffer()).decode("ascii")
    buf.close()
    return f"data:image/png;base64,{data}"



def get_historical_klines(symbol, interval, start_str, end_str=None):
    """Fetch historical candlestick data from Binance API."""
    all_data = []
    start_ts = int(pd.to_datetime(start_str).timestamp() * 1000)
    end_ts = int(pd.to_datetime(end_str).timestamp() * 1000) if end_str else None

    while True:
        new_klines = client.get_klines(
            symbol=symbol,
            interval=interval,
            startTime=start_ts,
            endTime=end_ts,
            limit=1000
        )

        if not new_klines:
            break  # Stop when no more data is returned

        all_data.extend(new_klines)
        start_ts = new_klines[-1][0] + 1  # Move to the next timestamp
        time.sleep(0.5)  # Avoid exceeding Binance rate limits

    return all_data
@app.route("/ai_predictor", methods=["GET", "POST"])
def ai_predictor():
    if request.method == "POST":
        stock = request.form.get("stock", "BTCUSDT")
        no_of_days = int(request.form.get("no_of_days", 10))

        # Fetch Historical Data from Binance
        klines = get_historical_klines(symbol=stock, interval=Client.KLINE_INTERVAL_1DAY, start_str="2017-08-17")

        # Convert to DataFrame
        stock_data = pd.DataFrame(klines, columns=[
            'Open Time', 'Open', 'High', 'Low', 'Close', 'Volume', 'Close Time',
            'Quote Asset Volume', 'Number of Trades', 'Taker Buy Base Asset Volume',
            'Taker Buy Quote Asset Volume', 'Ignore'
        ])
        stock_data['Close'] = stock_data['Close'].astype(float)
        stock_data.index = pd.to_datetime(stock_data['Close Time'], unit='ms')

        if stock_data.empty:
            return render_template("ai_price_predictor.html", error="Invalid crypto pair or no data available.")

        # Prepare candlestick data for visualization
        candlestick_data = stock_data[['Close Time', 'Open', 'High', 'Low', 'Close', 'Volume']].tail(200)
        candlestick_json = candlestick_data.to_json(orient="records")

        # Data Preparation for Prediction
        splitting_len = int(len(stock_data) * 0.9)
        x_test = stock_data[['Close']][splitting_len:]

        scaler = MinMaxScaler(feature_range=(0, 1))
        scaled_data = scaler.fit_transform(x_test)

        x_data, y_data = [], []
        for i in range(100, len(scaled_data)):
            x_data.append(scaled_data[i - 100:i])
            y_data.append(scaled_data[i])

        x_data, y_data = np.array(x_data), np.array(y_data)

        # Make Predictions
        predictions = model.predict(x_data)
        inv_predictions = scaler.inverse_transform(predictions)
        inv_y_test = scaler.inverse_transform(y_data)

        # Prepare Data for Plotting
        plotting_data = pd.DataFrame({
            'Original Test Data': inv_y_test.flatten(),
            'Predicted Test Data': inv_predictions.flatten()
        }, index=x_test.index[100:])
        plt.style.use('dark_background')

        # Generate Plots
        # Plot 1: Original Closing Prices
        fig1 = plt.figure(figsize=(15, 6))
        plt.plot(stock_data['Close'], 'b', label='Close Price')
        plt.title("Closing Prices Over Time")
        plt.xlabel("Date")
        plt.ylabel("Close Price")
        plt.legend()
        original_plot = plot_to_html(fig1)

        # Plot 2: Original vs Predicted Test Data
        fig2 = plt.figure(figsize=(15, 6))
        plt.plot(plotting_data['Original Test Data'], label="Original Test Data")
        plt.plot(plotting_data['Predicted Test Data'], label="Predicted Test Data", linestyle="--")
        plt.legend()
        plt.title("Original vs Predicted Closing Prices")
        plt.xlabel("Date")
        plt.ylabel("Close Price")
        predicted_plot = plot_to_html(fig2)

        # Plot 3: Future Predictions
        last_100 = stock_data[['Close']].tail(100)
        last_100_scaled = scaler.transform(last_100)

        future_predictions = []
        last_100_scaled = last_100_scaled.reshape(1, -1, 1)
        for _ in range(no_of_days):
            next_day = model.predict(last_100_scaled)
            future_predictions.append(scaler.inverse_transform(next_day))
            last_100_scaled = np.append(last_100_scaled[:, 1:, :], next_day.reshape(1, 1, -1), axis=1)

        future_predictions = np.array(future_predictions).flatten()

        fig3 = plt.figure(figsize=(15, 6))
        plt.plot(range(1, no_of_days + 1), future_predictions, marker='o', label="Predicted Future Prices", color="purple")
        plt.title("Future Close Price Predictions")
        plt.xlabel("Days Ahead")
        plt.ylabel("Predicted Close Price")
        plt.grid(alpha=0.3)
        plt.legend()
        future_plot = plot_to_html(fig3)

        return render_template(
            "ai_price_predictor.html",
            stock=stock,
            candlestick_json=candlestick_json,
            predicted_plot=predicted_plot,
            future_plot=future_plot,
            enumerate=enumerate,
            future_predictions=future_predictions
        )
    return render_template("ai_price_predictor.html")

@app.route('/search')
def search():
    query = request.args.get('q', '').strip().lower()

    if not query:
        return jsonify([])

    try:
        # Search for partial matches in name or symbol
        results = CryptoAsset.query.filter(
            (CryptoAsset.name.ilike(f"%{query}%")) | 
            (CryptoAsset.symbol.ilike(f"%{query}%"))
        ).limit(10).all()

        # Get current prices from Binance for matching symbols
        binance_prices = get_specific_prices_from_binance()
        price_map = {price['symbol'].replace('USDT', ''): price for price in binance_prices}

        # Format the results with price data
        response = []
        for asset in results:
            price_data = price_map.get(asset.symbol.upper())
            
            result = {
    "name": asset.name,
    "symbol": asset.symbol,
    "type": "crypto",
    "link": asset.link,
    "image": f"/static/img/crypto/{asset.symbol.upper()}.png"
}

            
            if price_data:
                result.update({
                    "price": float(price_data['price'].replace(',', '')),
                    "price_change": float(price_data['priceChangePercent'])
                })
            
            response.append(result)

        return jsonify(response)

    except Exception as e:
        app.logger.error(f"Search error: {str(e)}")
        return jsonify({"error": "Search failed"}), 500





import asyncio
from binance import AsyncClient  # Use AsyncClient for Binance API


import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
def get_wallet_balances(api_key, api_secret, exchange):
    """Fetches wallet balances from different exchanges."""
    try:
        if exchange.lower() == "binance":
            return asyncio.run(get_binance_balances_async(api_key, api_secret))

        elif exchange.lower() == "coindcx":
            return get_coindcx_balances(api_key, api_secret)

        elif exchange.lower() == "wazirx":
            return get_wazirx_balances(api_key, api_secret)

        else:
            logging.error(f"Unsupported exchange: {exchange}")
            return None, 0.0

    except Exception as e:
        logging.error(f"Error in get_wallet_balances: {e}")
        return None, 0.0

import asyncio
from binance import AsyncClient, BinanceAPIException
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

async def get_binance_balances_async(api_key, api_secret):
    """Fetches wallet balances from Binance asynchronously and calculates total balance in USD."""
    client = None
    try:
        # Initialize Binance client
        client = await AsyncClient.create(api_key, api_secret)
        logging.debug("Binance client created successfully.")

        # Fetch account info
        account_info = await client.get_account()
        logging.debug("Account info fetched successfully.")

        # Extract non-zero balances
        balances = {asset["asset"]: float(asset["free"]) for asset in account_info["balances"] if float(asset["free"]) > 0}
        logging.debug(f"Non-zero balances: {balances}")

        # Fetch USD prices for all assets
        total_balance_usd = 0.0
        for asset, amount in balances.items():
            symbol = f"{asset}USDT"
            try:
                price_info = await client.get_symbol_ticker(symbol=symbol)
                asset_price = float(price_info["price"])
                total_balance_usd += amount * asset_price
                logging.debug(f"Fetched price for {symbol}: {asset_price}")
            except BinanceAPIException as e:
                logging.warning(f"Failed to fetch price for {symbol}: {e}")
                continue  # Skip if price fetch fails

        logging.debug(f"Total balance in USD: {total_balance_usd}")
        return balances, total_balance_usd

    except BinanceAPIException as e:
        logging.error(f"Binance API Error: {e}")
        return None, 0.0
    except Exception as e:
        logging.error(f"Unexpected error in get_binance_balances_async: {e}")
        return None, 0.0
    finally:
        if client:
            await client.close_connection()
            logging.debug("Binance client connection closed.")


# Define the specific coins you want to fetch trades for
specific_coins_trades = [
    "BTCUSDT", "ETHUSDT", "XRPUSDT", "SOLUSDT", "BNBUSDT",
    "DOGEUSDT", "ADAUSDT", "TRXUSDT", "LINKUSDT", "AVAXUSDT", 
    "PEPEUSDT", "SUIUSDT", "TONUSDT", "FLOKIUSDT", "BCHUSDT",
    "SHIBUSDT", "XMRUSDT", "DOTUSDT", "LTCUSDT"
]

async def get_binance_transactions_async(api_key, api_secret):
    """Fetches transaction history for specific coins from Binance asynchronously."""
    client = None
    try:
        client = await AsyncClient.create(api_key, api_secret)

        # Step 1: Fetch trade history only for the specified coins
        all_trades = []
        for symbol in specific_coins_trades:
            try:
                # Fetch trades for the current symbol
                trades = await client.get_my_trades(symbol=symbol)
                if trades:
                    all_trades.extend(trades)  # Add trades to the list
                    logging.debug(f"Fetched {len(trades)} trades for {symbol}")

                # Add a delay to respect Binance's rate limits
                await asyncio.sleep(0.1)  # 100ms delay between requests

            except BinanceAPIException as e:
                logging.error(f"Binance API Error for symbol {symbol}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error for symbol {symbol}: {e}")

        return all_trades  # Return all trades for the specified coins

    except BinanceAPIException as e:
        logging.error(f"Binance API Error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error in get_binance_transactions_async: {e}")
        return None
    finally:
        if client:
            await client.close_connection()


# Define the datetimeformat filter
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a timestamp to a human-readable format."""
    if isinstance(value, int):
        # If the value is a timestamp in milliseconds, convert it to seconds
        value = value / 1000
    return datetime.utcfromtimestamp(value).strftime(format)

# Register the filter in the Jinja2 environment
app.jinja_env.filters['datetimeformat'] = datetimeformat
import hmac
import hashlib
import json
import time
import requests
import logging
def get_coindcx_balances(api_key, api_secret):
    """Fetches wallet balances from CoinDCX."""
    try:
        # Step 1: Generate a timestamp in milliseconds
        timestamp = int(round(time.time() * 1000))

        # Step 2: Create the JSON body
        body = {
            "timestamp": timestamp
        }
        json_body = json.dumps(body, separators=(',', ':'))

        # Step 3: Generate the signature using HMAC-SHA256
        secret_bytes = bytes(api_secret, encoding='utf-8')
        signature = hmac.new(secret_bytes, json_body.encode(), hashlib.sha256).hexdigest()

        # Step 4: Set up the headers
        headers = {
            'Content-Type': 'application/json',
            'X-AUTH-APIKEY': api_key,
            'X-AUTH-SIGNATURE': signature
        }

        # Step 5: Make the POST request
        url = "https://api.coindcx.com/exchange/v1/users/balances"
        response = requests.post(url, data=json_body, headers=headers)

        # Log the raw response for debugging
        print("API Response:", response.text)

        # Step 6: Handle the response
        if response.status_code == 200:
            data = response.json()
            print("Parsed Data:", data)

            # Handle empty or zero balances
            if not data:
                return {}, 0.0  # Return empty balances and zero total balance

            # Extract non-zero balances
            balances = {
                balance["currency"]: float(balance["balance"])
                for balance in data
                if float(balance["balance"]) > 0
            }

            # Calculate total balance in USD (if needed)
            total_balance_usd = sum(balances.values())  # This assumes all balances are already in USD
            return balances, total_balance_usd

        else:
            # Log the error if the request fails
            logging.error(f"CoinDCX API Error: {response.status_code} - {response.text}")
            return None, 0.0

    except Exception as e:
        # Log any unexpected errors
        logging.error(f"CoinDCX API Error: {e}")
        return None, 0.0

def get_wazirx_balances(api_key, api_secret):
    """Fetches wallet balances from WazirX."""
    try:
        # Step 1: Generate a timestamp in milliseconds
        timestamp = int(round(time.time() * 1000))

        # Step 2: Create the query string
        query_string = f"timestamp={timestamp}"

        # Step 3: Generate the signature using HMAC-SHA256
        signature = hmac.new(api_secret.encode(), query_string.encode(), hashlib.sha256).hexdigest()

        # Step 4: Set up the headers
        headers = {
            "X-Api-Key": api_key,
            "X-Api-Signature": signature,
        }

        # Step 5: Make the GET request
        url = f"https://api.wazirx.com/api/v2/funds?{query_string}"
        response = requests.get(url, headers=headers)

        # Log the raw response for debugging
        print("WazirX API Response:", response.text)

        # Step 6: Handle the response
        if response.status_code == 200:
            data = response.json()
            print("Parsed Data:", data)

            # Extract non-zero balances
            balances = {
                balance["asset"]: float(balance["free"])
                for balance in data
                if float(balance["free"]) > 0
            }

            # Calculate total balance in USD (if needed)
            total_balance_usd = sum(balances.values())  # This assumes all balances are already in USD
            return balances, total_balance_usd

        else:
            # Log the error if the request fails
            logging.error(f"WazirX API Error: {response.status_code} - {response.text}")
            return None, 0.0

    except Exception as e:
        # Log any unexpected errors
        logging.error(f"WazirX API Error: {e}")
        return None, 0.0

@app.route("/wallet_management", methods=["GET", "POST"])
@login_required
def wallet_management():
    user_id = current_user.id

    # Handle API Key Submission
    if request.method == "POST" and "api_key" in request.form:
        exchange = request.form.get("exchange")
        api_key = request.form.get("api_key")
        api_secret = request.form.get("api_secret")

        if not exchange or not api_key or not api_secret:
            flash("All fields are required!", "error")
            return redirect(url_for("wallet_management"))

        # Check if API key for this exchange already exists
        existing_key = UserAPIKey.query.filter_by(user_id=user_id, exchange=exchange).first()
        if existing_key:
            flash(f"API key for {exchange} already exists!", "warning")
            return redirect(url_for("wallet_management"))

        # Encrypt and store API keys
        new_api_key = UserAPIKey(user_id=user_id, exchange=exchange, api_key=api_key, api_secret=api_secret)
        db.session.add(new_api_key)
        db.session.commit()

        flash("API key added successfully!", "success")
        return redirect(url_for("wallet_management"))

    # Handle API Key Deletion
    if request.method == "POST" and "delete_api_key" in request.form:
        exchange = request.form.get("exchange")
        api_key_entry = UserAPIKey.query.filter_by(user_id=user_id, exchange=exchange).first()

        if api_key_entry:
            db.session.delete(api_key_entry)
            db.session.commit()
            flash(f"API key for {exchange} deleted successfully!", "success")
        else:
            flash(f"API key for {exchange} not found!", "error")

        return redirect(url_for("wallet_management"))

    # Fetch all exchanges and their balances
    user_exchanges = UserAPIKey.query.filter_by(user_id=user_id).all()
    exchange_data = []
    exchange_names = []
    exchange_balances = []
    all_transactions = []
    for exchange in ["Binance", "Wazirx", "CoinDCX"]:  # Replace Coinbase with CoinDCX
        api_key_entry = UserAPIKey.query.filter_by(user_id=user_id, exchange=exchange).first()
        balances = None
        total_balance_usd = None
        transactions = None

        if exchange == "Binance":
            logo_url = "https://w7.pngwing.com/pngs/703/998/png-transparent-binance-binancecoin-blockchain-coin-blockchain-classic-icon-thumbnail.png"
        elif exchange == "Wazirx":
            logo_url = "https://www.svgrepo.com/show/331638/wazirx.svg"
        else:
            logo_url = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR3Z7jjYiJS75NtXWpoSKRgKjnRw76IvszehQ&s"  # Replace with CoinDCX logo URL

        if api_key_entry:
            # Fetch balances and transactions if API key exists
            api_key, api_secret = api_key_entry.get_api_keys()
            balances, total_balance_usd = get_wallet_balances(api_key, api_secret, exchange)
            if exchange == "Binance":
                transactions = asyncio.run(get_binance_transactions_async(api_key, api_secret))
                for txn in transactions:
                    txn["exchange"] = "Binance"  # Add exchange field to each transaction
                all_transactions.extend(transactions)
        exchange_data.append({
            "name": exchange,
            "api_key_exists": api_key_entry is not None,
            "balances": balances,
            "total_balance_usd": total_balance_usd,
            "transactions": transactions,
            "logo_url": logo_url
        })

        if api_key_entry is not None and total_balance_usd is not None:
            exchange_names.append(exchange)
            exchange_balances.append(total_balance_usd)

    return render_template(
        "wallet_management.html",
        exchange_data=exchange_data,
        exchange_names=exchange_names,
        exchange_balances=exchange_balances,
        all_transactions=all_transactions,
        total_balance_all_exchanges=sum(exchange_balances)  # Calculate total balance across all exchanges
    )

@app.route("/delete_api_key/<int:api_id>", methods=["POST"])
@login_required
def delete_api_key(api_id):
    api_key_entry = UserAPIKey.query.filter_by(id=api_id, user_id=current_user.id).first()

    if not api_key_entry:
        flash("API key not found!", "error")
        return redirect(url_for("wallet_management"))

    db.session.delete(api_key_entry)
    db.session.commit()

    flash("API key removed successfully!", "success")
    return redirect(url_for("wallet_management"))


@app.route("/refresh_balances", methods=["GET"])
@login_required
def refresh_balances():
    user_id = current_user.id
    exchange = request.args.get("exchange")

    if not exchange:
        return jsonify({"success": False, "message": "Exchange name is required."}), 400

    # Fetch the API key for the exchange
    api_key_entry = UserAPIKey.query.filter_by(user_id=user_id, exchange=exchange).first()
    if not api_key_entry:
        return jsonify({"success": False, "message": f"API key for {exchange} not found."}), 404

    # Fetch updated balances for the requested exchange
    api_key, api_secret = api_key_entry.get_api_keys()
    balances, total_balance_usd = get_wallet_balances(api_key, api_secret, exchange)

    # Handle cases where balances are not fetched
    if balances is None or total_balance_usd is None:
        return jsonify({
            "success": True,
            "balances": {},
            "total_balance_usd": 0.0,
            "total_balance_all_exchanges": 0.0
        })

    # Calculate the total balance across all exchanges
    total_balance_all_exchanges = 0
    all_exchanges = UserAPIKey.query.filter_by(user_id=user_id).all()
    for exchange_entry in all_exchanges:
        if exchange_entry.exchange == exchange:
            # Use the updated balance for the current exchange
            total_balance_all_exchanges += total_balance_usd
        else:
            # Fetch the balance for other exchanges from the database or cache
            other_balances, other_total_balance_usd = get_wallet_balances(
                exchange_entry.get_api_keys()[0], exchange_entry.get_api_keys()[1], exchange_entry.exchange
            )
            if other_total_balance_usd is not None:
                total_balance_all_exchanges += other_total_balance_usd

    return jsonify({
        "success": True,
        "balances": balances,
        "total_balance_usd": total_balance_usd,  # Balance for the requested exchange
        "total_balance_all_exchanges": total_balance_all_exchanges  # Total balance across all exchanges
    })




@app.route('/forum')
def forum_home():
    categories = ForumCategory.query.all()
    return render_template('forum/home.html', categories=categories)

@app.route('/forum/category/<int:category_id>')
def forum_category(category_id):
    category = ForumCategory.query.get_or_404(category_id)
    threads = ForumThread.query.filter_by(category_id=category_id).order_by(ForumThread.created_at.desc()).all()
    return render_template('forum/category.html', category=category, threads=threads)

from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime

# ... (keep existing forum_home and forum_category routes) ...

@app.route('/forum/thread/<int:thread_id>', methods=['GET', 'POST'])
def forum_thread(thread_id):
    thread = ForumThread.query.get_or_404(thread_id)
    # Get all top-level posts and their replies
    posts = ForumPost.query.filter_by(thread_id=thread_id, reply_to=None)\
                          .order_by(ForumPost.created_at.asc()).all()
    all_users = User.query.all()  # For mention functionality
    form = PostForm()

    if request.method == 'GET':
        return render_template('forum/thread.html', 
                            thread=thread, 
                            posts=posts,
                            all_users=all_users,
                            form=form)
    
    return redirect(url_for('forum_thread', thread_id=thread_id))


@app.route('/forum/thread/<int:thread_id>/edit', methods=['POST'])
@login_required
def edit_thread(thread_id):
    thread = ForumThread.query.get_or_404(thread_id)

    if thread.user_id != current_user.id:
        abort(403)  # Forbidden

    # Get data from form submission
    title = request.form.get('title')
    content = request.form.get('content')





    if not title or not content:
        flash('Title and content are required', 'error')
        return redirect(url_for('forum_category', category_id=thread.category_id))

    thread.title = title
    thread.content = content
    db.session.commit()

    flash('Thread updated successfully!', 'success')
    return redirect(url_for('forum_thread', thread_id=thread.id))

@app.route('/forum/thread/<int:thread_id>/delete', methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = ForumThread.query.get_or_404(thread_id)

    if thread.user_id != current_user.id:
        abort(403)  # Forbidden

    category_id = thread.category_id
    db.session.delete(thread)
    db.session.commit()
    flash('Thread deleted successfully!', 'success')
    return redirect(url_for('forum_category', category_id=category_id))


@app.route('/forum/thread/<int:thread_id>/post', methods=['POST'])
@login_required
def create_post(thread_id):
    thread = ForumThread.query.get_or_404(thread_id)
    content = request.form.get('content', '').strip()
    reply_to = request.form.get('reply_to')
    image = request.files.get('image')
    
    # Validate input
    if not content and not image:
        return jsonify({'success': False, 'error': 'Message or image is required'}), 400

    if content and len(content) > 2000:
        return jsonify({'success': False, 'error': 'Message too long (max 2000 characters)'}), 400
    
    # Handle image upload
    image_url = None
    if image and allowed_file(image.filename):
        if image.content_length > 5 * 1024 * 1024:  # 5MB limit
            return jsonify({'success': False, 'error': 'Image size should be less than 5MB'}), 400
            
        filename = secure_filename(image.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        image.save(filepath)
        image_url = url_for('static', filename=f'uploads/{unique_filename}')

    # Create the post
    post = ForumPost(
        content=content,
        user_id=current_user.id,
        thread_id=thread_id,
        reply_to=reply_to if reply_to else None,
        image_url=image_url
    )
    db.session.add(post)
    db.session.commit()

    # Handle mentions and notifications
    mentioned_usernames = extract_mentions(content)
    if mentioned_usernames:
        create_mention_notifications(mentioned_usernames, post, current_user, thread)

    # Handle reply notifications
    if reply_to:
        create_reply_notification(reply_to, post, current_user, thread)

   # After creating the post and committing to DB
    socketio.emit('new_post', {
        'post': {
            'id': post.id,
            'content': post.content,
            'created_at': post.created_at.strftime('%H:%M · %b %d, %Y'),
            'username': current_user.username,
            'user_initial': current_user.username[0].upper(),
            'reply_to': post.reply_to,
            'image_url': post.image_url,
            'thread_id': thread_id,
            'user_id': current_user.id,
            'is_op': current_user.id == thread.user_id
        }
    }, room=f'thread_{thread_id}')
    
    return jsonify({
        'success': True,
        'post': {
            'id': post.id,
            'content': post.content,
            'created_at': post.created_at.strftime('%H:%M · %b %d, %Y'),
            'username': current_user.username,
            'user_initial': current_user.username[0].upper(),
            'reply_to': post.reply_to,
            'image_url': post.image_url
        }
    })
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_thread')
def handle_join_thread(data):
    thread_id = data['thread_id']
    join_room(f'thread_{thread_id}')
    print(f'Client joined thread {thread_id}')

@socketio.on('leave_thread')
def handle_leave_thread(data):
    thread_id = data['thread_id']
    leave_room(f'thread_{thread_id}')
    print(f'Client left thread {thread_id}')


def extract_mentions(text):
    import re
    return set(re.findall(r'@(\w+)', text))

def create_mention_notifications(usernames, post, sender, thread):
    for username in usernames:
        user = User.query.filter_by(username=username).first()
        if user and user.id != sender.id:  # Don't notify yourself
            notification = Notification(
                user_id=user.id,
                sender_id=sender.id,
                post_id=post.id,
                thread_id=thread.id,
                content=f"{sender.username} mentioned you in a post",
                notification_type='mention'
            )
            db.session.add(notification)
    db.session.commit()

def create_reply_notification(reply_to_id, post, sender, thread):
    original_post = ForumPost.query.get(reply_to_id)
    if original_post and original_post.user_id != sender.id:  # Don't notify yourself
        notification = Notification(
            user_id=original_post.user_id,
            sender_id=sender.id,
            post_id=post.id,
            thread_id=thread.id,
            content=f"{sender.username} replied to your post",
            notification_type='reply'
        )
        db.session.add(notification)
        db.session.commit()

@app.route('/forum/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = ForumPost.query.get_or_404(post_id)
    
    # Check if user already liked this post
    existing_like = PostLike.query.filter_by(
        user_id=current_user.id,
        post_id=post_id
    ).first()
    
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'success': True, 'action': 'unlike', 'likes_count': len(post.likes)})
    else:
        new_like = PostLike(
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'success': True, 'action': 'like', 'likes_count': len(post.likes)})

@app.route('/forum/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = ForumPost.query.get_or_404(post_id)
    
    if post.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    thread_id = post.thread_id
    db.session.delete(post)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Post deleted successfully',
        'thread_id': thread_id
    })

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.template_filter('time_ago')
def time_ago_filter(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    if diff.days > 0:
        return f"{diff.days} days ago"
    if diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    if diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    return "just now"
@app.route('/forum/create_thread/<int:category_id>', methods=['POST'])
@login_required
def create_thread(category_id):
    # Get data from form submission
    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        flash('Title and content are required', 'error')
        return redirect(url_for('forum_category', category_id=category_id))

    thread = ForumThread(
        title=title,
        content=content,
        user_id=current_user.id,
        category_id=category_id
    )
    db.session.add(thread)
    db.session.commit()

    flash('Thread created successfully!', 'success')
    return redirect(url_for('forum_category', category_id=category_id))

# Add this custom filter to convert @mentions to links
@app.template_filter('replace_mentions')
def replace_mentions_filter(content):
    import re
    return re.sub(r'@(\w+)', r'<a href="#" class="mention">@\1</a>', content)

@app.route('/notifications')
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
                                    .order_by(Notification.created_at.desc())\
                                    .limit(10).all()
    
    # Mark as read when fetched
    for notification in notifications:
        if not notification.is_read:
            notification.is_read = True
    db.session.commit()
    
    return jsonify({
        'notifications': [{
            'id': n.id,
            'content': n.content,
            'created_at': n.created_at.strftime('%H:%M · %b %d, %Y'),
            'is_read': n.is_read,
            'type': n.notification_type,
            'thread_id': n.thread_id,
            'post_id': n.post_id,
            'sender': n.sender.username if n.sender else None
        } for n in notifications]
    })

@app.route('/notifications/count')
@login_required
def get_unread_notification_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})
@app.route('/profile/notifications')
@login_required
def view_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
                                    .order_by(Notification.created_at.desc())\
                                    .paginate(page=1, per_page=20)
    return render_template('profile/notifications.html', notifications=notifications)
@app.route('/help-center')
@login_required
def help_center():
    """Render the Help Center page"""
    return render_template('help_center.html', 
                          current_user=current_user,
                          datetime=datetime)

@app.route('/security')
@login_required
def security():
    """Render the Security page with user-specific security status"""
    # Count active sessions (simplified example - you might need to implement session tracking)
    session_count = 1  # Default to 1 for current session
    
    return render_template('security.html',
                         current_user=current_user,
                         session_count=session_count)

@app.route('/privacy-policy')
def privacy_policy():
    """Render the Privacy Policy page"""
    return render_template('privacy_policy.html',
                         datetime=datetime)

@app.route('/terms')
def terms():
    """Render the Terms of Service page"""
    return render_template('terms.html',
                         datetime=datetime)
from mark.models import BlogCategory, BlogPost
from mark.form import BlogPostForm
from werkzeug.utils import secure_filename
import os
import uuid

@app.route('/blog')
def blog_home():
    """Show all published blog posts"""
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.filter_by(is_published=True)\
                         .order_by(BlogPost.created_at.desc())\
                         .paginate(page=page, per_page=5)
    
    # Get categories and popular posts
    categories = BlogCategory.query.all()
    popular_posts = BlogPost.query.filter_by(is_published=True)\
                                .order_by(BlogPost.views.desc())\
                                .limit(3)\
                                .all()
    
    return render_template('blog/index.html', 
                         posts=posts,
                         categories=categories,
                         popular_posts=popular_posts)

@app.route('/blog/<string:slug>')
def blog_post(slug):
    """Show single blog post"""
    post = BlogPost.query.filter_by(slug=slug, is_published=True).first_or_404()
    
    # Increment view count
    post.views += 1
    db.session.commit()
    
    # Get related posts
    related_posts = BlogPost.query.filter(
        BlogPost.category_id == post.category_id,
        BlogPost.id != post.id,
        BlogPost.is_published == True
    ).order_by(db.func.random()).limit(3).all()
    
    return render_template('blog/post.html',
                         post=post,
                         related_posts=related_posts)

@app.route('/blog/category/<string:slug>')
def blog_category(slug):
    """Show posts in a category"""
    category = BlogCategory.query.filter_by(slug=slug).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.filter_by(category_id=category.id, is_published=True)\
                         .order_by(BlogPost.created_at.desc())\
                         .paginate(page=page, per_page=5)
    return render_template('blog/category.html',
                         category=category,
                         posts=posts)

# Admin routes
@app.route('/blog/create', methods=['GET', 'POST'])
@login_required
def create_blog_post():

    form = BlogPostForm()
    form.category_id.choices = [(c.id, c.name) for c in BlogCategory.query.all()]
    
    if form.validate_on_submit():
        # Handle file upload
        featured_image = None
        if form.featured_image.data:
            filename = secure_filename(form.featured_image.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'blog', unique_filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            form.featured_image.data.save(filepath)
            featured_image = f"blog/{unique_filename}"
        
        post = BlogPost(
            title=form.title.data,
            slug=form.slug.data,
            content=form.content.data,
            excerpt=form.excerpt.data,
            featured_image=featured_image,
            is_published=form.is_published.data,
            author_id=current_user.id,
            category_id=form.category_id.data
        )
        db.session.add(post)
        db.session.commit()
        flash('Blog post created successfully!', 'success')
        return redirect(url_for('blog_post', slug=post.slug))
    
    return render_template('blog/create.html', form=form)

@app.route('/blog/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blog_post(post_id):
    """Edit existing blog post"""
 
    
    post = BlogPost.query.get_or_404(post_id)
    form = BlogPostForm(obj=post)
    form.category_id.choices = [(c.id, c.name) for c in BlogCategory.query.all()]
    
    if form.validate_on_submit():
        # Handle file upload
        if form.featured_image.data:
            # Delete old image if exists
            if post.featured_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], post.featured_image))
                except:
                    pass
            
            filename = secure_filename(form.featured_image.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'blog', unique_filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            form.featured_image.data.save(filepath)
            post.featured_image = f"blog/{unique_filename}"
        
        post.title = form.title.data
        post.slug = form.slug.data
        post.content = form.content.data
        post.excerpt = form.excerpt.data
        post.is_published = form.is_published.data
        post.category_id = form.category_id.data
        db.session.commit()
        flash('Blog post updated successfully!', 'success')
        return redirect(url_for('blog_post', slug=post.slug))
    
    return render_template('blog/edit.html', form=form, post=post)

@app.route('/blog/categories')
@login_required
def manage_blog_categories():
    """Manage blog categories"""
   
    categories = BlogCategory.query.all()
    return render_template('blog/categories.html', categories=categories)

