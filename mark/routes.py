from mark import app, db, mail
from mark.form import RegisterForm, LoginForm, otpform, verifyform,Authenticationform
from mark.models import User, Item, CryptoAsset, Exchange, UserAPIKey
from flask import render_template,request, redirect, url_for, flash, session
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
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import matplotlib
import matplotlib.pyplot as plt
import io
import base64
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
        'DOTUSDT', 'OMUSDT', 'BCHUSDT', 'HYPEUSDT', 'USDeUSDT', 'DAIUSDT', 'BGBUSDT', 'UNIUSDT', 'XMRUSDT', 'NEARUSDT',
        'APTUSDT', 'ONDOUSDT', 'PEPEUSDT', 'ICPUSDT', 'ETCUSDT', 'AAVEUSDT', 'TRUMPUSDT', 'OKBUSDT', 'TAOUSDT',
        'MNTUSDT', 'VETUSDT', 'POLUSDT', 'ALGOUSDT', 'KASUSDT', 'CROUSDT', 'RENDERUSDT', 'FILUSDT', 'FDUSDUSDT',
        'TIAUSDT', 'JUPUSDT', 'GTUSDT', 'SUSDT', 'ARBUSDT', 'KNCUSDT', 'BALUSDT', 'YFIUSDT', 'MKUSDT', 'SUSHIUSDT',
        'ZRXUSDT', 'UMAUSDT', 'RARIUSDT', 'CVCUSDT', 'MITHUSDT', 'LOOMUSDT', 'GNOUSDT', 'GRTUSDT', '1INCHUSDT',
        'DIAUSDT', 'LRCUSDT', 'STMXUSDT', 'PERLUSDT', 'RENUSDT', 'FETUSDT', 'DODOUSDT', 'MTAUSDT', 'HNTUSDT', 'FILUSDT',
        'RUNEUSDT', 'SANDUSDT', 'CELOUSDT', 'DASHUSDT'
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
    'DOT-USDT', 'OM-USDT', 'BCH-USDT', 'HYPE-USDT', 'USDe-USDT', 'DAI-USDT', 'BGB-USDT', 'UNI-USDT', 'XMR-USDT', 'NEAR-USDT',
    'APT-USDT', 'ONDO-USDT', 'PEPE-USDT', 'ICP-USDT', 'ETC-USDT', 'AAVE-USDT', 'TRUMP-USDT', 'OKB-USDT', 'TAO-USDT',
    'MNT-USDT', 'VET-USDT', 'POL-USDT', 'ALGO-USDT', 'KAS-USDT', 'CRO-USDT', 'RENDER-USDT', 'FIL-USDT', 'FDUSD-USDT',
    'TIA-USDT', 'JUP-USDT', 'GT-USDT', 'SU-USDT', 'ARB-USDT', 'KNC-USDT', 'BAL-USDT', 'YFI-USDT', 'MK-USDT', 'SUSHI-USDT',
    'ZRX-USDT', 'UMA-USDT', 'RARI-USDT', 'CVC-USDT', 'MITH-USDT', 'LOOM-USDT', 'GNO-USDT', 'GRT-USDT', '1INCH-USDT',
    'DIA-USDT', 'LRC-USDT', 'STMX-USDT', 'PERL-USDT', 'REN-USDT', 'FET-USDT', 'DODO-USDT', 'MTA-USDT', 'HNT-USDT', 'FIL-USDT',
    'RUNE-USDT', 'SAND-USDT', 'CELO-USDT', 'DASH-USDT'
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
    binance_prices = get_specific_prices_from_binance()
    okx_prices = get_specific_prices_from_okx()
    coinbase_prices = get_specific_prices_from_coinbase()

    for ticker in binance_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in okx_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in coinbase_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    return render_template('index.html', binance_prices=binance_prices, okx_prices=okx_prices, coinbase_prices=coinbase_prices,crypto_logos=crypto_logos)


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
    user = User.query.filter_by(username=current_user.username).first()
    name = user.username
    email = user.email
    binance_prices = get_specific_prices_from_binance()
    okx_prices = get_specific_prices_from_okx()
    coinbase_prices = get_specific_prices_from_coinbase()

    for ticker in binance_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in okx_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    for ticker in coinbase_prices:
        ticker['priceChangePercent'] = float(ticker['priceChangePercent'])

    return render_template('index.html', binance_prices=binance_prices, okx_prices=okx_prices, coinbase_prices=coinbase_prices,crypto_logos=crypto_logos)

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
        user = User(username=form.username.data, email=form.email.data, password=form.password1.data)
        db.session.add(user)
        db.session.commit()
        session['userid'] = user.username
        return redirect(url_for('otp_form'))
    if form.errors:
        for err in form.errors.values():
            flash(err,"warning")
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

    # Search for partial matches first
    results = CryptoAsset.query.filter(
        (CryptoAsset.name.ilike(f"%{query}%")) | (CryptoAsset.symbol.ilike(f"%{query}%"))
    ).limit(10).all()

    # Format the results
    response = [
        {"name": f"{asset.symbol} - {asset.name}", "link": f"/charts?symbol={asset.symbol}USDT"}
        for asset in results
    ]

    return jsonify(response)






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
