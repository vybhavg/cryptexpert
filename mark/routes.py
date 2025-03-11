
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
            return redirect(url_for('otp_form'))
        else:
            flash('Username and password are incorrect',"danger")
    
    if form.errors:
        for err in form.errors.values():
            flash(err,"warning")
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
    try:
        msg = Message('Cryptexpert OTP Verification', recipients=[email])
        msg.body = f'''
        Dear Valued User,
        
        Your One-Time Password (OTP) for Cryptexpert authentication is: **{otp}**  
        This OTP is valid for a limited time. Please do not share it with anyone.
        
        If you did not request this OTP, please ignore this email.  
        
        Best regards,  
        **Cryptexpert Team**  
        Secure Your Crypto Investments with Confidence.
        '''
        mail.send(msg)
        flash("OTP sent successfully","success")
        return redirect(url_for('verify_form'))
    except Exception as e:
        flash(f'Unable to send OTP: {e}',"danger")
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
            flash('Incorrect OTP',"danger")

    if auth_form.validate_on_submit():
        entered_code = auth_form.authotp.data
        totp = pyotp.TOTP(user.authenticator_secret)
        if totp.verify(entered_code):
            login_user(user) 
            flash(f'User logged in successfully: {user.username}',"success") 
            return redirect(url_for('index'))
        else:
            flash("Invalid authenticator code. Please try again.","warning")
            return render_template('verify_otp.html', form=auth_form, username=session['userid'], show_auth_form=True)


    if form.errors:
        for err in form.errors.values():
            flash(err,"warning")
    return render_template('verify_otp.html', form=form, username=session['userid'], show_auth_form=False)

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
            flash('No account found with this email.', 'danger')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token.', 'danger')
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
            flash("Invalid authenticator code. Please try again.","danger")

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
        flash("Invalid access.","danger")
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
    # Pass the current_user object to the template
    return render_template('charts.html', user=current_user)

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

@app.route("/submit_api_key", methods=["GET", "POST"])
@login_required
def submit_api_key():
    if request.method == "POST":
        exchange = request.form.get("exchange")
        api_key = request.form.get("api_key")
        api_secret = request.form.get("api_secret")

        if not exchange or not api_key or not api_secret:
            flash("All fields are required!", "danger")
            return redirect(url_for("submit_api_key"))

        # Check if API key for this exchange already exists
        existing_key = UserAPIKey.query.filter_by(user_id=current_user.id, exchange=exchange).first()
        if existing_key:
            flash(f"API key for {exchange} already exists!", "warning")
            return redirect(url_for("submit_api_key"))

        # Encrypt and store API keys
        new_api_key = UserAPIKey(user_id=current_user.id, exchange=exchange, api_key=api_key, api_secret=api_secret)
        db.session.add(new_api_key)
        db.session.commit()

        flash("API key added successfully!", "success")
        return redirect(url_for("submit_api_key"))

    # Fetch user API keys for display
    user_api_keys = UserAPIKey.query.filter_by(user_id=current_user.id).all()
    user_exchanges = {key.exchange for key in user_api_keys}  # Set of exchanges user has keys for

    return render_template("submit_api_key.html", user_api_keys=user_api_keys, user_exchanges=user_exchanges)


@app.route("/delete_api_key/<int:api_id>", methods=["POST"])
@login_required
def delete_api_key(api_id):
    api_key_entry = UserAPIKey.query.filter_by(id=api_id, user_id=current_user.id).first()

    if not api_key_entry:
        flash("API key not found!", "danger")
        return redirect(url_for("submit_api_key"))

    db.session.delete(api_key_entry)
    db.session.commit()

    flash("API key removed successfully!", "success")
    return redirect(url_for("submit_api_key"))

import asyncio
from binance import AsyncClient  # Use AsyncClient for Binance API


# Function to get wallet balances based on selected exchange
def get_wallet_balances(api_key, api_secret, exchange):
    """Fetches wallet balances from different exchanges."""
    
    if exchange.lower() == "binance":
        return asyncio.run(get_binance_balances_async(api_key, api_secret))  # Use asyncio.run()

    elif exchange.lower() == "coinbase":
        return get_coinbase_balances(api_key, api_secret)

    return None

import asyncio
from binance import AsyncClient

async def get_binance_balances_async(api_key, api_secret):
    """Fetches wallet balances from Binance asynchronously and calculates total balance in USD."""
    try:
        client = await AsyncClient.create(api_key, api_secret)  # Async client
        account_info = await client.get_account()

        # Extract non-zero balances
        balances = {asset["asset"]: float(asset["free"]) for asset in account_info["balances"] if float(asset["free"]) > 0}

        # Fetch USD prices for all assets
        total_balance_usd = 0.0
        for asset, amount in balances.items():
            symbol = f"{asset}USDT"
            try:
                price_info = await client.get_symbol_ticker(symbol=symbol)
                asset_price = float(price_info["price"])
                total_balance_usd += amount * asset_price
            except:
                continue  # Skip if price fetch fails (e.g., some tokens don't have direct USDT pairs)

        # Fix: Properly close the client session
        await client.close_connection()

        return balances, total_balance_usd

    except Exception as e:
        print(f"Binance API Error: {e}")
        return None, 0.0


# Function to get wallet balances from Coinbase
def get_coinbase_balances(api_key, api_secret):
    """Fetches wallet balances from Coinbase."""
    try:
        headers = {
            "Accept": "application/json",
            "CB-ACCESS-KEY": api_key,
            "CB-ACCESS-SIGN": api_secret,
        }
        response = requests.get("https://api.coinbase.com/v2/accounts", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            balances = {account["currency"]: float(account["balance"]["amount"]) for account in data["data"] if float(account["balance"]["amount"]) > 0}
            return balances
        
        else:
            print(f"Coinbase API Error: {response.json()}")
            return None

    except Exception as e:
        print(f"Coinbase API Error: {e}")
        return None

# Route for displaying and processing wallet balances
@app.route("/wallet_balances", methods=["GET", "POST"])
@login_required
def wallet_balances():
    user_id = current_user.id
    exchanges = Exchange.query.all()  # Get available exchanges

    if request.method == "POST":
        exchange_name = request.form.get("exchange")
        api_key_entry = UserAPIKey.query.filter_by(user_id=user_id, exchange=exchange_name).first()

        if not api_key_entry:
            flash(f"API key for {exchange_name} is missing. Please submit your API key.")
            return redirect(url_for("submit_api_key"))

        # Decrypt API keys using the `decrypt_data` function
        api_key, api_secret = api_key_entry.get_api_keys()
        if(api_key):
            print(api_key, api_secret)

        # Fetch wallet balances based on the selected exchange
        balances,total_balance_usd = get_wallet_balances(api_key, api_secret, exchange_name)

        # Render the template with the fetched balances
        return render_template("wallet_balances.html", exchanges=exchanges, exchange=exchange_name, balances=balances, total_balance_usd=total_balance_usd)

    return render_template("wallet_balances.html", exchanges=exchanges, exchange=None, balances=None)   



