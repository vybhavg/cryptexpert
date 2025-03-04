
from mark import app, db, mail
from mark.form import RegisterForm, LoginForm, otpform, verifyform,Authenticationform
from mark.models import User, Item
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
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import pandas as pd
import numpy as np

def get_specific_prices_from_binance():
    response = requests.get("https://api.binance.com/api/v3/ticker/24hr")
    
    if response.status_code != 200:
        print("Error fetching data:", response.status_code)
        return []
    
    data = response.json()

    # List of specific cryptocurrencies to display
    specific_coins = [
  "BTCUSDT", "ETHUSDT", "XRPUSDT", "USDTUSDT", "BNBUSDT", "SOLUSDT", 
  "USDCUSDT", "ADAUSDT", "DOGEUSDT", "TRXUSDT", "LINKUSDT", "HBARUSDT", 
  "XLMUSDT", "AVAXUSDT", "LEOUSDT", "SUIUSDT", "LTCUSDT", "TONUSDT", 
  "SHIBUSDT", "DOTUSDT", "OMUSDT", "BCHUSDT", "HYPEUSDT", "USDeUSDT", 
  "DAIUSDT", "BGBUSDT", "UNIUSDT", "XMRUSDT", "NEARUSDT", "APTUSDT", 
  "ONDOUSDT", "PEPEUSDT", "ICPUSDT", "ETCUSDT", "AAVEUSDT", "TRUMPUSDT", 
  "OKBUSDT", "TAOUSDT", "MNTUSDT", "VETUSDT", "POLUSDT", "ALGOUSDT", 
  "KASUSDT", "CROUSDT", "RENDERUSDT", "FILUSDT", "FDUSDUSDT", "TIAUSDT", 
  "JUPUSDT", "GTUSDT", "SUSDT", "ARBUSDT", "KNCUSDT", "BALUSDT", "YFIUSDT", 
  "MKUSDT", "SUSHIUSDT", "ZRXUSDT", "UMAUSDT", "RARIUSDT", "CVCUSDT", 
  "MITHUSDT", "LOOMUSDT", "GNOUSDT", "GRTUSDT", "1INCHUSDT", "DIAUSDT", 
  "LRCUSDT", "STMXUSDT", "PERLUSDT", "RENUSDT", "FETUSDT", "DODOUSDT", 
  "MTAUSDT", "HNTUSDT", "FILUSDT", "RUNEUSDT", "SANDUSDT", "CELOUSDT", 
  "DASHUSDT", "MITHUSDT", "SKLUSDT", "MBOXUSDT", "TWTUSDT", "MTLUSDT", 
  "EGLDUSDT", "KSMUSDT", "ICXUSDT", "OXTUSDT", "STPTUSDT", "BNTUSDT", 
  "LOKAUSDT", "DOGEUSDT", "CKBUSDT", "STRAXUSDT", "BLZUSDT", "CTSIUSDT", 
  "LENDUSDT", "LENDUSDT", "MITHUSDT", "FARMUSDT", "KP3RUSDT", "COINUSDT", 
  "RICKUSDT", "TKNUSDT", "OKUSDT", "MOBILEUSDT", "CRVUSDT", "CNSUSDT", 
  "PAXGUSDT"
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
    specific_coins = ['BTC', 'ETH', 'XRP', '', 'BNB', 'SOL', 'USDC', 'ADA', 'DOGE', 'TRX', 'LINK', 'HBAR', 
 'XLM', 'AVAX', 'LEO', 'SUI', 'LTC', 'TON', 'SHIB', 'DOT', 'OM', 'BCH', 'HYPE', 'USDe', 
 'DAI', 'BGB', 'UNI', 'XMR', 'NEAR', 'APT', 'ONDO', 'PEPE', 'ICP', 'ETC', 'AAVE', 'TRUMP', 
 'OKB', 'TAO', 'MNT', 'VET', 'POL', 'ALGO', 'KAS', 'CRO', 'RENDER', 'FIL', 'FDUSD', 'TIA', 
 'JUP', 'GT', 'S', 'ARB', 'KNC', 'BAL', 'YFI', 'MK', 'SUSHI', 'ZRX', 'UMA', 'RARI', 'CVC', 
 'MITH', 'LOOM', 'GNO', 'GRT', '1INCH', 'DIA', 'LRC', 'STMX', 'PERL', 'REN', 'FET', 'DODO', 
 'MTA', 'HNT', 'FIL', 'RUNE', 'SAND', 'CELO', 'DASH']

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
                    price = crypto['quote']['USD']['price']
                    
                    # Check if price is None
                    if price is not None:
                        price = f"{float(price):,.2f}"
                    else:
                        price = "N/A"  # Set to "N/A" if price is None

                    price_change_percent = f"{float(crypto['quote']['USD']['percent_change_24h']):.2f}" if 'percent_change_24h' in crypto['quote']['USD'] else "N/A"

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

model = load_model("/home/vybhavguttula/cryptexpert/mark/model.keras")

# Initialize Binance Client (No API Key Required for Public Data)
client = Client()
def plot_to_html(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    buf.seek(0)
    data = base64.b64encode(buf.getbuffer()).decode("ascii")
    buf.close()
    return f"data:image/png;base64,{data}"


@app.route("/data_fetching", methods=["GET", "POST"])
def data_fetching():
    if request.method == "POST":
        stock = request.form.get("stock")
        no_of_days = int(request.form.get("no_of_days"))
        return redirect(url_for("predict", stock=stock, no_of_days=no_of_days))
    return render_template("todo-lists.html")

def get_historical_klines(symbol, interval, start_str, end_str=None):
    all_data = []
    start_ts = int(pd.to_datetime(start_str).timestamp() * 1000)
    end_ts = int(pd.to_datetime(end_str).timestamp() * 1000) if end_str else None
    
    while True:
        # Fetch 1000 candles per request
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
        
        # Update start timestamp for the next batch
        start_ts = new_klines[-1][0] + 1  # Move to the next timestamp
        
        # Prevent exceeding Binance rate limits
        time.sleep(0.5)  # Wait to avoid API bans
    
    return all_data
@app.route("/predict", methods=["GET", "POST"])
def predict():
    stock = request.args.get("stock", "BTCUSDT")  # Binance uses BTCUSDT instead of BTC-USD
    no_of_days = int(request.args.get("no_of_days", 10))

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
        return render_template("result.html", error="Invalid crypto pair or no data available.")
    candlestick_data = stock_data[['Close Time', 'Open', 'High', 'Low', 'Close', 'Volume']].tail(200)
    candlestick_json = candlestick_data.to_json(orient="records")

    # Data Preparation
    splitting_len = int(len(stock_data) * 0.9)
    x_test = stock_data[['Close']][splitting_len:]
    scaler = MinMaxScaler(feature_range=(0, 1))
    scaled_data = scaler.fit_transform(x_test)

    x_data = []
    y_data = []
    for i in range(100, len(scaled_data)):
        x_data.append(scaled_data[i - 100:i])
        y_data.append(scaled_data[i])

    x_data = np.array(x_data)
    y_data = np.array(y_data)

    # Predictions
    predictions = model.predict(x_data)
    inv_predictions = scaler.inverse_transform(predictions)
    inv_y_test = scaler.inverse_transform(y_data)

    # Prepare Data for Plotting
    plotting_data = pd.DataFrame({
        'Original Test Data': inv_y_test.flatten(),
        'Predicted Test Data': inv_predictions.flatten()
    }, index=x_test.index[100:])

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
        "todos.html",
        stock=stock,
        candlestick_json=candlestick_json,
        predicted_plot=predicted_plot,
        future_plot=future_plot,
        enumerate=enumerate,
        future_predictions=future_predictions
    )
