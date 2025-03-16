import time
import requests

# Benchmark function
def benchmark_function(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)  # Call the function
    end_time = time.time()
    print(f"{func.__name__} executed in {end_time - start_time:.4f} seconds")
    print("Test passed")
    return result

# API calls
def get_specific_prices_from_binance():
    url = "https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT"
    response = requests.get(url)
    return response.json()  # Returns the price data

def get_specific_prices_from_okx():
    url = "https://www.okx.com/api/v5/market/ticker?instId=BTC-USDT"
    response = requests.get(url)
    return response.json()

def get_specific_prices_from_coinbase():
    url = "https://api.coinbase.com/v2/prices/BTC-USD/spot"
    response = requests.get(url)
    return response.json()

# Run benchmark tests
benchmark_function(get_specific_prices_from_binance)
benchmark_function(get_specific_prices_from_okx)
benchmark_function(get_specific_prices_from_coinbase)
