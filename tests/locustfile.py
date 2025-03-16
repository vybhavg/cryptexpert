from locust import HttpUser, task, between

class CryptexpertUser(HttpUser):
    wait_time = between(1, 5)  # Simulated users will wait between 1 and 5 seconds between tasks

    @task
    def get_binance_prices(self):
        # Simulate a request to fetch Binance prices
        self.client.get("/binance_prices")

    @task
    def get_okx_prices(self):
        # Simulate a request to fetch OKX prices
        self.client.get("/okx_prices")

    @task
    def get_coinbase_prices(self):
        # Simulate a request to fetch Coinbase prices
        self.client.get("/coinbase_prices")
