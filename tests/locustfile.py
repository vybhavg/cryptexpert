from locust import HttpUser, task, between

class CryptoPriceUser(HttpUser):
    wait_time = between(1, 3)  # Simulate users waiting before making another request

    @task
    def get_binance_prices(self):
        self.client.get("/binance_prices")

    @task
    def get_okx_prices(self):
        self.client.get("/okx_prices")

    @task
    def get_coinbase_prices(self):
        self.client.get("/coinbase_prices")
