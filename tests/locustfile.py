from locust import HttpUser, task, between

class CryptexpertUser(HttpUser):
    wait_time = between(1, 5)  # Simulated users will wait between 1 and 5 seconds between tasks

    @task
    def home_page(self):
        # Simulate a request to the home page
        self.client.get("/")

    @task
    def live_prices(self):
        # Simulate a request to the live prices page
        self.client.get("/live_prices")


    @task
    def wallet_management(self):
        # Simulate a request to the wallet management page
        self.client.get("/wallet_management")

    @task
    def ai_predictor(self):
        # Simulate a request to the AI predictor page
        self.client.get("/ai_predictor")

    @task
    def charts_page(self):
        # Simulate a request to the charts page
        self.client.get("/charts")

    @task
    def profile_page(self):
        # Simulate a request to the profile page
        self.client.get("/profile")

    @task
    def search(self):
        # Simulate a search request
        self.client.get("/search?q=btc")
