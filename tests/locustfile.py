from locust import HttpUser, task, between

class CryptexpertUser(HttpUser):
    wait_time = between(1, 5)  # Simulated users will wait between 1 and 5 seconds between tasks

   
    @task
    def live_prices(self):
        # Simulate a request to the live prices page
        self.client.get("/live_prices")




    @task
    def ai_predictor(self):
        # Simulate a request to the AI predictor page
        self.client.get("/ai_predictor")

  
