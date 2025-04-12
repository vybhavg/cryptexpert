# Use a slim Python image to reduce size
FROM python:3.9-slim

# Set working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies, make sure to include pip version pinning if necessary
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your app is running on
EXPOSE 5000

# Set environment variable for Flask app
ENV FLASK_APP=lap.py

# Run Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
