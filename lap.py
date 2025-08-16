import os
from mark import app, socketio

# Disable GPU and suppress TensorFlow logs (as in your original code)
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

if __name__ == "__main__":
    # Get the port from the environment variable, default to 5000 if not set (for local testing)
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
