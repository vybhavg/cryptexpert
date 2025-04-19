from mark import app,socketio
import os
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs
if(__name__=="__main__"):
    socketio.run(app, host="0.0.0.0", port=8080, debug=True)
