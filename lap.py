from mark import app
import os
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs
if(__name__=="__main__"):
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT env variable
    
    app.run(host='0.0.0.0', port=port)
