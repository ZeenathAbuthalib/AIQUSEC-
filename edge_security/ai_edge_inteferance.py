import joblib
import numpy as np
import time

# Load a pre-trained AI model
model = joblib.load('ai_threat_detection_model.joblib')

def perform_inference():
    while True:
        # Random sample input data (you would use real sensor data here)
        sample_input = np.array([[5.5, 2.3, 1.3, 0.2]])
        prediction = model.predict(sample_input)
        print(f"AI Edge Inference Prediction: {prediction}")
        time.sleep(10)  # Perform inference every 10 seconds

if __name__ == "__main__":
    perform_inference()
