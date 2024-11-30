# simulate_multiple_edges.py

from multiprocessing import Process
import os
import numpy as np
import time
import joblib

# Load the pre-trained AI model
model = joblib.load('./models/ai_threat_detection_model.joblib')

def perform_inference():
    while True:
        # Random sample input data (replace with real sensor data here)
        sample_input = np.array([[5.5, 2.3, 1.3, 0.2]])
        prediction = model.predict(sample_input)
        print(f"AI Edge Inference Prediction from process {os.getpid()}: {prediction}")
        time.sleep(10)  # Perform inference every 10 seconds

if __name__ == "__main__":
    num_processes = 3  # For example, simulate 3 edge devices
    processes = [Process(target=perform_inference) for _ in range(num_processes)]
    for p in processes:
        p.start()
    for p in processes:
        p.join()
