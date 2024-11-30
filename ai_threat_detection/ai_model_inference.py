import pandas as pd
from joblib import load

# Load the model
model = load("../models/ai_threat_detection_model.joblib")

# Load test data
test_data = pd.read_csv("../data/cyber-threat-intelligence-splited_test.csv")
X_test = test_data.drop(columns=["label"])

# Inference
predictions = model.predict(X_test)
print(predictions)
