import pandas as pd
from joblib import load

def edge_security_inference(data_path):
    model = load("../models/ai_threat_detection_model.joblib")
    data = pd.read_csv(data_path)
    predictions = model.predict(data)
    return predictions

# Example usage
print(edge_security_inference("../data/cyber-threat-intelligence-splited_validate.csv"))
