import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

def train_model():
    # Load dataset
    data = pd.read_csv('data/cyber-threat-intelligence-splited_train.csv')
    X = data.drop(columns=['label'])  # Assuming 'label' is the target column
    y = data['label']

    # Split data
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Save model
    joblib.dump(model, 'models/ai_threat_detection_model.joblib')

    # Return training accuracy
    return model.score(X_val, y_val)  # Returns validation accuracy
