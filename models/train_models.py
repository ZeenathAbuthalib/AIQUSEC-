import pandas as pd
from sklearn.linear_model import LinearRegression
from pyod.models.iforest import IForest
import joblib

# Load data
data = pd.read_csv('data/dataset1 (1).csv')

# Train predictive model
def train_predictive_model():
    X = data[['timestamp']].values
    y = data['data'].values
    model = LinearRegression()
    model.fit(X, y)
    joblib.dump(model, 'models/predictive_model.pkl')

# Train anomaly detection model
def train_anomaly_model():
    model = IForest()
    model.fit(data[['data']])
    joblib.dump(model, 'models/anomaly_model.pkl')

train_predictive_model()
train_anomaly_model()

