from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_restful import Api, Resource
import pandas as pd
import plotly.express as px
import plotly.io as pio
import re
from plotly import graph_objs as go 
import plotly.graph_objects as go
import networkx as nx
import plotly.graph_objects as go
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import MinMaxScaler
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.cluster import KMeans
from sklearn.cluster import DBSCAN
from sklearn.ensemble import RandomForestClassifier
import random
from pennylane import numpy as np
import pennylane as qml
from sklearn.preprocessing import StandardScaler
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from statsmodels.tsa.arima.model import ARIMA
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import pennylane as qml
from pennylane import numpy as qnp
from datetime import datetime, timedelta
from multiprocessing import Process
from quantum_safe.pqc_keygen import generate_keys
from quantum_safe.pqc_encryption import encrypt_message, decrypt_message
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from werkzeug.utils import secure_filename
import os
from flask import session
from werkzeug.security import check_password_hash, generate_password_hash




# External Threat Feed Example (Simulated)
threat_feed = [
    "192.168.1.10", "malicious-domain.com", "8.8.8.8", "10.0.0.5", "phishing-domain.com"
]

# MITRE ATT&CK Example Mapping
mitre_attack_mapping = {
    "192.168.1.10": "Initial Access - Phishing",
    "malicious-domain.com": "Command and Control - Domain Generation",
    "8.8.8.8": "Exfiltration - Data Transfer",
    "10.0.0.5": "Credential Access - Brute Force",
    "phishing-domain.com": "Initial Access - Spearphishing"
}

# Reputation Scores (Simulated)
reputation_scores = {
    "192.168.1.10": 85,
    "malicious-domain.com": 90,
    "8.8.8.8": 10,  # Low score for a known trusted IP
    "10.0.0.5": 75,
    "phishing-domain.com": 95
}

# Sample Network Traffic Data
network_traffic = pd.DataFrame({
    'IP Address': [f"192.168.1.{i}" for i in range(1, 101)],
    'Packets Sent': np.random.poisson(50, 100)
})

# Adding a few external IPs from the threat feed
network_traffic.loc[random.sample(range(100), 5), 'IP Address'] = [random.choice(threat_feed) for _ in range(5)]



 # Correctly import graph objects for Plotly


# Flask App Initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize libraries
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
api = Api(app)

DATA_PATH = 'data/dataset1 (1).csv' 

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # e.g., 'admin', 'viewer'

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)

# Initialize database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-based access control decorator
def role_required(role):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# User Management Routes
@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username, role=current_user.role)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Set a secure password for the admin dashboard (hashed)
ADMIN_DASHBOARD_PASSWORD = generate_password_hash("admin@231")

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_dashboard():
    # Check if the admin session is already validated
    if 'admin_validated' in session and session['admin_validated']:
        # Fetch all users and render the admin dashboard
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)

    if request.method == 'POST':
        # Get the password entered by the admin
        entered_password = request.form.get('password')

        # Validate the password
        if check_password_hash(ADMIN_DASHBOARD_PASSWORD, entered_password):
            # Set session flag to allow access
            session['admin_validated'] = True
            # Redirect to the admin dashboard after successful validation
            return redirect(url_for('admin_dashboard'))
        else:
            # Flash an error message for incorrect password
            flash('Incorrect password. Please try again.', 'danger')

    # Render the password prompt form if not already validated
    return render_template('admin_password_prompt.html')

@app.route('/viewer')
@login_required
@role_required('viewer')
def viewer_dashboard():
    return render_template('viewer_dashboard.html')


    
@app.route('/ai_insights')
@login_required
def ai_insights():
    try:
        # Synthetic data generation (as a replacement for actual data)
        temperature_data = np.random.normal(25, 5, 100).reshape(-1, 1)  # Average temperature of 25°C with variance
        power_data = np.random.normal(50, 10, 100)  # Power level data with some variance
        radiation_data = np.random.normal(0.3, 0.05, 100)  # Radiation level data

        # Synthetic data for cybersecurity metrics (Network Traffic)
        ip_addresses = [f'192.168.0.{i}' for i in range(1, 101)]
        packets_per_second = np.random.poisson(100, len(ip_addresses)) + np.random.choice([0, 500], size=len(ip_addresses), p=[0.9, 0.1])

        # Synthetic Threat Data for Behavior Analysis
        threat_data = pd.DataFrame({
            'IP Address': [f'192.168.1.{i}' for i in range(1, 101)],
            'Packets Sent': np.random.randint(50, 1000, 100),
            'Failed Logins': np.random.randint(0, 20, 100),
            'Data Exfiltration Attempts': np.random.randint(0, 5, 100)
        })


        # Anomaly Detection using Isolation Forest (Temperature Data)
        model_if = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        anomalies = model_if.fit_predict(temperature_data)

        # Prepare data for temperature anomaly scatter plot
        temperature_df = pd.DataFrame({
            'Index': np.arange(len(temperature_data)),
            'Temperature': temperature_data.flatten(),
            'Anomaly': ['Anomaly' if val == -1 else 'Normal' for val in anomalies]
        })

        # Anomaly Detection Scatter Plot for Temperature
        fig_anomaly_scatter = px.scatter(
            temperature_df,
            x='Index',
            y='Temperature',
            color='Anomaly',
            title='Temperature Anomaly Detection',
            labels={'Index': 'Time Step', 'Temperature': 'Temperature (°C)'},
            color_discrete_map={'Normal': 'blue', 'Anomaly': 'red'}
        )
        anomaly_scatter_html = pio.to_html(fig_anomaly_scatter, full_html=False)

        # Predictive Maintenance using Linear Regression (Power Data)
        time_series = np.arange(0, len(power_data)).reshape(-1, 1)  # Representing time steps
        model_lr = LinearRegression()
        model_lr.fit(time_series, power_data)
        future_time = np.array([[len(power_data) + 10]])  # Predicting power consumption 10 steps into the future
        future_power = model_lr.predict(future_time)


        

        # Power Consumption Trend Line Chart
        power_df = pd.DataFrame({
            'Time Step': np.arange(len(power_data)),
            'Power Consumption': power_data
        })
        fig_power_trend = go.Figure()
        fig_power_trend.add_trace(go.Scatter(
            x=power_df['Time Step'],
            y=power_df['Power Consumption'],
            mode='lines',
            name='Power Consumption'
        ))
        fig_power_trend.add_trace(go.Scatter(
            x=[len(power_data) + 10],
            y=[future_power[0]],
            mode='markers',
            name='Future Power Prediction',
            marker=dict(color='red', size=10)
        ))
        fig_power_trend.update_layout(
            title='Power Consumption Trend with Future Prediction',
            xaxis_title='Time Step',
            yaxis_title='Power Consumption (W)',
            template='plotly_white'
        )
        power_trend_html = pio.to_html(fig_power_trend, full_html=False)

        # Enhanced Radiation Levels Over Time (With Mean & Std Dev)
        radiation_df = pd.DataFrame({
            'Time Step': np.arange(len(radiation_data)),
            'Radiation Level': radiation_data
        })
        mean_radiation = radiation_df['Radiation Level'].mean()
        std_radiation = radiation_df['Radiation Level'].std()

        fig_radiation_line = go.Figure()
        fig_radiation_line.add_trace(go.Scatter(
            x=radiation_df['Time Step'],
            y=radiation_df['Radiation Level'],
            mode='lines',
            name='Radiation Level'
        ))
        fig_radiation_line.add_trace(go.Scatter(
            x=radiation_df['Time Step'],
            y=[mean_radiation] * len(radiation_df),
            mode='lines',
            name='Mean Radiation Level',
            line=dict(color='green', dash='dash')
        ))
        fig_radiation_line.add_trace(go.Scatter(
            x=radiation_df['Time Step'],
            y=[mean_radiation + std_radiation] * len(radiation_df),
            mode='lines',
            name='Mean + Std Dev',
            line=dict(color='orange', dash='dot')
        ))
        fig_radiation_line.update_layout(
            title='Radiation Levels Over Time (With Mean & Std Dev)',
            xaxis_title='Time Step',
            yaxis_title='Radiation Level (μSv/h)',
            template='plotly_white'
        )
        radiation_line_chart_html = pio.to_html(fig_radiation_line, full_html=False)

        # Anomaly Detection for Network Traffic using Isolation Forest
        scaler = MinMaxScaler()
        packets_scaled = scaler.fit_transform(packets_per_second.reshape(-1, 1))
        model_traffic_if = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        traffic_anomalies = model_traffic_if.fit_predict(packets_scaled)

        # Prepare Data for Network Traffic Anomaly Plot
        network_traffic_df = pd.DataFrame({
            'IP Address': ip_addresses,
            'Packets per Second': packets_per_second,
            'Anomaly': ['Anomaly' if x == -1 else 'Normal' for x in traffic_anomalies]
        })

        # Network Traffic Anomaly Detection Scatter Plot
        fig_network_traffic_anomaly = px.scatter(
            network_traffic_df,
            x='IP Address',
            y='Packets per Second',
            color='Anomaly',
            title='Network Traffic Anomaly Detection',
            labels={'Packets per Second': 'Packets per Second'},
            color_discrete_map={'Normal': 'blue', 'Anomaly': 'red'}
        )
        network_traffic_anomaly_html = pio.to_html(fig_network_traffic_anomaly, full_html=False)

        # Malware Behavior Analysis using KMeans Clustering
        processes = np.random.randint(10, 100, 100)
        file_modifications = np.random.randint(0, 50, 100)
        malware_data = np.column_stack((processes, file_modifications))
        model_kmeans = KMeans(n_clusters=2, random_state=42)
        labels = model_kmeans.fit_predict(malware_data)

        # Prepare Data for Malware Heatmap
        malware_df = pd.DataFrame(malware_data, columns=['Processes', 'File Modifications'])
        malware_df['Cluster'] = ['Malicious' if label == 1 else 'Benign' for label in labels]

        # Heatmap for Malware Behavior Analysis
        fig_malware_heatmap = go.Figure(data=go.Heatmap(
            z=malware_df['File Modifications'],
            x=malware_df.index,
            y=malware_df['Processes'],
            colorscale='Viridis'
        ))
        fig_malware_heatmap.update_layout(
            title='Malware Behavior Analysis',
            xaxis_title='Sample Index',
            yaxis_title='Number of Processes',
            template='plotly_white'
        )
        malware_heatmap_html = pio.to_html(fig_malware_heatmap, full_html=False)

        # Real-time Threat Level Monitoring (Random Data)
        threat_levels = np.random.choice(['Low', 'Medium', 'High'], size=10, p=[0.7, 0.2, 0.1])
        threat_df = pd.DataFrame({
            'Time Step': np.arange(len(threat_levels)),
            'Threat Level': threat_levels
        })

         # ----- Advanced Cyber Attack Analysis -----

        # 1. DDoS Attack Analysis using Machine Learning
        traffic_df = pd.DataFrame({
            'IP Address': ip_addresses,
            'Packets per Second': packets_per_second
        })

        # Label IP addresses with unusually high packets per second as potential DDoS
        traffic_df['DDoS Label'] = ['DDoS' if packets > 400 else 'Normal' for packets in packets_per_second]

        # Visualize DDoS Analysis
        fig_ddos_scatter = px.scatter(
            traffic_df,
            x='IP Address',
            y='Packets per Second',
            color='DDoS Label',
            title='DDoS Attack Analysis',
            labels={'Packets per Second': 'Packets per Second'},
            color_discrete_map={'Normal': 'blue', 'DDoS': 'red'}
        )
        ddos_scatter_html = pio.to_html(fig_ddos_scatter, full_html=False)

        # 2. Intrusion Detection System (IDS) using Random Forest Classifier
        # Synthetic features: number of connections, packet size, flags
        num_connections = np.random.randint(50, 300, 100)
        packet_size = np.random.normal(500, 100, 100)
        flags = np.random.choice([0, 1], size=100, p=[0.8, 0.2])  # Binary flags (0 or 1)

        ids_data = pd.DataFrame({
            'Num Connections': num_connections,
            'Packet Size': packet_size,
            'Flags': flags,
            'Anomaly': np.random.choice([0, 1], size=100, p=[0.9, 0.1])  # 1 = Intrusion, 0 = Normal
        })

        # Train IDS model
        X = ids_data[['Num Connections', 'Packet Size', 'Flags']]
        y = ids_data['Anomaly']
        model_rf = RandomForestClassifier(n_estimators=100, random_state=42)
        model_rf.fit(X, y)

        # Make predictions and evaluate
        predictions = model_rf.predict(X)
        ids_data['Predicted Anomaly'] = predictions

        # IDS Result Visualization
        fig_ids_heatmap = px.imshow(ids_data.corr(), title="IDS Feature Correlation Heatmap", labels={"color": "Correlation"})
        ids_heatmap_html = pio.to_html(fig_ids_heatmap, full_html=False)

         # Threat Clustering using DBSCAN
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        threat_features = threat_data[['Packets Sent', 'Failed Logins', 'Data Exfiltration Attempts']]
        scaler = MinMaxScaler()
        threat_features_scaled = scaler.fit_transform(threat_features)
        threat_data['Cluster'] = dbscan.fit_predict(threat_features_scaled)

        # Threat Clustering Scatter Plot
        fig_threat_behavior = px.scatter_3d(
            threat_data,
            x='Packets Sent',
            y='Failed Logins',
            z='Data Exfiltration Attempts',
            color='Cluster',
            title='Threat Behavior Clustering Analysis',
            labels={'Packets Sent': 'Packets Sent', 'Failed Logins': 'Failed Logins', 'Data Exfiltration Attempts': 'Data Exfiltration Attempts'}
        )
        threat_behavior_html = pio.to_html(fig_threat_behavior, full_html=False)

         # Step 1: Threat Intelligence Feed Analysis
        # Cross-reference the threat feed with internal network traffic
        network_traffic['Threat'] = network_traffic['IP Address'].apply(
            lambda x: 'Threat Detected' if x in threat_feed else 'Normal'
        )
        
        # Step 2: Add Reputation Score to IPs in Network Traffic
        network_traffic['Reputation Score'] = network_traffic['IP Address'].apply(
            lambda x: reputation_scores.get(x, random.randint(20, 60))  # Default score for IPs not in threat feed
        )
        
        # Step 3: MITRE ATT&CK Mapping
        network_traffic['MITRE ATT&CK TTP'] = network_traffic['IP Address'].apply(
            lambda x: mitre_attack_mapping.get(x, 'N/A')
        )
        
        # Visualization: Threat Intelligence Feed Analysis
        fig_threat_analysis = px.scatter(
            network_traffic,
            x='IP Address',
            y='Packets Sent',
            color='Threat',
            hover_data=['Reputation Score', 'MITRE ATT&CK TTP'],
            title='Threat Intelligence Feed Analysis',
            color_discrete_map={'Threat Detected': 'red', 'Normal': 'blue'}
        )
        threat_analysis_html = pio.to_html(fig_threat_analysis, full_html=False)

        # Visualization: Reputation Score of IP Addresses
        fig_reputation_scores = px.bar(
            network_traffic,
            x='IP Address',
            y='Reputation Score',
            color='Threat',
            title='Reputation Score Analysis of External IPs',
            color_discrete_map={'Threat Detected': 'red', 'Normal': 'blue'}
        )
        reputation_scores_html = pio.to_html(fig_reputation_scores, full_html=False)


        # Visualization: MITRE ATT&CK Techniques
        mitre_techniques_df = network_traffic[network_traffic['MITRE ATT&CK TTP'] != 'N/A']
        fig_mitre_attack = px.histogram(
            mitre_techniques_df,
            x='MITRE ATT&CK TTP',
            color='Threat',
            title='Detected Activities Mapped to MITRE ATT&CK TTPs',
            color_discrete_map={'Threat Detected': 'red', 'Normal': 'blue'}
        )
        mitre_attack_html = pio.to_html(fig_mitre_attack, full_html=False)

        # Firewall Log Analysis - Blocked IP Analysis
        blocked_ips = [f'192.168.1.{i}' for i in range(1, 101)]
        block_counts = np.random.poisson(5, len(blocked_ips))
        firewall_df = pd.DataFrame({
            'IP Address': blocked_ips,
            'Block Count': block_counts
        })

        # Detect IPs with high blocking frequency
        high_block_ips = firewall_df[firewall_df['Block Count'] > firewall_df['Block Count'].mean() + 2 * firewall_df['Block Count'].std()]
        
        # Visualize the blocked IP trends
        fig_firewall = px.bar(
            firewall_df,
            x='IP Address',
            y='Block Count',
            title='Blocked IP Address Analysis',
            labels={'Block Count': 'Number of Blocks'}
        )
        firewall_html = fig_firewall.to_html(full_html=False)

        # DNS Query Monitoring - Track suspicious domains
        domains = [f"example{i}.com" for i in range(1, 101)]
        dns_queries = np.random.poisson(10, len(domains))
        dns_df = pd.DataFrame({
            'Domain': domains,
            'Query Count': dns_queries,
            'Suspicious': np.random.choice(['Yes', 'No'], len(domains), p=[0.1, 0.9])
        })

        # Filter suspicious domains
        suspicious_domains = dns_df[dns_df['Suspicious'] == 'Yes']

        # Visualize DNS Query Monitoring
        fig_dns_queries = px.scatter(
            dns_df,
            x='Domain',
            y='Query Count',
            color='Suspicious',
            title='DNS Query Monitoring',
            labels={'Query Count': 'Number of Queries'}
        )
        dns_html = fig_dns_queries.to_html(full_html=False)

        # SIEM Integration - Correlating Alerts
        siem_alerts = ['Malware Detected', 'Unauthorized Access', 'DDoS Attack', 'Suspicious Login', 'Data Exfiltration']
        siem_data = np.random.choice(siem_alerts, size=100, p=[0.3, 0.2, 0.2, 0.2, 0.1])
        alert_counts = dict(Counter(siem_data))

        # Correlate SIEM Alerts
        fig_siem_alerts = go.Figure(data=[go.Pie(labels=list(alert_counts.keys()), values=list(alert_counts.values()))])
        fig_siem_alerts.update_layout(
            title='SIEM Alert Correlation Analysis',
            template='plotly_white'
        )
        siem_html = fig_siem_alerts.to_html(full_html=False)
        


        # Mock dataset for simplicity (replace with your actual dataset)
        data = pd.DataFrame({
            'velocity': np.random.rand(100),
            'latency': np.random.rand(100),
            'power_consumption': np.random.rand(100),
            'altitude': np.random.rand(100),
            'data': np.random.rand(100)
        })

        # Classical AI Model: Random Forest Regressor
        features = data[['velocity', 'latency', 'power_consumption', 'altitude']]
        labels = data['data']
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
        rf_model = RandomForestRegressor(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        feature_importances = rf_model.feature_importances_

        # Quantum Feature Mapping with PennyLane
        n_qubits = 2
        dev = qml.device("default.qubit", wires=n_qubits)

        @qml.qnode(dev)
        def quantum_feature_map(x):
            qml.Hadamard(wires=0)
            qml.RY(x[0], wires=0)
            qml.RY(x[1], wires=1)
            return qml.probs(wires=[0, 1])

        # Apply quantum feature mapping to the dataset
        quantum_features = [quantum_feature_map([row['velocity'], row['latency']]) for _, row in data.iterrows()]
        quantum_features = qnp.array(quantum_features)

        # Train a Support Vector Classifier (SVC) with Quantum Features
        scaler = StandardScaler()
        scaled_quantum_features = scaler.fit_transform(quantum_features)
        svm_model = SVC(kernel='linear')
        y_classification_labels = (data['power_consumption'] > 0.5).astype(int)  # Label: Power Consumption above median
        svm_model.fit(scaled_quantum_features, y_classification_labels)

        # Create Feature Importance Chart
        fig_rf = go.Figure(data=[
            go.Bar(
                x=['Velocity', 'Latency', 'Power Consumption', 'Altitude'],
                y=feature_importances,
                marker=dict(color='white')
            )
        ])
        fig_rf.update_layout(
            title='Feature Importance from Random Forest Regressor',
            xaxis_title='Features',
            yaxis_title='Importance',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        feature_importance_chart_html = pio.to_html(fig_rf, full_html=False)

        # Create Quantum Feature Mapping Visualization
        fig_qm = go.Figure(data=[
            go.Scatter3d(
                x=quantum_features[:, 0],
                y=quantum_features[:, 1],
                z=quantum_features[:, 2],
                mode='markers',
                marker=dict(size=5, color='red', opacity=0.8)
            )
        ])
        fig_qm.update_layout(
            title='Quantum Feature Mapping Visualization',
            scene=dict(
                xaxis_title='Qubit 0',
                yaxis_title='Qubit 1',
                zaxis_title='Probability',
                xaxis=dict(backgroundcolor="black", gridcolor="white"),
                yaxis=dict(backgroundcolor="black", gridcolor="white"),
                zaxis=dict(backgroundcolor="black", gridcolor="white"),
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        quantum_feature_chart_html = pio.to_html(fig_qm, full_html=False)

        # Load Dataset (Threat Intelligence)
        data = pd.DataFrame({
            'timestamp': [datetime.now() - timedelta(hours=i) for i in range(100)],
            'latency': np.random.rand(100) * 100,
            'velocity': np.random.rand(100) * 10,
            'power_consumption': np.random.rand(100) * 50,
            'altitude': np.random.rand(100) * 500,
            'threat_score': np.random.randint(1, 100, 100)
        })

        # Classical ML - Random Forest Classifier for Threat Detection
        features = data[['velocity', 'latency', 'power_consumption', 'altitude']]
        labels = data['threat_score'] > 50  # Binary classification - Threat or not
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        feature_importances = rf_model.feature_importances_

        # Quantum Feature Mapping with PennyLane for Threat Intelligence
        n_qubits = 2
        dev = qml.device("default.qubit", wires=n_qubits)

        @qml.qnode(dev)
        def quantum_feature_map(x):
            qml.Hadamard(wires=0)
            qml.RY(x[0], wires=0)
            qml.RY(x[1], wires=1)
            return qml.probs(wires=[0, 1])

        quantum_features = [quantum_feature_map([row['velocity'], row['latency']]) for _, row in data.iterrows()]
        quantum_features = qnp.array(quantum_features)

        # Train an SVM using Quantum Features
        scaler = StandardScaler()
        scaled_quantum_features = scaler.fit_transform(quantum_features)
        svm_model = SVC(kernel='linear')
        svm_model.fit(scaled_quantum_features, labels)

        # Quantum Feature Importance Visualization
        quantum_importances = [np.mean(qf) for qf in quantum_features]

        # Create Feature Importance Chart
        fig_rf = go.Figure(data=[
            go.Bar(
                x=['Velocity', 'Latency', 'Power Consumption', 'Altitude'],
                y=feature_importances,
                marker=dict(color='blue')
            )
        ])
        fig_rf.update_layout(
            title='Feature Importance from Random Forest Classifier',
            xaxis_title='Features',
            yaxis_title='Importance',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        feature_importance_chart_html = pio.to_html(fig_rf, full_html=False)

        # Create Quantum Feature Importance Chart
        fig_qf = go.Figure(data=[
            go.Bar(
                x=data.index,
                y=quantum_importances,
                marker=dict(color='purple')
            )
        ])
        fig_qf.update_layout(
            title='Quantum Feature Importance Analysis',
            xaxis_title='Data Index',
            yaxis_title='Importance (Quantum)',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        quantum_feature_importance_html = pio.to_html(fig_qf, full_html=False)

        # Time-Series Analysis for Threat Score
        fig_ts = go.Figure(data=[
            go.Scatter(
                x=data['timestamp'],
                y=data['threat_score'],
                mode='lines+markers',
                line=dict(color='red')
            )
        ])
        fig_ts.update_layout(
            title='Time-Series Analysis of Threat Score',
            xaxis_title='Timestamp',
            yaxis_title='Threat Score',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        threat_time_series_html = pio.to_html(fig_ts, full_html=False)


        # Train an SVM using Quantum Features
        scaler = StandardScaler()
        scaled_quantum_features = scaler.fit_transform(quantum_features)
        svm_model = SVC(kernel='linear', probability=True)
        svm_model.fit(scaled_quantum_features, labels)

        # Quantum-Based Anomaly Detection Chart
        anomaly_labels = labels != svm_model.predict(scaled_quantum_features)
        fig_anomaly = go.Figure(data=[
            go.Scatter(
                x=data.index,
                y=quantum_features[:, 0],
                mode='markers',
                marker=dict(
                    color=np.where(anomaly_labels, 'red', 'blue'),
                    size=8,
                    opacity=0.6
                ),
                name='Quantum Features Anomaly Detection'
            )
        ])
        fig_anomaly.update_layout(
            title='Quantum-Based Anomaly Detection',
            xaxis_title='Data Index',
            yaxis_title='Quantum Feature (Mapped)',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        anomaly_detection_chart_html = pio.to_html(fig_anomaly, full_html=False)

        # Quantum Correlation Heatmap
        correlation_matrix = pd.DataFrame(quantum_features).corr()
        fig_corr = go.Figure(data=go.Heatmap(
            z=correlation_matrix.values,
            x=['Quantum Feature 0', 'Quantum Feature 1'],
            y=['Quantum Feature 0', 'Quantum Feature 1'],
            colorscale='Viridis'
        ))
        fig_corr.update_layout(
            title='Quantum Correlation Heatmap',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='black')
        )
        quantum_correlation_chart_html = pio.to_html(fig_corr, full_html=False)

        

        # Render the AI insights template
        return render_template(
            'ai_insights.html',
            anomaly_scatter_html=anomaly_scatter_html,
            power_trend_html=power_trend_html,
            radiation_line_chart_html=radiation_line_chart_html,
            network_traffic_anomaly_html=network_traffic_anomaly_html,
            malware_heatmap_html=malware_heatmap_html,
            future_power_prediction=future_power[0],
            ddos_scatter_html=ddos_scatter_html,
            ids_heatmap_html=ids_heatmap_html, threat_behavior_html=threat_behavior_html,  threat_analysis_html=threat_analysis_html,
            reputation_scores_html=reputation_scores_html,
            mitre_attack_html=mitre_attack_html, firewall_html=firewall_html,
            dns_html=dns_html,
            siem_html=siem_html, feature_importance_chart=feature_importance_chart_html,
            quantum_feature_chart=quantum_feature_chart_html, quantum_feature_importance_chart=quantum_feature_importance_html,
            threat_time_series_chart=threat_time_series_html,
            anomaly_detection_chart=anomaly_detection_chart_html,
            quantum_correlation_chart=quantum_correlation_chart_html,
            
        )
    except Exception as e:
        return jsonify({"error": str(e)})




@app.route('/visualization')
@login_required
def visualization():
    return render_template('3d_visualization.html')

@app.route('/api/satellite_positions')
def satellite_positions():
    try:
        # Load the dataset
        data = pd.read_csv(DATA_PATH)

        # Ensure required columns exist
        required_columns = ['Location (Latitude)', 'Location (Longitude))', 'Satellite ID']
        missing_columns = [col for col in required_columns if col not in data.columns]
        if missing_columns:
            return jsonify({"error": f"Missing columns: {missing_columns}"})

        # Extract relevant data for visualization
        satellite_data = data[['Satellite ID', 'Location (Latitude)', 'Location (Longitude))']]

        # Handle potential missing data or formatting issues
        satellite_data = satellite_data.dropna(subset=['Location (Latitude)', 'Location (Longitude))'])

        # Convert the data to a list of dictionaries
        satellites = satellite_data.to_dict(orient='records')

        # Return the data as a JSON response
        return jsonify(satellites)

    except Exception as e:
        return jsonify({"error": str(e)})


# Satellite Dashboard
@app.route('/satellite_dashboard', methods=['GET'])
@login_required
def satellite_dashboard():
    try:
        # Load the dataset
        data = pd.read_csv(DATA_PATH)

        # Clean column names
        data.columns = [re.sub(r'[^\w\s]', '', col).strip().lower().replace(" ", "_") for col in data.columns]

        

        # Check for required columns
        required_columns = ['location_latitude', 'location_longitude', 'satellite_id', 
                            'satellite_type', 'orbit_type', 'date_time', 'data']
        missing_columns = [col for col in required_columns if col not in data.columns]
        if missing_columns:
            return jsonify({"error": f"Missing columns: {missing_columns}"})
        # Add a default altitude column, assuming an arbitrary fixed value
        data['altitude'] = 500000  # Altitude in meters (500 km)
        
        # Add synthetic data for missing columns
        if 'velocity' not in data.columns or data['velocity'].nunique() == 1:
            data['velocity'] = np.random.uniform(3.0, 8.0, size=len(data))  # Random velocity between 3 km/s to 8 km/s

        if 'latency' not in data.columns:
            data['latency'] = np.random.randint(20, 100, size=len(data))  # Random latency in milliseconds

        if 'latency' not in data.columns:
            data['latency'] = np.random.normal(50, 10, size=len(data)).clip(20, 100)  # Mean 50ms, std dev 10ms, clipped between 20 and 100
    

        if 'uptime' not in data.columns:
            data['uptime'] = np.random.randint(85, 100, size=len(data))  # Random uptime percentage between 85 and 100

        if 'downtime' not in data.columns:
            data['downtime'] = 100 - data['uptime']  # Downtime as complement of uptime

        # Add synthetic date_time column if it doesn't exist or has issues
        if 'date_time' not in data.columns or data['date_time'].nunique() == 1:
            start_date = pd.to_datetime('2022-09-01')
            data['date_time'] = pd.date_range(start=start_date, periods=len(data), freq='H')

         # Add synthetic power consumption column if it doesn't exist
        if 'power_consumption' not in data.columns:
            data['power_consumption'] = np.random.uniform(10, 100, size=len(data))  # Random power consumption between 10W and 100W
        
        # Add synthetic qubit column if it doesn't exist
        if 'qubit' not in data.columns:
            data['qubit'] = np.random.randint(1, 100, size=len(data))  # Random number of qubits transmitted

        
        
        # Generate charts
         # Add additional details
        launch_vehicle_info = {
            "name": "Falcon Heavy | Mission: ArabSat 6A",
            "date": "April 7, 2019 | 22:36 UTC"
        }

        trajectory_info = {
            "latitude": 49.3932119,
            "longitude": 15.8838159,
            "altitude": 256000,  # in meters
            "velocity": 25555    # in km/h
        }

        mission_info = {
            "countdown": "05:55:25",
            "distance": 245,     # in km
            "current_speed": 25555,  # in km/h
            "next_transmission": "1 Hour"
        }

        sensor_data = {
            "temperature": -20,  # in degrees Celsius
            "power": 74,         # in percentage
            "radiation _level": "0.25 μSv/h",
            "solar_intensity": "1361 W/m²"
        }

        ground_station_info = {
            "name": "Station 55 Roseworth",
            "lat_long": "54.341579 / -1.435360",
            "last_seen": "25th November 2019"
        }

        # Create the charts
        def update_fig_style(fig):
            fig.update_layout(
                paper_bgcolor='black',
                plot_bgcolor='black',
                font=dict(color='white'),
                title_font=dict(color='white')
            )
            return fig

        # 3D Scatter Plot
        fig_scatter_3d = go.Figure(data=[
            go.Scatter3d(
                x=data['location_longitude'],
                y=data['location_latitude'],
                z=data['altitude'],
                mode='markers',
                marker=dict(
                    size=5,
                    color=data['altitude'],
                    colorscale='Viridis',
                    opacity=0.8
                ),
                text=data['satellite_id']
            )
        ])
        fig_scatter_3d = update_fig_style(fig_scatter_3d)
        scatter_3d = pio.to_html(fig_scatter_3d, full_html=False)

        # Create the 3D Scatter Plot as shown above
        fig_3d_map = go.Figure(data=[
            go.Scatter3d(
                x=data['location_longitude'],
                y=data['location_latitude'],
                z=data['altitude'],
                mode='markers',
                marker=dict(
                    size=5,
                    color=data['altitude'],
                    colorscale='Viridis',
                    opacity=0.8
                ),
                text=data['satellite_id'],
                hoverinfo='text'
            )
        ])
        
        fig_3d_map.update_layout(
            title="3D Map of Satellite Trajectory/Location",
            scene=dict(
                xaxis_title='Longitude',
                yaxis_title='Latitude',
                zaxis_title='Altitude (m)',
                xaxis=dict(backgroundcolor="black", gridcolor="white"),
                yaxis=dict(backgroundcolor="black", gridcolor="white"),
                zaxis=dict(backgroundcolor="black", gridcolor="white"),
            ),
           paper_bgcolor="black",  # Set entire figure background to black
           plot_bgcolor="black",   # Set the plotting area background to black
           font=dict(color="white")  # Set text color to white for better visibility
) 
        
        # Convert the figure to HTML
        map_chart_3d = pio.to_html(fig_3d_map, full_html=False)

     
        # Pie Chart for Satellite Types
        satellite_type_counts = data['satellite_type'].value_counts()
        fig_pie = px.pie(names=satellite_type_counts.index, values=satellite_type_counts.values, title="Satellite Types")
        pie_chart = pio.to_html(fig_pie, full_html=False)

        
        # Bar Chart for Orbit Types
        orbit_type_counts = data['orbit_type'].value_counts()
        fig_bar = px.bar(x=orbit_type_counts.index, y=orbit_type_counts.values, title="Orbit Types")
        bar_chart = pio.to_html(fig_bar, full_html=False)

        # Line Graph for Data Transmission Over Time
        fig_line = px.line(data, x='date_time', y='data', title="Data Transmission Over Time")
        line_chart = pio.to_html(fig_line, full_html=False)

        # Map for Satellite Positions
        fig_map = px.scatter_geo(data, lat='location_latitude', lon='location_longitude',
                                 hover_name='satellite_id', title="Satellite Positions")
        map_chart = pio.to_html(fig_map, full_html=False)

        # Generate Heatmap for Satellite Data Transmission
        fig_heatmap = px.density_heatmap(
            data_frame=data,
            x='date_time',
            y='satellite_id',
            z='data',
            title="Heatmap of Satellite Data Transmission Over Time",
            labels={'date_time': 'Date', 'satellite_id': 'Satellite ID', 'data': 'Data Transmission Rate'},
            color_continuous_scale='Viridis'
        )
        heatmap = pio.to_html(fig_heatmap, full_html=False)
 

          

    # Bubble Chart for Time-Series Analysis of Data Transmission
        fig_bubble = px.scatter(
            data, 
            x='date_time', 
            y='satellite_id', 
            size='data', 
            color='satellite_type', 
            title='Time-Series Analysis of Data Transmission (Bubble Chart)',
            labels={'date_time': 'Date', 'satellite_id': 'Satellite ID', 'data': 'Data Transmission'},
            hover_data=['orbit_type']
        )
        bubble_chart = pio.to_html(fig_bubble, full_html=False)
    
       # Further filtering dataset (e.g., limit to first 30 satellite-ground station pairs for readability)
        data = data.head(30)

        # Create Network Graph
        G = nx.Graph()

        # Adding nodes (satellites and ground stations)
        for _, row in data.iterrows():
            satellite_id = row['satellite_id']
            ground_station_id = row['ground_station_id']
            G.add_node(satellite_id, type='satellite')
            G.add_node(ground_station_id, type='ground_station')
            G.add_edge(satellite_id, ground_station_id)

        # Extracting the nodes and edges
        node_positions = nx.circular_layout(G)  # Use circular layout for better readability
        node_x = []
        node_y = []
        node_labels = []
        node_colors = []
        node_sizes = []

        for node, (x, y) in node_positions.items():
            node_x.append(x)
            node_y.append(y)
            node_labels.append(node)
            if G.nodes[node]['type'] == 'satellite':
                node_colors.append('red')
                node_sizes.append(10)  # Smaller size for satellites
            else:
                node_colors.append('blue')
                node_sizes.append(20)  # Larger size for ground stations

        edge_x = []
        edge_y = []

        for edge in G.edges():
            x0, y0 = node_positions[edge[0]]
            x1, y1 = node_positions[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        # Create the network graph figure
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_labels,
            hoverinfo='text',
            marker=dict(
                color=node_colors,
                size=node_sizes,
                line_width=2
            )
        )

        fig_network = go.Figure(data=[edge_trace, node_trace],
                                layout=go.Layout(
                                    title="Network Graph of Ground Stations and Satellites",
                                    titlefont_size=16,
                                    showlegend=False,
                                    hovermode='closest',
                                    margin=dict(b=0, l=0, r=0, t=40),
                                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                                )

        network_graph = pio.to_html(fig_network, full_html=False)

         # Generate Uptime vs. Downtime Bar Chart
        fig_uptime_downtime = go.Figure()
        fig_uptime_downtime.add_trace(go.Bar(
            x=data['satellite_id'],
            y=data['uptime'],
            name='Uptime (%)',
            marker_color='green'
        ))
        fig_uptime_downtime.add_trace(go.Bar(
            x=data['satellite_id'],
            y=data['downtime'],
            name='Downtime (%)',
            marker_color='red'
        ))
        fig_uptime_downtime.update_layout(
            barmode='group',
            title='Satellite Uptime vs. Downtime',
            xaxis_title='Satellite ID',
            yaxis_title='Percentage (%)',
            legend_title='Status',
            template='plotly_white'
        )
        uptime_downtime_chart = pio.to_html(fig_uptime_downtime, full_html=False)

        # Select a satellite for real-time data transmission speed visualization
        selected_satellite = data.iloc[0]  # Selecting the first satellite as an example
        transmission_speed = selected_satellite['data']  # Assuming 'data' column holds transmission speed

        # Create gauge chart for real-time data transmission speed
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=transmission_speed,
            title={'text': f"Data Transmission Speed - {selected_satellite['satellite_id']}"},
            gauge={'axis': {'range': [None, 1000]},  # Adjust range according to your data
                   'bar': {'color': 'blue'}}
        ))
        gauge_chart = pio.to_html(fig_gauge, full_html=False)

        # Create a scatter_geo chart for satellite coverage areas
        fig_coverage = px.scatter_geo(
            data,
            lat='location_latitude',
            lon='location_longitude',
            hover_name='satellite_id',
            title="Satellite Coverage Area",
            size_max=50,
        )

        # Adding circles to represent coverage areas (assuming coverage radius of 500 km for demonstration)
        for i, row in data.iterrows():
            fig_coverage.add_trace(
                go.Scattergeo(
                    lon=[row['location_longitude']],
                    lat=[row['location_latitude']],
                    mode='markers+text',
                    marker=dict(
                        size=10,
                        opacity=0.5,
                        color='blue'
                    ),
                    name=f"Coverage - {row['satellite_id']}",
                    text=row['satellite_id'],
                    showlegend=False
                )
            )

        coverage_chart = pio.to_html(fig_coverage, full_html=False)

        # Latency Analysis Histogram
        fig_latency_hist = px.histogram(
            data, 
            x='latency',
            nbins=30,
            title="Latency Analysis Histogram",
            labels={'latency': 'Latency (ms)'},
            color_discrete_sequence=['#636EFA']
        )
        latency_histogram = pio.to_html(fig_latency_hist, full_html=False)

        # Satellite Velocity Over Time Line Chart
        fig_velocity_line = px.line(
            data, 
            x='date_time', 
            y='velocity',
            color='satellite_id',
            title="Satellite Velocity Over Time",
            labels={'date_time': 'Time', 'velocity': 'Velocity (km/s)', 'satellite_id': 'Satellite ID'}
        )
        velocity_chart = pio.to_html(fig_velocity_line, full_html=False)

         # Power Consumption Analysis (Stacked Area Chart)
        fig_power_consumption = go.Figure()
        for satellite_id in data['satellite_id'].unique():
            satellite_data = data[data['satellite_id'] == satellite_id]
            fig_power_consumption.add_trace(go.Scatter(
                x=satellite_data['date_time'],
                y=satellite_data['power_consumption'],
                mode='lines',
                name=f'Satellite {satellite_id}',
                fill='tonexty'
            ))

        fig_power_consumption.update_layout(
            title='Power Consumption Analysis for Satellites',
            xaxis_title='Time',
            yaxis_title='Power Consumption (W)',
            template='plotly_white'
        )
        power_consumption_chart = pio.to_html(fig_power_consumption, full_html=False)

# Qubit Transmission Over Time (Scatter Plot)
        fig_qubit_transmission = px.scatter(
            data,
            x='date_time',
            y='qubit',
            color='satellite_id',
            title='Qubit Transmission Over Time',
            labels={'date_time': 'Time', 'qubit': 'Number of Qubits'}
        )
        qubit_transmission_chart = pio.to_html(fig_qubit_transmission, full_html=False)

        # Qubit Transmission vs Error Rate
        if 'error_rate' in data.columns:
            fig_qubit_vs_error = px.scatter(
                data,
                x='error_rate',
                y='qubit',
                color='satellite_id',
                title='Qubit Transmission vs. Error Rate',
                labels={'error_rate': 'Error Rate', 'qubit': 'Number of Qubits'}
            )
            qubit_vs_error_chart = pio.to_html(fig_qubit_vs_error, full_html=False)
        else:
            qubit_vs_error_chart = None

        # Column Chart of Qubits
        fig_qubit_column = px.bar(
            data,
            x='satellite_id',
            y='qubit',
            title='Number of Qubits Transmitted by Satellite',
            labels={'satellite_id': 'Satellite ID', 'qubit': 'Number of Qubits'},
            color_discrete_sequence=['#00ccff']
        )
        qubit_histogram_chart = pio.to_html(fig_qubit_column, full_html=False)
        

        return render_template('satellite_dashboard.html', launch_vehicle_info=launch_vehicle_info,
                                trajectory_info=trajectory_info,
                                mission_info=mission_info,
                                sensor_data=sensor_data,
                                ground_station_info=ground_station_info,
                                map_chart_3d=map_chart_3d,
                                pie_chart=pie_chart, bar_chart=bar_chart,
                                line_chart=line_chart, map_chart=map_chart, heatmap=heatmap, scatter_3d=scatter_3d,  
                                bubble_chart=bubble_chart,  network_graph=network_graph, 
                                uptime_downtime_chart=uptime_downtime_chart,gauge_chart=gauge_chart, coverage_chart=coverage_chart,
                                latency_histogram=latency_histogram,
                                velocity_chart=velocity_chart, power_consumption_chart=power_consumption_chart,
                                qubit_transmission_chart=qubit_transmission_chart,
                                qubit_vs_error_chart=qubit_vs_error_chart,
                                qubit_histogram_chart=qubit_histogram_chart)

    except Exception as e:
        return jsonify({"error": str(e)})

# Generate keys on app startup
public_key, private_key = generate_keys()

@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    command = data.get("command")
    
    if command:
        # Encrypt the command before sending
        ciphertext = encrypt_message(public_key, command)
        # Simulate sending the command (encrypted)
        print(f"Encrypted command to send: {ciphertext}")
        
        return jsonify({"status": "Command sent", "ciphertext": ciphertext.decode('utf-8')})
    return jsonify({"error": "No command provided"}), 400

@app.route('/receive_command', methods=['POST'])
def receive_command():
    data = request.get_json()
    ciphertext = data.get("ciphertext")
    
    if ciphertext:
        # Decrypt the command
        decrypted_command = decrypt_message(private_key, ciphertext.encode('utf-8'))
        print(f"Received command: {decrypted_command}")
        
        return jsonify({"status": "Command received", "decrypted_command": decrypted_command})
    return jsonify({"error": "No ciphertext provided"}), 400


@app.route('/quantum_visualization')
def quantum_visualization():

    # Quantum AI Cluster Formation
    n_clusters = 3
    n_points = 300
    points = []
    labels = []
    for i in range(n_clusters):
        cluster_points = np.random.randn(n_points // n_clusters, 3) + np.random.rand(3) * 5
        points.append(cluster_points)
        labels.extend([i] * (n_points // n_clusters))
    points = np.vstack(points)
    labels = np.array(labels)

    fig_clusters = go.Figure()
    fig_clusters.add_trace(go.Scatter3d(
        x=points[:, 0],
        y=points[:, 1],
        z=points[:, 2],
        mode='markers',
        marker=dict(
            size=5,
            color=labels,
            colorscale='Rainbow',
            showscale=True,
            colorbar=dict(title="Cluster"),
        )
    ))
    fig_clusters.update_layout(
        title="Quantum AI Cluster Formation",
        scene=dict(
            xaxis_title="Feature 1",
            yaxis_title="Feature 2",
            zaxis_title="Feature 3"
        )
    )
    clusters_html = pio.to_html(fig_clusters, full_html=False)

    # Quantum Neural Network Weights Visualization
    layers = 5
    nodes_per_layer = 10
    x = np.random.rand(layers * nodes_per_layer)
    y = np.random.rand(layers * nodes_per_layer)
    z = np.repeat(np.arange(layers), nodes_per_layer)
    weights = np.random.rand(layers * nodes_per_layer)

    fig_weights = go.Figure(data=[go.Volume(
        x=x,
        y=y,
        z=z,
        value=weights,
        opacity=0.2,
        surface_count=20,
        colorscale='Viridis',
        colorbar=dict(title="Weight Magnitude")
    )])
    fig_weights.update_layout(
        title="Quantum Neural Network Weights Visualization",
        scene=dict(
            xaxis_title="Nodes in Layer",
            yaxis_title="Activation",
            zaxis_title="Layer"
        )
    )
    weights_html = pio.to_html(fig_weights, full_html=False)

     # 1. Quantum Energy 3D Surface Plot
    x = np.linspace(-2, 2, 100)
    y = np.linspace(-2, 2, 100)
    x, y = np.meshgrid(x, y)
    z = np.exp(-x**2 - y**2) * np.sin(2 * np.pi * x) * np.sin(2 * np.pi * y)

    fig_energy_surface = go.Figure(data=[go.Surface(
        z=z,
        x=x,
        y=y,
        colorscale='Viridis',
        showscale=True,
        colorbar=dict(title="Energy")
    )])
    fig_energy_surface.update_layout(
        title="Quantum Energy 3D Surface",
        scene=dict(
            xaxis_title="X Axis",
            yaxis_title="Y Axis",
            zaxis_title="Energy"
        )
    )
    energy_1surface_html = pio.to_html(fig_energy_surface, full_html=False)

    # 2. Quantum State Evolution 3D Trajectory
    time = np.linspace(0, 10, 500)
    compute = np.sin(time)
    latency = np.cos(time)
    data_flow = time

    fig_workflow = go.Figure()
    fig_workflow.add_trace(go.Scatter3d(
        x=compute,
        y=latency,
        z=data_flow,
        mode='lines',
        line=dict(color='blue', width=3),
        name='Optimized Workflow'
    ))
    fig_workflow.update_layout(
        title="Quantum State Evolution 3D Trajectory",
        scene=dict(
            xaxis_title="Compute Efficiency",
            yaxis_title="Latency Reduction",
            zaxis_title="Data Flow"
        )
    )
    workflow_html = pio.to_html(fig_workflow, full_html=False)

    # 3. Quantum AI Decision Boundary
    x = np.linspace(-1, 1, 100)
    y = np.linspace(-1, 1, 100)
    x, y = np.meshgrid(x, y)
    z = np.sin(np.pi * x) * np.cos(np.pi * y)

    fig_decision_boundary = go.Figure(data=[go.Surface(
        z=z,
        x=x,
        y=y,
        colorscale='Plasma',
        showscale=True,
        colorbar=dict(title="Decision Score")
    )])
    fig_decision_boundary.update_layout(
        title="Quantum AI Decision Boundary",
        scene=dict(
            xaxis_title="Feature 1",
            yaxis_title="Feature 2",
            zaxis_title="Boundary Score"
        )
    )
    decision_1boundary_html = pio.to_html(fig_decision_boundary, full_html=False)

    # 4. Quantum Edge Intelligence Latency Map
    x = np.linspace(0, 10, 100)
    y = np.linspace(0, 10, 100)
    x, y = np.meshgrid(x, y)
    z = np.sin(x / 2) + np.cos(y / 3) + np.random.rand(*x.shape) * 0.1

    fig_latency_map = go.Figure(data=[go.Surface(
        z=z,
        x=x,
        y=y,
        colorscale='Viridis',
        showscale=True,
        colorbar=dict(title="Latency (ms)")
    )])
    fig_latency_map.update_layout(
        title="Quantum Edge Intelligence Latency Map",
        scene=dict(
            xaxis_title="Edge Devices",
            yaxis_title="Task Complexity",
            zaxis_title="Latency (ms)"
        )
    )
    latency_map_html = pio.to_html(fig_latency_map, full_html=False)

    # 5. CTI-Driven Quantum Topology
    G = nx.erdos_renyi_graph(15, 0.2)
    pos = nx.spring_layout(G, dim=3)
    x_nodes = [pos[k][0] for k in G.nodes()]
    y_nodes = [pos[k][1] for k in G.nodes()]
    z_nodes = [pos[k][2] for k in G.nodes()]
    x_edges = []
    y_edges = []
    z_edges = []
    for edge in G.edges():
        x_edges += [pos[edge[0]][0], pos[edge[1]][0], None]
        y_edges += [pos[edge[0]][1], pos[edge[1]][1], None]
        z_edges += [pos[edge[0]][2], pos[edge[1]][2], None]

    edge_trace = go.Scatter3d(
        x=x_edges,
        y=y_edges,
        z=z_edges,
        mode='lines',
        line=dict(width=2, color='#888')
    )

    node_trace = go.Scatter3d(
        x=x_nodes,
        y=y_nodes,
        z=z_nodes,
        mode='markers+text',
        marker=dict(size=8, color='blue'),
        text=list(G.nodes())
    )

    fig_topology = go.Figure(data=[edge_trace, node_trace])
    fig_topology.update_layout(
        title="CTI-Driven Quantum Topology",
        scene=dict(
            xaxis_title="X",
            yaxis_title="Y",
            zaxis_title="Z"
        )
    )
    topology_html = pio.to_html(fig_topology, full_html=False)


    # 1. Scatter Plot for Anomaly Detection
    network_traffic = pd.DataFrame({
        'Time Step': np.arange(100),
        'Packets Sent': np.random.poisson(50, 100),
        'Anomaly': ['Normal'] * 90 + ['Anomaly'] * 10
    })
    fig_scatter = px.scatter(
        network_traffic,
        x='Time Step',
        y='Packets Sent',
        color='Anomaly',
        title='Network Traffic Anomaly Detection',
        color_discrete_map={'Normal': 'blue', 'Anomaly': 'red'}
    )
    scatter_html = pio.to_html(fig_scatter, full_html=False)

    # 2. Heatmap for Key Vulnerabilities
    keys = ['Key 1', 'Key 2', 'Key 3', 'Key 4']
    vulnerabilities = [0.3, 0.2, 0.8, 0.5]
    fig_heatmap = go.Figure(data=go.Heatmap(
        z=[vulnerabilities],
        x=keys,
        y=['Vulnerability Score'],
        colorscale='Viridis'
    ))
    fig_heatmap.update_layout(title='Key Vulnerability Heatmap')
    heatmap_html = pio.to_html(fig_heatmap, full_html=False)

    # 3. Network Graph Visualization
    G = nx.Graph()
    G.add_edges_from([('Satellite 1', 'Ground Station A'), ('Satellite 2', 'Ground Station B')])
    pos = nx.spring_layout(G)

    node_x = [pos[node][0] for node in G.nodes()]
    node_y = [pos[node][1] for node in G.nodes()]
    node_text = list(G.nodes())

    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), mode='lines')
    node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text', text=node_text, marker=dict(size=10))

    fig_network = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(title='Network Graph Visualization'))
    network_html = pio.to_html(fig_network, full_html=False)

    # 4. Gauge Chart for Encryption Speed
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=75,
        title={'text': "Encryption Speed"},
        gauge={'axis': {'range': [None, 100]}}
    ))
    gauge_html = pio.to_html(fig_gauge, full_html=False)

    # 3D Graphs
    # 5. 3D Scatter Plot
    fig_3d_scatter = px.scatter_3d(
        x=np.random.randn(100),
        y=np.random.randn(100),
        z=np.random.randn(100),
        color=np.random.choice(['Group 1', 'Group 2'], 100),
        title="3D Scatter Plot"
    )
    scatter_3d_html = pio.to_html(fig_3d_scatter, full_html=False)

    # 6. 3D Surface Plot
    x = np.linspace(-2, 2, 100)
    y = np.linspace(-2, 2, 100)
    x, y = np.meshgrid(x, y)
    z = np.sin(np.sqrt(x**2 + y**2))

    fig_3d_surface = go.Figure(data=[go.Surface(z=z, x=x, y=y)])
    fig_3d_surface.update_layout(
        title='3D Surface Plot',
        scene=dict(
            xaxis_title='X Axis',
            yaxis_title='Y Axis',
            zaxis_title='Z Axis'
        )
    )
    surface_3d_html = pio.to_html(fig_3d_surface, full_html=False)

    # 3D Line Graph Data
    t = np.linspace(0, 10, 100)
    x = np.sin(t)
    y = np.cos(t)
    z = t

    fig_3d_line = go.Figure()

    # Add 3D Line Trace
    fig_3d_line.add_trace(go.Scatter3d(
        x=x,
        y=y,
        z=z,
        mode='lines+markers',
        line=dict(color='blue', width=2),
        marker=dict(size=5)
    ))

    fig_3d_line.update_layout(
        title='3D Line Graph',
        scene=dict(
            xaxis_title='X Axis',
            yaxis_title='Y Axis',
            zaxis_title='Z Axis'
        )
    )

    # Convert to HTML
    line_3d_html = pio.to_html(fig_3d_line, full_html=False)
    # 3D Cone Plot Data
    # Create a grid of points in 3D space
    x, y, z = np.meshgrid(
        np.linspace(-2, 2, 10),  # X-axis points
        np.linspace(-2, 2, 10),  # Y-axis points
        np.linspace(-2, 2, 10)   # Z-axis points
    )

    # Define vector components (for a hypothetical quantum training field)
    u = -x  # X-component of the vector field
    v = -y  # Y-component of the vector field
    w = z   # Z-component of the vector field

    # Create the 3D Cone Plot
    fig_cone = go.Figure(data=go.Cone(
        x=x.flatten(),
        y=y.flatten(),
        z=z.flatten(),
        u=u.flatten(),
        v=v.flatten(),
        w=w.flatten(),
        colorscale='Viridis',
        sizemode='absolute',
        sizeref=0.5
    ))

    # Update layout
    fig_cone.update_layout(
        title='Quantum-Trained 3D Cone Plot',
        scene=dict(
            xaxis_title='X Axis',
            yaxis_title='Y Axis',
            zaxis_title='Z Axis',
        )
    )

    # Convert the plot to HTML
    cone_html = pio.to_html(fig_cone, full_html=False)
    
       # 3D Sphere Projection
    # Define spherical coordinates
    theta = np.linspace(0, 2 * np.pi, 100)  # Angle around the z-axis
    phi = np.linspace(0, np.pi, 100)        # Angle from the z-axis
    theta, phi = np.meshgrid(theta, phi)

    # Convert spherical coordinates to Cartesian coordinates
    radius = 1  # Sphere radius
    x = radius * np.sin(phi) * np.cos(theta)
    y = radius * np.sin(phi) * np.sin(theta)
    z = radius * np.cos(phi)

    # Create the 3D Sphere Projection
    fig_sphere = go.Figure(data=[go.Surface(
        x=x,
        y=y,
        z=z,
        colorscale='Viridis',  # Color map
        showscale=False       # Hide the color scale
    )])

    # Update layout
    fig_sphere.update_layout(
        title='3D Sphere Projection',
        scene=dict(
            xaxis_title='X Axis',
            yaxis_title='Y Axis',
            zaxis_title='Z Axis',
        )
    )

    # Convert the plot to HTML
    sphere_html = pio.to_html(fig_sphere, full_html=False)

    # Quantum Energy 3D Surface Plot
    x = np.linspace(-2, 2, 100)
    y = np.linspace(-2, 2, 100)
    x, y = np.meshgrid(x, y)
    z = np.exp(-x**2 - y**2) * np.sin(2 * np.pi * x) * np.sin(2 * np.pi * y)

    fig_energy_surface = go.Figure(data=[go.Surface(
        z=z,
        x=x,
        y=y,
        colorscale='Viridis',
        showscale=True,
        colorbar=dict(title="Energy")
    )])
    fig_energy_surface.update_layout(
        title="Quantum Energy 3D Surface",
        scene=dict(
            xaxis_title="X Axis",
            yaxis_title="Y Axis",
            zaxis_title="Energy"
        )
    )
    energy_surface_html = pio.to_html(fig_energy_surface, full_html=False)

    # Quantum State Evolution 3D Trajectory
    time = np.linspace(0, 10, 500)
    x = np.sin(time)
    y = np.cos(time)
    z = time

    fig_state_evolution_3d = go.Figure()

    fig_state_evolution_3d.add_trace(go.Scatter3d(
        x=x, y=y, z=z,
        mode='lines',
        line=dict(color='blue', width=2),
        name='Quantum State'
    ))

    fig_state_evolution_3d.update_layout(
        title="Quantum State Evolution 3D Trajectory",
        scene=dict(
            xaxis_title="Amplitude X",
            yaxis_title="Amplitude Y",
            zaxis_title="Time"
        )
    )
    state_evolution_3d_html = pio.to_html(fig_state_evolution_3d, full_html=False)

     # Quantum Entanglement Probability Distribution
    n_points = 100
    x = np.random.rand(n_points)
    y = np.random.rand(n_points)
    z = np.random.rand(n_points)
    probabilities = np.random.rand(n_points)

    fig_entanglement = go.Figure()

    fig_entanglement.add_trace(go.Scatter3d(
        x=x,
        y=y,
        z=z,
        mode='markers',
        marker=dict(
            size=5,
            color=probabilities,
            colorscale='Portland',
            showscale=True,
            colorbar=dict(title='Probability')
        )
    ))

    fig_entanglement.update_layout(
        title="Quantum Entanglement Probability Distribution",
        scene=dict(
            xaxis_title="Entanglement Factor X",
            yaxis_title="Entanglement Factor Y",
            zaxis_title="Entanglement Factor Z",
        )
    )
    entanglement_html = pio.to_html(fig_entanglement, full_html=False)

    # Quantum Harmonic Oscillator Potential
    x = np.linspace(-2, 2, 100)
    y = np.linspace(-2, 2, 100)
    x, y = np.meshgrid(x, y)
    z = 0.5 * (x**2 + y**2)

    fig_harmonic = go.Figure(data=[go.Surface(
        z=z,
        x=x,
        y=y,
        colorscale='Cividis',
        showscale=True
    )])
    fig_harmonic.update_layout(
        title="Quantum Harmonic Oscillator Potential",
        scene=dict(
            xaxis_title="Position X",
            yaxis_title="Position Y",
            zaxis_title="Potential Energy",
        )
    )
    harmonic_html = pio.to_html(fig_harmonic, full_html=False)

   
   
    


    

    return render_template('quantum_visualization.html', 
                           clusters_html=clusters_html,
                           weights_html=weights_html,energy_1surface_html=energy_1surface_html,
                           workflow_html=workflow_html,
                           decision_1boundary_html=decision_1boundary_html,
                            latency_map_html=latency_map_html,
                            topology_html=topology_html,
                           scatter_html=scatter_html,
                           heatmap_html=heatmap_html,
                           network_html=network_html,
                           gauge_html=gauge_html,
                           scatter_3d_html=scatter_3d_html, surface_3d_html=surface_3d_html,  line_3d_html=line_3d_html, cone_html=cone_html, 
                            sphere_html=sphere_html, energy_surface_html=energy_surface_html,
                           state_evolution_3d_html=state_evolution_3d_html,entanglement_html=entanglement_html,
                           harmonic_html=harmonic_html,
                           
                            )



@app.route('/encryption_demo')
def encryption_demo():
    message = "Quantum Safe Encryption Example"
    encrypted_message = encrypt_message(public_key, message)
    decrypted_message = decrypt_message(private_key, encrypted_message)
    return jsonify({
        "Encrypted": encrypted_message.decode(),
        "Decrypted": decrypted_message
    })


# API for External Integration
class SatelliteDataAPI(Resource):
    def get(self):
        data = pd.read_csv(DATA_PATH)
        return jsonify(data.to_dict(orient='records'))

api.add_resource(SatelliteDataAPI, '/api/satellite_data')

# Configure upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Utility function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Route for File Upload
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if file is uploaded
        if 'file' not in request.files:
            flash("No file part in the request", "danger")
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash("No file selected", "danger")
            return redirect(request.url)
        
        # Validate file type
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Process the uploaded file to generate insights, graphs, and alerts
            insights, ai_graphs, alerts, reduction_mechanisms, error_message = process_csv(file_path)

            if error_message:
                flash(error_message, "danger")
                return redirect(request.url)

            # Flash success message after file is uploaded and processed
            flash("File uploaded successfully!", "success")

            # Render results in insights.html
            return render_template(
                'insights.html',
                insights=insights,
                ai_graphs=ai_graphs,
                alerts=alerts, 
                reduction_mechanisms=reduction_mechanisms, 
                zip=zip  # Pass zip function to the template
            )

    # Render the file upload form
    return render_template('upload.html')

# Function to process CSV and generate AI insights and graphs
def process_csv(file_path):
    required_columns = {'value', 'feature1', 'feature2', 'threat_score', 'label', 'packets', 'num_connections', 'packet_size', 'connection_type', 'response_time'}
    # Load the CSV file
    try:
        # Load the CSV file
        data = pd.read_csv(file_path)
    except Exception as e:
        return None, None, None, None, f"Error reading CSV file: {str(e)}"

    # Validate required columns
    missing_columns = required_columns - set(data.columns)
    if missing_columns:
        error_message = f"The dataset is missing the following required columns: {', '.join(missing_columns)}"
        return None, None, None, None, error_message
    

    # Ensure numeric columns are properly formatted
    for column in data.select_dtypes(include='object').columns:
        data[column] = pd.to_numeric(data[column], errors='coerce')
    data = data.dropna()  # Drop rows with invalid values

    # Real-time Insights (Example: Anomaly Detection)
    insights = {}
    alerts = []  # List to store alert messages
    reduction_mechanisms = []
    if 'value' in data.columns:
        scaler = StandardScaler()
        values_scaled = scaler.fit_transform(data[['value']])
        model = IsolationForest(contamination=0.1, random_state=42)
        data['anomaly'] = model.fit_predict(values_scaled)
        insights['anomalies'] = data[data['anomaly'] == -1].to_dict(orient='records')



    # AI-Trained Graphs
    ai_graphs = []

    # 1. Anomaly Detection Scatter Plot
    if 'value' in data.columns:
        data['anomaly_color'] = data['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
        scatter_fig = px.scatter(
            data,
            x=data.index,
            y='value',
            color='anomaly_color',
            title="Anomaly Detection in Values",
            labels={'x': 'Index', 'value': 'Value'},
            color_discrete_map={'Normal': 'blue', 'Anomaly': 'red'}
        )
        ai_graphs.append(pio.to_html(scatter_fig, full_html=False))

    # 2. Feature Importance from Random Forest
    if {'feature1', 'feature2', 'label'}.issubset(data.columns):
        features = data[['feature1', 'feature2']]
        labels = data['label']
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        feature_importances = rf_model.feature_importances_

        feature_fig = px.bar(
            x=['Feature 1', 'Feature 2'],
            y=feature_importances,
            title="Feature Importance from Random Forest",
            labels={'x': 'Features', 'y': 'Importance'}
        )
        ai_graphs.append(pio.to_html(feature_fig, full_html=False))

    # 3. KMeans Clustering
    if {'feature1', 'feature2'}.issubset(data.columns):
        kmeans = KMeans(n_clusters=3, random_state=42)
        data['cluster'] = kmeans.fit_predict(data[['feature1', 'feature2']])
        cluster_fig = px.scatter(
            data,
            x='feature1',
            y='feature2',
            color='cluster',
            title="KMeans Clustering",
            labels={'feature1': 'Feature 1', 'feature2': 'Feature 2'}
        )
        ai_graphs.append(pio.to_html(cluster_fig, full_html=False))

    # 4. Trend Line Plot
    if 'value' in data.columns:
        trend_fig = px.line(
            data,
            x=data.index,
            y='value',
            title="Trend Line for Values",
            labels={'x': 'Index', 'value': 'Value'}
        )
        ai_graphs.append(pio.to_html(trend_fig, full_html=False))

    # 2. 3D Scatter Plot for Anomaly Visualization
    if 'value' in data.columns:
        fig_3d_scatter = go.Figure()
        fig_3d_scatter.add_trace(go.Scatter3d(
            x=data.index,
            y=data['value'],
            z=data['value'] * 0.1,  # Use a scaled version of 'value' as the Z-axis
            mode='markers',
            marker=dict(
                size=5,
                color=data['anomaly'],  # Use anomaly values for coloring
                colorscale=['blue', 'red'],  # Map anomalies to red, normal to blue
                colorbar=dict(title='Anomaly'),
            ),
            text=data['anomaly_color'],  # Text to display 'Normal' or 'Anomaly'
        ))
        fig_3d_scatter.update_layout(
            title="3D Anomaly Detection Scatter Plot",
            scene=dict(
                xaxis_title="Index",
                yaxis_title="Value",
                zaxis_title="Scaled Value"
            ),
        )
        ai_graphs.append(pio.to_html(fig_3d_scatter, full_html=False))

         # Quantum-Trained Threat Detection Graph (3D)
    if 'feature1' in data.columns and 'feature2' in data.columns and 'threat_score' in data.columns:
        # Set up a quantum device
        dev = qml.device("default.qubit", wires=2)

        @qml.qnode(dev)
        def quantum_feature_map(x):
            qml.Hadamard(wires=0)
            qml.RY(x[0], wires=0)
            qml.RY(x[1], wires=1)
            return qml.probs(wires=[0, 1])

        quantum_features = []
        for _, row in data.iterrows():
            features = [row['feature1'], row['feature2']]
            quantum_features.append(quantum_feature_map(features))
        quantum_features = qnp.array(quantum_features)

        # Generate Quantum-Trained Threat Detection Graph
        fig_3d_threat = go.Figure()
        fig_3d_threat.add_trace(go.Scatter3d(
            x=quantum_features[:, 0],
            y=quantum_features[:, 1],
            z=data['threat_score'],  # Use the 'threat_score' column as the Z-axis
            mode='markers',
            marker=dict(
                size=5,
                color=data['threat_score'],  # Color based on threat score
                colorscale='Viridis',
                colorbar=dict(title='Threat Score'),
            ),
            text=data['anomaly_color'],  # Text to display 'Normal' or 'Anomaly'
        ))
        fig_3d_threat.update_layout(
            title="Quantum-Trained Threat Detection",
            scene=dict(
                xaxis_title="Quantum Feature 1",
                yaxis_title="Quantum Feature 2",
                zaxis_title="Threat Score"
            ),
        )
        ai_graphs.append(pio.to_html(fig_3d_threat, full_html=False))

    if 'value' in data.columns and 'feature1' in data.columns:
        # Simulating packet analysis by scaling feature1 (as packets per second)
        data['packets_per_second'] = data['feature1'] * 1000  # Simulating packet count
        
        # Define DDoS threshold (e.g., >800 packets/sec is DDoS)
        data['DDoS'] = data['packets_per_second'].apply(lambda x: 'DDoS' if x > 800 else 'Normal')

        # Generate scatter plot for DDoS detection
        fig_ddos = px.scatter(
            data,
            x='value',
            y='packets_per_second',
            color='DDoS',
            title='Real-Time DDoS Attack Detection',
            labels={'value': 'Value', 'packets_per_second': 'Packets per Second'},
            color_discrete_map={'DDoS': 'red', 'Normal': 'blue'}
        )
        ai_graphs.append(pio.to_html(fig_ddos, full_html=False))


         # Intrusion Detection System (IDS)
    if {'feature1', 'feature2', 'value'}.issubset(data.columns):
        # Simulating additional network traffic features
        data['num_connections'] = data['feature1'] * 50  # Number of connections
        data['packet_size'] = data['feature2'] * 150  # Average packet size
        data['flags'] = data['value'].apply(lambda x: 1 if x > 50 else 0)  # Binary flags

        # Labels: 1 = Intrusion, 0 = Normal (based on a threshold)
        data['anomaly'] = (data['num_connections'] > 2000) | (data['packet_size'] > 500)
        data['anomaly_label'] = data['anomaly'].apply(lambda x: 'Intrusion' if x else 'Normal')

        # Visualize the IDS results using a scatter plot
        fig_ids = px.scatter(
            data,
            x='num_connections',
            y='packet_size',
            color='anomaly_label',
            size='value',
            title='Intrusion Detection System (IDS)',
            labels={
                'num_connections': 'Number of Connections',
                'packet_size': 'Packet Size (bytes)',
                'value': 'Threat Score',
            },
            color_discrete_map={'Intrusion': 'red', 'Normal': 'blue'},
        )
        ai_graphs.append(pio.to_html(fig_ids, full_html=False))

        # Simulating Threat Intelligence Feed Data
    if {'feature1', 'feature2', 'value'}.issubset(data.columns):
        # Simulate reputation scores and MITRE ATT&CK mapping
        data['reputation_score'] = data['value'].apply(lambda x: random.randint(0, 100))
        data['mitre_attack'] = data['feature1'].apply(
            lambda x: 'Initial Access' if x < 0.3 else 'Exfiltration' if x < 0.7 else 'Privilege Escalation'
        )
        data['packets_sent'] = data['feature2'] * 1000  # Simulate packets sent

        # Generate a 3D scatter plot
        fig_threat = go.Figure(data=go.Scatter3d(
            x=data['reputation_score'],
            y=data['packets_sent'],
            z=data['value'],
            mode='markers',
            marker=dict(
                size=8,
                color=data['value'],  # Use the 'value' column for color intensity
                colorscale='Viridis',
                opacity=0.8
            ),
            text=data['mitre_attack']  # Hover text shows MITRE ATT&CK technique
        ))

        fig_threat.update_layout(
            title='3D Threat Intelligence Feed Analysis',
            scene=dict(
                xaxis_title='Reputation Score',
                yaxis_title='Packets Sent',
                zaxis_title='Threat Value'
            )
        )

        ai_graphs.append(pio.to_html(fig_threat, full_html=False))


      # 4. Time-Series Threat Score
    if 'threat_score' in data.columns:
        time_series_fig = px.line(
            data,
            x=data.index,
            y='threat_score',
            title="Time-Series Threat Score",
            labels={'index': 'Index', 'threat_score': 'Threat Score'},
        )
        time_series_fig.update_traces(mode='lines+markers')
        ai_graphs.append(pio.to_html(time_series_fig, full_html=False))

        # 5. Line Chart for Trend Analysis
    if 'value' in data.columns:
        line_fig = px.line(
            data,
            x=data.index,
            y='value',
            title="Trend Analysis for Values",
            labels={'index': 'Index', 'value': 'Value'},
            color_discrete_sequence=['#636EFA']
        )
        ai_graphs.append(pio.to_html(line_fig, full_html=False))

         # 2. Pie Chart for Threat Categories
    if 'threat_score' in data.columns:
        data['threat_category'] = data['threat_score'].apply(
            lambda x: 'Low' if x < 0.3 else 'Medium' if x < 0.7 else 'High'
        )
        pie_fig = px.pie(
            data,
            names='threat_category',
            title="Threat Score Distribution",
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        ai_graphs.append(pio.to_html(pie_fig, full_html=False))

    # 3. Bar Chart for Threat Score Categories
    if 'threat_score' in data.columns:
        bar_fig = px.bar(
            data,
            x=data.index,
            y='threat_score',
            color='threat_score',
            title="Threat Scores",
            labels={'x': 'Index', 'threat_score': 'Score'},
            color_continuous_scale='Plasma'
        )
        ai_graphs.append(pio.to_html(bar_fig, full_html=False))

        

         # NEW GRAPH: Threat Detection and Reduction Trend
    if 'threat_score' in data.columns and 'num_connections' in data.columns:
        # Calculate rolling average for threat_score
        data['avg_threat_score'] = data['threat_score'].rolling(window=3).mean()

        # Generate a line chart for trend analysis
        trend_fig = px.line(
            data,
            x='num_connections',  # Using 'num_connections' as the x-axis
            y=['threat_score', 'avg_threat_score'],
            title="Threat Detection and Reduction Over Time",
            labels={
                'num_connections': 'Number of Connections',
                'value': 'Threat Score',
                'variable': 'Metric'
            },
        )
        trend_fig.update_traces(mode='lines+markers')
        trend_fig.update_layout(
            legend=dict(
                title="Metrics",
                itemsizing="constant"
            )
        )
        ai_graphs.append(pio.to_html(trend_fig, full_html=False))
        
        # Threshold Levels for Alerts
    THRESHOLDS = {
        'value': 80,  # Example threshold for 'value'
        'threat_score': 0.7,  # Example threshold for 'threat_score'
        'response_time': 100,  # Example threshold for 'response_time'
        'packets': 2000,  # Example threshold for 'packets'
    }

    # Check for Alerts
    for index, row in data.iterrows():
        if row['value'] > THRESHOLDS['value']:
            alerts.append(f"High Value Alert: Row {index} exceeded the threshold for 'value' with {row['value']}.")
        if row['threat_score'] > THRESHOLDS['threat_score']:
            alerts.append(f"High Threat Score Alert: Row {index} exceeded the threshold with {row['threat_score']}.")
        if row['response_time'] > THRESHOLDS['response_time']:
            alerts.append(f"High Response Time Alert: Row {index} exceeded the threshold with {row['response_time']}.")
        if row['packets'] > THRESHOLDS['packets']:
            alerts.append(f"High Packet Alert: Row {index} exceeded the threshold with {row['packets']} packets.")


            # Add reduction mechanisms (example mechanisms)
    reduction_mechanisms = [
        {"mechanism": "Firewall Block Rules", "description": "Blocking high-risk IP addresses detected in anomalies."},
        {"mechanism": "Rate Limiting", "description": "Throttling packets exceeding safe thresholds."},
        {"mechanism": "AI-Based Signature Matching", "description": "Analyzing data patterns and matching them with known threat signatures."},
        {"mechanism": "Quarantine Detected Hosts", "description": "Isolating hosts associated with anomalies to prevent lateral movement."}
    ]

    # Threat reduction logic (example)
    if 'threat_score' in data.columns:
        data['reduced_threat_score'] = data['threat_score'] * 0.5  # Assume a 50% reduction
        reduction_fig = px.bar(
            data,
            x=data.index,
            y=['threat_score', 'reduced_threat_score'],
            title="Threat Levels Before and After Reduction",
            labels={'value': 'Threat Level', 'index': 'Index'},
            barmode='group'
        )
        ai_graphs.append(pio.to_html(reduction_fig, full_html=False))

    # Include other graphs (existing logic)


    # Return insights and graphs
    return insights, ai_graphs,  alerts, reduction_mechanisms, None





if __name__ == '__main__':
    app.run(debug=True)
