import pytest
from app import app
from io import BytesIO
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))



@pytest.fixture
def client():
    """Fixture for the Flask test client."""
    with app.test_client() as client:
        yield client


# 1. Test Application Initialization
def test_app_initialization(client):
    response = client.get('/')
    assert response.status_code == 302  # Redirect to login


# 2. Test Registration and Login
def test_register_and_login(client):
    # Test user registration
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpassword',
        'role': 'admin'
    })
    assert response.status_code == 200

    # Test login with the newly registered user
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 302  # Redirect after login


# 3. Test File Upload Workflow
def test_file_upload(client):
    # Simulate CSV file upload
    data = {
        'file': (BytesIO(
            b"value,feature1,feature2,threat_score,label,packets,num_connections,packet_size,response_time\n"
            b"1,0.5,0.6,0.8,1,2000,50,500,100"
        ), 'test.csv')
    }
    response = client.post('/upload', content_type='multipart/form-data', data=data)
    assert response.status_code == 200
    assert b"Insights" in response.data  # Ensure insights page is rendered


# 4. Test AI Insights
def test_ai_insights(client):
    response = client.get('/ai_insights')
    assert response.status_code == 200
    assert b"AI Insights" in response.data  # Check for specific keywords


# 5. Test Satellite Dashboard
def test_satellite_dashboard(client):
    response = client.get('/satellite_dashboard')
    assert response.status_code == 200
    assert b"Satellite Dashboard" in response.data  # Check for dashboard elements


# 6. Test Quantum Visualization
def test_quantum_visualization(client):
    response = client.get('/quantum_visualization')
    assert response.status_code == 200
    assert b"Quantum Visualization" in response.data


# 7. Test Encryption Demo
def test_encryption_demo(client):
    response = client.get('/encryption_demo')
    assert response.status_code == 200
    data = response.get_json()
    assert "Encrypted" in data
    assert "Decrypted" in data


# 8. Test Insights and Alerts from File Upload
def test_process_csv(client):
    # Simulate a valid CSV file upload
    data = {
        'file': (BytesIO(
            b"value,feature1,feature2,threat_score,label,packets,num_connections,packet_size,response_time\n"
            b"85,0.7,0.8,0.9,1,3000,70,700,200\n"
            b"40,0.4,0.3,0.6,0,1000,30,300,50"
        ), 'valid.csv')
    }
    response = client.post('/upload', content_type='multipart/form-data', data=data)
    assert response.status_code == 200
    assert b"Anomalies Detected" in response.data or b"Alerts Detected" in response.data


# 9. Test Admin Dashboard Password Validation
def test_admin_dashboard(client):
    # Simulate login as admin
    client.post('/register', data={
        'username': 'adminuser',
        'password': 'adminpass',
        'role': 'admin'
    })
    client.post('/login', data={
        'username': 'adminuser',
        'password': 'adminpass'
    })

    # Access admin dashboard
    response = client.get('/admin')
    assert response.status_code == 200 or response.status_code == 302  # Password prompt or dashboard


# 10. Test Satellite Positions API
def test_satellite_positions(client):
    response = client.get('/api/satellite_positions')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list) or "error" in data


# 11. Test Satellite Data API
def test_satellite_data_api(client):
    response = client.get('/api/satellite_data')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)  # Should return a list of dictionaries


# 12. Test Quantum Workflow Visualization
def test_quantum_workflow(client):
    response = client.get('/quantum_visualization')
    assert response.status_code == 200
    assert b"Quantum State Evolution" in response.data
