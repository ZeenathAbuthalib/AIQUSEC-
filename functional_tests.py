import unittest
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

# Configuration for testing
class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy()

# Mock User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Functional Tests
class FunctionalTests(unittest.TestCase):
    def setUp(self):
        # Setup Flask app for testing
        self.app = Flask(__name__)
        self.app.config.from_object(TestConfig)
        db.init_app(self.app)

        # Define test routes
        @self.app.route('/register', methods=['POST'])
        def register():
            data = request.get_json()
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return jsonify({"error": "Missing required fields"}), 400
            
            if User.query.filter_by(username=username).first():
                return jsonify({"error": "User already exists"}), 409

            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            return jsonify({"message": "Registration successful"}), 201

        @self.app.route('/login', methods=['POST'])
        def login():
            data = request.get_json()
            username = data.get("username")
            password = data.get("password")

            user = User.query.filter_by(username=username).first()
            if user and user.password == password:
                return jsonify({"message": "Login successful"}), 200
            return jsonify({"error": "Invalid credentials"}), 401

        # Initialize database
        with self.app.app_context():
            db.create_all()

        self.client = self.app.test_client()

    def tearDown(self):
        # Clean up database after tests
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_registration_valid_details(self):
        """Test registration with valid details."""
        response = self.client.post('/register', json={
            "username": "testuser",
            "password": "password"
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn("Registration successful", response.get_json()["message"])

    def test_registration_missing_fields(self):
        """Test registration with missing fields."""
        response = self.client.post('/register', json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Missing required fields", response.get_json()["error"])

    def test_registration_duplicate_user(self):
        """Test duplicate user registration."""
        self.client.post('/register', json={
            "username": "testuser",
            "password": "password"
        })
        response = self.client.post('/register', json={
            "username": "testuser",
            "password": "password"
        })
        self.assertEqual(response.status_code, 409)
        self.assertIn("User already exists", response.get_json()["error"])

    def test_login_valid_credentials(self):
        """Test login with valid credentials."""
        self.client.post('/register', json={
            "username": "testuser",
            "password": "password"
        })
        response = self.client.post('/login', json={
            "username": "testuser",
            "password": "password"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful", response.get_json()["message"])

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        self.client.post('/register', json={
            "username": "testuser",
            "password": "password"
        })
        response = self.client.post('/login', json={
            "username": "testuser",
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid credentials", response.get_json()["error"])

if __name__ == "__main__":
    unittest.main()
