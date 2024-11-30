import unittest
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

# Testing configuration
class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy()

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

# Flask app factory for testing
def create_test_app():
    app = Flask(__name__)
    app.config.from_object(TestConfig)
    db.init_app(app)

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({"message": "Missing required fields"}), 400

        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return jsonify({"message": "User already exists"}), 400

        user = User(username=data['username'], role=data.get('role', 'viewer'))
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Registration successful"}), 201

    return app

# System tests for user registration
class UserRegistrationSystemTest(unittest.TestCase):
    def setUp(self):
        """Set up the test environment."""
        self.app = create_test_app()
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Tear down the test environment."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_user_registration_valid(self):
        """Test successful user registration."""
        response = self.client.post('/register', json={
            "username": "newuser",
            "password": "securepassword",
            "role": "viewer"
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn("Registration successful", response.get_json()["message"])

    def test_user_registration_duplicate(self):
        """Test duplicate user registration."""
        # Register a user
        self.client.post('/register', json={
            "username": "existinguser",
            "password": "password123",
            "role": "viewer"
        })
        # Attempt to register the same user again
        response = self.client.post('/register', json={
            "username": "existinguser",
            "password": "password123",
            "role": "viewer"
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("User already exists", response.get_json()["message"])

    def test_user_registration_missing_fields(self):
        """Test registration with missing fields."""
        response = self.client.post('/register', json={
            "username": "",  # Missing username
            "password": "password123",
            "role": "viewer"
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Missing required fields", response.get_json()["message"])

# Run the tests
if __name__ == "__main__":
    unittest.main()
