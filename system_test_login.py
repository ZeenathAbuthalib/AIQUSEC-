import unittest
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

# Setup isolated test configuration
class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Setup a separate database instance for tests
db = SQLAlchemy()

def create_test_app():
    """Create an isolated test Flask application."""
    app = Flask(__name__)
    app.config.from_object(TestConfig)
    db.init_app(app)

    # Define test-specific routes
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        if data.get("username") == "adminuser" and data.get("password") == "adminpass":
            return jsonify({"message": "Login successful", "role": "admin"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401

    @app.route('/admin', methods=['GET'])
    def admin():
        if request.headers.get("Role") == "admin":
            return jsonify({"message": "Welcome Admin!"}), 200
        else:
            return jsonify({"message": "Unauthorized"}), 403

    return app

class SystemTest(unittest.TestCase):
    def setUp(self):
        """Set up the test environment with an isolated app."""
        self.app = create_test_app()
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Tear down the test environment."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_login_with_valid_credentials(self):
        """Test login functionality with valid credentials."""
        response = self.client.post('/login', json={"username": "adminuser", "password": "adminpass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful", response.get_json().get("message"))

    def test_login_with_invalid_credentials(self):
        """Test login functionality with invalid credentials."""
        response = self.client.post('/login', json={"username": "wronguser", "password": "wrongpass"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid credentials", response.get_json().get("message"))

    def test_protected_admin_route(self):
        """Test access to admin route."""
        # Case 1: Admin access
        response = self.client.get('/admin', headers={"Role": "admin"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Welcome Admin!", response.get_json().get("message"))

        # Case 2: Unauthorized access
        response = self.client.get('/admin', headers={"Role": "viewer"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("Unauthorized", response.get_json().get("message"))

if __name__ == "__main__":
    unittest.main()

