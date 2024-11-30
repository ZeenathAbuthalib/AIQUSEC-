import unittest
from flask import Flask
from app import app  # Import your existing app

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_brute_force_protection(self):
        """Test that brute force login attempts are prevented."""
        # Simulate multiple failed login attempts
        for attempt in range(5):  # Replace 5 with the actual limit implemented in the app
            response = self.client.post('/login', json={
                "username": "nonexistent_user",
                "password": "wrongpassword"
            })
            self.assertEqual(response.status_code, 401, f"Failed at attempt {attempt + 1}")

        # Exceeding the limit should result in rate limiting
        lockout_response = self.client.post('/login', json={
            "username": "nonexistent_user",
            "password": "wrongpassword"
        })

        self.assertEqual(lockout_response.status_code, 429, "Rate limiting not triggered after repeated failures")

    def test_successful_login_after_lockout(self):
        """Verify that a legitimate login attempt works after rate limit reset."""
        # Simulate hitting the rate limit
        for attempt in range(5):  # Replace 5 with the actual limit implemented in the app
            self.client.post('/login', json={
                "username": "nonexistent_user",
                "password": "wrongpassword"
            })

        # Wait for the rate limit to reset (adjust time based on your app's rate limiting reset policy)
        import time
        time.sleep(60)  # Assuming 1-minute reset for the rate limit

        # Attempt a valid login after reset
        valid_response = self.client.post('/login', json={
            "username": "admin",  # Replace with an actual valid username
            "password": "password"  # Replace with an actual valid password
        })
        self.assertEqual(valid_response.status_code, 200, "Valid login attempt failed after rate limit reset")


if __name__ == "__main__":
    unittest.main()





