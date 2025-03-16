# tests/test_auth.py
import unittest
from mark.routes import app, db, User  # Import your Flask app and User model
from werkzeug.security import generate_password_hash

class TestAuthRoutes(unittest.TestCase):
    def setUp(self):
        # Set up the test client
        self.client = app.test_client()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        db.create_all()

        # Create a test user
        self.test_user = User(
            username="testuser",
            email="test@example.com",
            password=generate_password_hash("testpassword")
        )
        db.session.add(self.test_user)
        db.session.commit()

    def tearDown(self):
        # Clean up the database
        db.session.remove()
        db.drop_all()

    def test_login_success(self):
        # Test successful login
        response = self.client.post('/login', data={
            "username": "testuser",
            "password": "testpassword"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Logged in successfully", response.data)

    def test_login_failure(self):
        # Test failed login
        response = self.client.post('/login', data={
            "username": "testuser",
            "password": "wrongpassword"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Username and password are incorrect", response.data)

if __name__ == '__main__':
    unittest.main()
