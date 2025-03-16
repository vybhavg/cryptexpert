# tests/test_coinbase.py
import unittest
from unittest.mock import patch, Mock
from mark.routes import get_specific_prices_from_coinbase  # Import from app.py

class TestCoinbasePrices(unittest.TestCase):
    @patch('mark.routes.requests.get')
    def test_get_specific_prices_from_coinbase(self, mock_get):
        # Mock the API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"amount": "50000.00"}
        }
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_coinbase()

        # Assert the results
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['symbol'], 'BTC')
        self.assertEqual(result[0]['price'], '50,000.00')

    @patch('cryptexpert.app.requests.get')
    def test_get_specific_prices_from_coinbase_error(self, mock_get):
        # Mock an error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_coinbase()

        # Assert the results
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()
