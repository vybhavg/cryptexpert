# tests/test_okx.py
import unittest
from unittest.mock import patch, Mock
from cryptexpert.app import get_specific_prices_from_okx  # Import from app.py

class TestOKXPrices(unittest.TestCase):
    @patch('cryptexpert.app.requests.get')
    def test_get_specific_prices_from_okx(self, mock_get):
        # Mock the API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"instId": "BTC-USDT", "last": "50000.00", "change24h": "1.23"},
            ]
        }
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_okx()

        # Assert the results
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['symbol'], 'BTC')
        self.assertEqual(result[0]['price'], '50,000.00')

    @patch('cryptexpert.app.requests.get')
    def test_get_specific_prices_from_okx_error(self, mock_get):
        # Mock an error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_okx()

        # Assert the results
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()
