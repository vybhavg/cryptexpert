# tests/test_okx.py
import unittest
from unittest.mock import patch, Mock
from mark.routes import get_specific_prices_from_okx  # Import from the correct module

class TestOKXPrices(unittest.TestCase):
    @patch('mark.routes.requests.get')  # Mock requests.get in the correct module
    def test_get_specific_prices_from_okx(self, mock_get):
        # Mock the API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"instId": "BTC-USDT", "last": "50000.00", "change24h": "1.23"},
                {"instId": "ETH-USDT", "last": "4000.00", "change24h": "2.34"},
            ]
        }
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_okx()

        # Assert the results
        self.assertEqual(len(result), 2)  # Ensure this matches the number of mocked items
        self.assertEqual(result[0]['symbol'], 'BTC')
        self.assertEqual(result[0]['price'], '50,000.00')
        self.assertEqual(result[0]['priceChangePercent'], '123.00')

    @patch('mark.routes.requests.get')
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
