# tests/test_binance.py
import unittest
from unittest.mock import patch, Mock
from cryptexpert.app import get_specific_prices_from_binance  # Import from app.py

class TestBinancePrices(unittest.TestCase):
    @patch('cryptexpert.app.requests.get')  # Mock requests.get in app.py
    def test_get_specific_prices_from_binance(self, mock_get):
        # Mock the API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"symbol": "BTCUSDT", "lastPrice": "50000.00", "priceChangePercent": "1.23"},
        ]
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_binance()

        # Assert the results
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['symbol'], 'BTCUSDT')

    @patch('cryptexpert.app.requests.get')
    def test_get_specific_prices_from_binance_error(self, mock_get):
        # Mock an error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        # Call the function
        result = get_specific_prices_from_binance()

        # Assert the results
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()
