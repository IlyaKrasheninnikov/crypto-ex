import requests
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)


class PriceService:
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 10  # seconds

    def get_price(self, pair):
        try:
            base, quote = pair.split('/')

            coin_map = {
                'BTC': 'bitcoin',
                'ETH': 'ethereum',
                'BNB': 'binancecoin',
                'XRP': 'ripple',
                'SOL': 'solana',
                'USDT': 'tether'
            }

            if base not in coin_map or quote not in coin_map:
                return None

            url = f"https://api.coingecko.com/api/v3/simple/price"
            params = {
                'ids': coin_map[base],
                'vs_currencies': quote.lower()
            }

            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                price = data.get(coin_map[base], {}).get(quote.lower())
                if price:
                    return Decimal(str(price))

            return self._get_fallback_price(pair)

        except Exception as e:
            logger.error(f"Price fetch error: {e}")
            return self._get_fallback_price(pair)

    def _get_fallback_price(self, pair):
        fallback_prices = {
            'BTC/USDT': Decimal('45000'),
            'ETH/USDT': Decimal('2500'),
            'BNB/USDT': Decimal('300'),
            'XRP/USDT': Decimal('0.60'),
            'SOL/USDT': Decimal('100'),
        }
        return fallback_prices.get(pair, Decimal('1'))

    def get_24h_change(self, pair):
        try:
            base, quote = pair.split('/')
            coin_map = {
                'BTC': 'bitcoin',
                'ETH': 'ethereum',
                'BNB': 'binancecoin',
                'XRP': 'ripple',
                'SOL': 'solana'
            }

            if base not in coin_map:
                return 0

            url = f"https://api.coingecko.com/api/v3/simple/price"
            params = {
                'ids': coin_map[base],
                'vs_currencies': 'usd',
                'include_24hr_change': 'true'
            }

            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                change = data.get(coin_map[base], {}).get('usd_24h_change', 0)
                return round(change, 2)

            return 0
        except:
            return 0

    def get_current_price(self, pair):
        if '/' not in pair:
            if pair.endswith('USDT'):
                base = pair[:-4]
                pair = f"{base}/USDT"
            elif pair.endswith('BTC'):
                base = pair[:-3]
                pair = f"{base}/BTC"

        try:
            price = self.get_price(pair)
            if price is None or price <= 0:
                logger.warning(f"Invalid price for {pair}, using fallback")
                return self._get_fallback_price(pair)
            return price
        except Exception as e:
            logger.error(f"Price fetch failed for {pair}: {e}")
            return self._get_fallback_price(pair)
