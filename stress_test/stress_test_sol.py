# ==================== WARNING ====================
# line @limiter.limit("100 per minute") and line @require_kyc should be commented in app.py in order/place endpoint
# =================================================
import requests
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime


class TradingStressTest:
    def __init__(self):
        self.base_url = "http://localhost:5003/api"
        self.users = []
        self.results = []
        self.lock = threading.Lock()
        self.stats = {
            'total_orders': 0,
            'successful_orders': 0,
            'failed_orders': 0,
            'buy_orders': 0,
            'sell_orders': 0,
            'start_time': None,
            'end_time': None
        }

    def load_users(self):
        try:
            with open('test_users.json', 'r') as f:
                self.users = json.load(f)
            print(f"Loaded {len(self.users)} users for stress test")
        except Exception as e:
            print(f"Failed to load users: {str(e)}")
            return False
        return True

    def place_order(self, user, order_type, price, quantity):
        try:
            order_data = {
                "pair": "SOLUSDT",
                "side": order_type,
                "price": price,
                "amount": quantity,
                "order_side": "limit"
            }

            headers = {
                "Authorization": f"Bearer {user['access_token']}",
                "Content-Type": "application/json",
                "X-User-ID": str(user['id'])
            }

            start_time = time.time()
            response = requests.post(
                f"{self.base_url}/orders/place",
                json=order_data,
                headers=headers,
                timeout=30
            )
            end_time = time.time()

            response_time = (end_time - start_time) * 1000

            result = {
                'user_id': user['id'],
                'order_type': order_type,
                'price': price,
                'quantity': quantity,
                'response_time_ms': response_time,
                'success': False,
                'status_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            }

            if response.status_code == 201:
                order_info = response.json()
                result['success'] = True
                result['order_id'] = order_info.get('order', {}).get('id')

                with self.lock:
                    self.stats['successful_orders'] += 1
                    self.stats['total_orders'] += 1
                    if order_type == 'buy':
                        self.stats['buy_orders'] += 1
                    else:
                        self.stats['sell_orders'] += 1

                print(f"{order_type.upper()} order placed by user {user['id']} - {response_time:.2f}ms")

            else:
                with self.lock:
                    self.stats['failed_orders'] += 1
                    self.stats['total_orders'] += 1

                print(f"{order_type.upper()} order failed for user {user['id']} - Status: {response.status_code}")
                result['error'] = response.text

            self.results.append(result)
            return result

        except Exception as e:
            error_result = {
                'user_id': user['id'],
                'order_type': order_type,
                'price': price,
                'quantity': quantity,
                'response_time_ms': 0,
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

            with self.lock:
                self.stats['failed_orders'] += 1
                self.stats['total_orders'] += 1

            self.results.append(error_result)
            print(f"Exception for user {user['id']}: {str(e)}")
            return error_result

    def generate_realistic_price(self, base_price=100):
        fluctuation = random.uniform(-0.05, 0.05)
        return round(base_price * (1 + fluctuation), 2)

    def generate_realistic_quantity(self):
        return random.uniform(1, 100)

    def user_trading_session(self, user, num_orders=20):
        print(f"Starting trading session for user {user['id']}")

        for i in range(num_orders):
            order_type = random.choice(['buy', 'sell'])

            price = self.generate_realistic_price()
            quantity = self.generate_realistic_quantity()

            self.place_order(user, order_type, price, quantity)

            time.sleep(random.uniform(0.1, 1))

    def run_stress_test(self, orders_per_user=20, max_workers=10):
        if not self.load_users():
            return

        print(f"Starting stress test with {len(self.users)} users, {orders_per_user} orders per user")
        print(f"Total orders to be placed: {len(self.users) * orders_per_user}")

        self.stats['start_time'] = datetime.now()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self.user_trading_session, user, orders_per_user)
                for user in self.users
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Trading session error: {str(e)}")

        self.stats['end_time'] = datetime.now()

        self.analyze_results()

    def analyze_results(self):
        total_time = (self.stats['end_time'] - self.stats['start_time']).total_seconds()

        successful_orders = self.stats['successful_orders']
        total_orders = self.stats['total_orders']
        success_rate = (successful_orders / total_orders * 100) if total_orders > 0 else 0

        orders_per_second = total_orders / total_time if total_time > 0 else 0

        response_times = [r['response_time_ms'] for r in self.results if r['success']]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0

        print("\n" + "=" * 60)
        print("STRESS TEST RESULTS")
        print("=" * 60)
        print(f"Total test duration: {total_time:.2f} seconds")
        print(f"Total orders placed: {total_orders}")
        print(f"Successful orders: {successful_orders}")
        print(f"Failed orders: {self.stats['failed_orders']}")
        print(f"Success rate: {success_rate:.2f}%")
        print(f"Orders per second: {orders_per_second:.2f}")
        print(f"Buy orders: {self.stats['buy_orders']}")
        print(f"Sell orders: {self.stats['sell_orders']}")
        print(f"Average response time: {avg_response_time:.2f}ms")
        print(f"Min response time: {min_response_time:.2f}ms")
        print(f"Max response time: {max_response_time:.2f}ms")

        self.save_detailed_results()

    def save_detailed_results(self):
        results_data = {
            'summary': {
                'total_orders': self.stats['total_orders'],
                'successful_orders': self.stats['successful_orders'],
                'failed_orders': self.stats['failed_orders'],
                'buy_orders': self.stats['buy_orders'],
                'sell_orders': self.stats['sell_orders'],
                'start_time': self.stats['start_time'].isoformat(),
                'end_time': self.stats['end_time'].isoformat()
            },
            'detailed_results': self.results
        }

        with open('stress_test_results.json', 'w') as f:
            json.dump(results_data, f, indent=2)

        print("Detailed results saved to stress_test_results.json")


def check_system_health():
    try:
        response = requests.get("http://localhost:5003/health", timeout=5)
        if response.status_code == 200:
            print("System is healthy")
            return True
        else:
            print("System health check failed")
            return False
    except Exception as e:
        print(f"Cannot connect to system: {str(e)}")
        return False


if __name__ == "__main__":
    if not check_system_health():
        print("Please start the server first!")
        exit(1)

    stress_test = TradingStressTest()
    stress_test.run_stress_test(
        orders_per_user=20,
        max_workers=15
    )