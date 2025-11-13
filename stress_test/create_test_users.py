# ==================== WARNING ====================
# line @limiter.limit("5 per minute") should be commented in app.py in register endpoint
# lines #'SOL': Decimal('20000.0'), and #'USDT': Decimal('100000.0'), in app.py in register should be uncommented
# lines 'USDT': Decimal('0.0'), and 'SOL': Decimal('0.0'), in app.py in register should be commented
# =================================================
import string

import requests
import json
import random
import threading

BASE_URL = "http://localhost:5003/"
NUM_USERS = 50
INITIAL_USDT = 100000
INITIAL_SOL = 20000


class UserManager:
    def __init__(self):
        self.users = []
        self.lock = threading.Lock()

    def create_test_user(self, user_id):
        try:
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            user_data = {
                "email": f"testuser{user_id}" + random_suffix + "@example.com",
                "username": f"stress_test_{user_id}" + random_suffix,
                "password": "TestPassword123!"
            }

            print(f"Creating user {user_id}: {user_data['username']}")

            response = requests.post(
                f"{BASE_URL}/api/auth/register",
                json=user_data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            if response.status_code in [201, 200]:
                user_info = response.json()

                if 'user' in user_info and 'id' in user_info['user']:
                    user_id_actual = user_info['user']['id']
                    deposit_address = user_info['user'].get('deposit_address', '')

                    print(f"User {user_id} registered successfully (ID: {user_id_actual})")

                    login_data = {
                        "username": user_data["username"],
                        "password": user_data["password"]
                    }

                    login_response = requests.post(
                        f"{BASE_URL}/api/auth/login",
                        json=login_data,
                        timeout=30
                    )

                    if login_response.status_code == 200:
                        auth_data = login_response.json()
                        access_token = auth_data['access_token']

                        self.simulate_deposit(user_id_actual, deposit_address, access_token)

                        with self.lock:
                            self.users.append({
                                'id': user_id_actual,
                                'username': user_data['username'],
                                'email': user_data['email'],
                                'access_token': access_token,
                                'deposit_address': deposit_address
                            })

                        print(f"User {user_id} fully configured (ID: {user_id_actual})")
                        return True
                    else:
                        print(f"Login failed for user {user_id}: {login_response.text}")
                        return False
                else:
                    print(f"Invalid response format for user {user_id}")
                    return False
            else:
                print(
                    f"Registration failed for user {user_id}: Status {response.status_code}, Response: {response.text}")
                return False

        except Exception as e:
            print(f"Error creating user {user_id}: {str(e)}")
            return False

    def simulate_deposit(self, user_id, address, access_token):
        try:
            usdt_deposit = {
                "address": address,
                "amount": INITIAL_USDT,
                "token": "USDT"
            }

            usdt_response = requests.post(
                f"{BASE_URL}/api/wallet/deposit",
                json=usdt_deposit,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                timeout=30
            )

            sol_deposit = {
                "address": address,
                "amount": INITIAL_SOL,
                "token": "SOL"
            }

            sol_response = requests.post(
                f"{BASE_URL}/api/wallet/deposit",
                json=sol_deposit,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                timeout=30
            )

            if usdt_response.status_code == 201 and sol_response.status_code == 201:
                print(f"Deposited {INITIAL_USDT} USDT and {INITIAL_SOL} SOL for user {user_id}")
                return True
            else:
                print(
                    f"Deposit simulation issues for user {user_id}: USDT={usdt_response.status_code}, SOL={sol_response.status_code}")
                return False

        except Exception as e:
            print(f"Deposit simulation failed for user {user_id}: {str(e)}")
            return False

    def create_all_users(self):
        print(f"Starting creation of {NUM_USERS} test users...")

        successful_users = 0

        for user_num in range(1, NUM_USERS + 1):
            if self.create_test_user(user_num):
                successful_users += 1

        print(f"Successfully created {successful_users}/{NUM_USERS} users")

        self.save_users_to_file()

        return self.users

    def save_users_to_file(self):
        try:
            users_data = []
            for user in self.users:
                users_data.append({
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'access_token': user['access_token'],
                    'deposit_address': user['deposit_address']
                })

            with open('test_users.json', 'w') as f:
                json.dump(users_data, f, indent=2)

            print(f"User data saved to test_users.json")
            print(f"Users created: {len(self.users)}")

            for user in self.users:
                print(f" {user['username']} (ID: {user['id']})")

        except Exception as e:
            print(f"Failed to save user data: {str(e)}")


def check_system_health():
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            health_data = response.json()
            print(f"System is healthy: {health_data.get('status', 'unknown')}")
            return True
        else:
            print(f"System health check failed: Status {response.status_code}")
            return False
    except Exception as e:
        print(f"Cannot connect to system: {str(e)}")
        return False


if __name__ == "__main__":
    if not check_system_health():
        print("Please start the server first!")
        exit(1)

    manager = UserManager()
    users = manager.create_all_users()
