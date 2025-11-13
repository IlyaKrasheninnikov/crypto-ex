import requests
import json

# API endpoint URL
url = "http://127.0.0.1:5003/api/wallet/deposit"

# Headers
headers = {
    "Content-Type": "application/json",
    "X-User-ID": "6"
}

# Request payload
payload = {
    "amount": 3.5,
    "currency": "BTC"
}

try:
    # Make the POST request
    response = requests.post(
        url=url,
        headers=headers,
        data=json.dumps(payload)
    )

    # Print the response
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")

    # Parse and pretty print JSON response if successful
    if response.status_code == 201:
        response_data = response.json()
        print("\nDeposit Successful!")
        print(f"Transaction ID: {response_data.get('transaction_id')}")
        print(f"Amount: {response_data.get('amount')} {response_data.get('currency')}")
        print(f"New Balance: {response_data.get('new_balance')} {response_data.get('currency')}")
        print(f"Message: {response_data.get('message')}")
    else:
        print(f"Error: {response.json().get('error', 'Unknown error')}")

except requests.exceptions.ConnectionError:
    print("Connection Error: Could not connect to the server. Make sure it's running on localhost:5003")
except requests.exceptions.Timeout:
    print("Timeout Error: The request timed out")
except requests.exceptions.RequestException as e:
    print(f"Request Error: {e}")
except json.JSONDecodeError:
    print("Error: Invalid JSON response from server")