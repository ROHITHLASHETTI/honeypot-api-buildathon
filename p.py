# Save this as test_local.py
import requests

url = "http://127.0.0.1:8000/honeypot"
headers = {
    "x-api-key": "changeme", # This must match your API_KEY env variable
    "Content-Type": "application/json"
}
data = {
    "conversation_id": "local_test_01",
    "message": "Verify this scam: send money to upi@bank"
}

response = requests.post(url, json=data, headers=headers)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.json()}")