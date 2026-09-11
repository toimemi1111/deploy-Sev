cat > /opt/microsoft_auth_bot/microsoft_auth.py << 'PYEOF'
import requests
import json
from config import MS_TOKEN_URL, MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET, MS_SCOPE

class MicrosoftAuthenticator:
    def __init__(self):
        self.token_url = MS_TOKEN_URL.format(tenant=MS_TENANT_ID)
        self.client_id = MS_CLIENT_ID
        self.client_secret = MS_CLIENT_SECRET
        self.scope = MS_SCOPE
    def authenticate(self, username, password, otp):
        token_data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "username": username,
            "password": password,
            "grant_type": "password",
            "client_secret": self.client_secret,
            "otp": otp,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        response = requests.post(self.token_url, data=token_data, headers=headers)
        if response.status_code == 200:
            token_data = response.json()
            print("[+] Microsoft authentication successful!")
            return {"access_token": token_data.get("access_token"), "refresh_token": token_data.get("refresh_token"), "expires_in": token_data.get("expires_in"), "token_type": token_data.get("token_type")}
        else:
            error_data = response.json()
            error_code = error_data.get("error", "unknown")
            error_desc = error_data.get("error_description", "")
            print(f"[-] Auth failed: {error_code} — {error_desc}")
            return None
    def get_graph_data(self, access_token, endpoint="https://graph.microsoft.com/v1.0/me"):
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[-] Graph API error: {response.status_code}")
            return None
    def refresh_access_token(self, refresh_token):
        token_data = {"client_id": self.client_id, "scope": self.scope, "refresh_token": refresh_token, "grant_type": "refresh_token", "client_secret": self.client_secret}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        response = requests.post(self.token_url, data=token_data, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
PYEOF