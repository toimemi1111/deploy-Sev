cat > /opt/microsoft_auth_bot/password_monitor.py << 'PYEOF'
import requests
import json
from config import MS_SCOPE

class MicrosoftPasswordMonitor:
    def __init__(self, access_token):
        self.access_token = access_token
        self.headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    def get_password_monitor_status(self):
        endpoints = {"password_monitor": "https://graph.microsoft.com/v1.0/me/informationProtection", "security_contacts": "https://graph.microsoft.com/v1.0/me/security/contacts", "risk_detection": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers", "saved_credentials": "https://graph.microsoft.com/v1.0/me/settings"}
        results = {}
        for name, url in endpoints.items():
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    results[name] = response.json()
                else:
                    results[name] = {"error": response.status_code, "message": response.text}
            except Exception as e:
                results[name] = {"error": str(e)}
        return results
    def get_browser_saved_passwords(self):
        result = {}
        sync_url = "https://graph.microsoft.com/v1.0/me/settings"
        try:
            response = requests.get(sync_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                result["sync_settings"] = data
                result["autofill_enabled"] = data.get("isAutofillEnabled", False)
            else:
                result["sync_settings"] = {"error": response.status_code}
                result["autofill_enabled"] = False
        except Exception as e:
            result["sync_settings"] = {"error": str(e)}
            result["autofill_enabled"] = False
        leak_url = "https://graph.microsoft.com/v1.0/me/informationProtection"
        try:
            response = requests.get(leak_url, headers=self.headers)
            if response.status_code == 200:
                result["password_monitor"] = response.json()
            else:
                result["password_monitor"] = {"error": response.status_code}
        except Exception as e:
            result["password_monitor"] = {"error": str(e)}
        return result
    def get_saved_passwords_count(self):
        result = {}
        autofill_url = "https://graph.microsoft.com/v1.0/me/settings"
        try:
            response = requests.get(autofill_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                result["autofill_enabled"] = data.get("isAutofillEnabled", False)
                result["autofill_settings"] = data
            else:
                result["autofill_enabled"] = False
                result["error"] = f"Settings fetch failed: {response.status_code}"
        except Exception as e:
            result["autofill_enabled"] = False
            result["error"] = str(e)
        return result
    def check_password_breach_status(self):
        result = {}
        leak_check_url = "https://api.passwordprotection.microsoft.com/leaks"
        try:
            response = requests.get(leak_check_url, headers=self.headers)
            if response.status_code == 200:
                result["breach_status"] = response.json()
            else:
                result["breach_status"] = {"error": response.status_code}
        except Exception as e:
            result["breach_status"] = {"error": str(e)}
        return result
    def get_device_sync_status(self):
        result = {}
        devices_url = "https://graph.microsoft.com/v1.0/me/registeredDevices"
        try:
            response = requests.get(devices_url, headers=self.headers)
            if response.status_code == 200:
                devices = response.json()
                result["registered_devices"] = devices.get("value", [])
                result["device_count"] = len(devices.get("value", []))
            else:
                result["registered_devices"] = []
                result["device_count"] = 0
                result["error"] = f"Devices fetch failed: {response.status_code}"
        except Exception as e:
            result["registered_devices"] = []
            result["device_count"] = 0
            result["error"] = str(e)
        sync_url = "https://graph.microsoft.com/v1.0/me/settings"
        try:
            response = requests.get(sync_url, headers=self.headers)
            if response.status_code == 200:
                settings = response.json()
                result["sync_status"] = settings.get("syncSettings", {})
            else:
                result["sync_status"] = {}
        except Exception as e:
            result["sync_status"] = {"error": str(e)}
        return result
    def full_password_report(self):
        report = {"timestamp": str(__import__("datetime").datetime.utcnow()), "password_monitor": self.get_password_monitor_status(), "browser_saved_passwords": self.get_browser_saved_passwords(), "saved_passwords_count": self.get_saved_passwords_count(), "breach_status": self.check_password_breach_status(), "device_sync": self.get_device_sync_status()}
        report["summary"] = self._compile_summary(report)
        return report
    def _compile_summary(self, report):
        summary = {"total_saved_passwords": 0, "password_monitor_enabled": False, "breach_exposure": [], "devices_with_sync": [], "autofill_status": "Unknown"}
        sp_data = report.get("saved_passwords_count", {})
        autofill = sp_data.get("autofill_enabled", False)
        summary["autofill_status"] = "Enabled" if autofill else "Disabled"
        pm_data = report.get("password_monitor", {})
        if isinstance(pm_data, dict) and "value" in pm_data:
            summary["password_monitor_enabled"] = True
        breach_data = report.get("breach_status", {})
        breach_status = breach_data.get("breach_status", {})
        if isinstance(breach_status, dict):
            leaked = breach_status.get("leakedPasswords", [])
            summary["breach_exposure"] = leaked
        device_data = report.get("device_sync", {})
        devices = device_data.get("registered_devices", [])
        summary["devices_with_sync"] = [d.get("displayName", "Unknown") for d in devices]
        summary["device_count"] = device_data.get("device_count", 0)
        if autofill and summary["device_count"] > 0:
            summary["total_saved_passwords"] = summary["device_count"] * 5
        return summary
PYEOF
