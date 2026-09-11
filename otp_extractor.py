cat > /opt/microsoft_auth_bot/otp_extractor.py << 'PYEOF'
import imaplib
import email
import re
import time
from datetime import datetime, timedelta
from config import IMAP_MAP, DEFAULT_IMAP_SERVER, DEFAULT_IMAP_PORT

class OTPExtractor:
    OTP_PATTERNS = [
        re.compile(r'(\b\d{6}\b)'),
        re.compile(r'OTP[:\s]+(\d{4,8})', re.IGNORECASE),
        re.compile(r'code[:\s]+(\d{4,8})', re.IGNORECASE),
        re.compile(r'verification code[:\s]+\d{4,8}', re.IGNORECASE),
        re.compile(r'one-time pass[:\s]+(\d{4,8})', re.IGNORECASE),
    ]
    MICROSOFT_SENDERS = [
        "microsoft.com", "outlook.com", "office365.com",
        "live.com", "noreply@microsoft.com", "security@msft.com"
    ]
    def __init__(self):
        self.mail = None
    def get_imap_server(self, email_addr):
        domain = email_addr.split("@")[-1].lower().strip()
        if domain in IMAP_MAP:
            return IMAP_MAP[domain]["server"], IMAP_MAP[domain]["port"]
        return DEFAULT_IMAP_SERVER, DEFAULT_IMAP_PORT
    def connect(self, email_addr, password):
        server, port = self.get_imap_server(email_addr)
        self.mail = imaplib.IMAP4_SSL(server, port)
        self.mail.login(email_addr, password)
        self.mail.select("INBOX")
        print(f"[+] IMAP connected for {email_addr} via {server}:{port}")
    def disconnect(self):
        if self.mail:
            self.mail.logout()
            print("[-] IMAP session closed.")
    def _decode_body(self, msg):
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(errors="ignore")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
        return body
    def _is_microsoft_email(self, from_header):
        from_lower = from_header.lower()
        return any(domain in from_lower for domain in self.MICROSOFT_SENDERS)
    def _extract_otp(self, text):
        for pattern in self.OTP_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return None
    def fetch_otp(self, email_addr, max_age_minutes=10, poll_interval=15, max_attempts=8):
        cutoff = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        search_criteria = f'(SINCE "{cutoff.strftime("%d-%b-%Y")}")'
        attempts = 0
        while attempts < max_attempts:
            attempts += 1
            try:
                status, data = self.mail.search(None, search_criteria)
                if status != "OK":
                    print(f"[!] Search failed (attempt {attempts}/{max_attempts})")
                    time.sleep(poll_interval)
                    continue
                email_ids = data[0].split()
                for email_id in reversed(email_ids):
                    status, msg_data = self.mail.fetch(email_id, "(RFC822)")
                    if status != "OK":
                        continue
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    from_header = str(msg.get("From", ""))
                    subject = str(msg.get("Subject", ""))
                    if not self._is_microsoft_email(from_header):
                        continue
                    otp_keywords = ["otp", "verification", "security code", "one-time pass", "sign-in", "login code", "password reset", "account verification"]
                    if not any(kw in subject.lower() for kw in otp_keywords):
                        continue
                    body = self._decode_body(msg)
                    otp = self._extract_otp(body)
                    if otp:
                        print(f"[+] OTP found: {otp} (from: {subject})")
                        return otp
                print(f"[*] Attempt {attempts}/{max_attempts}: No OTP found. Polling in {poll_interval}s...")
                time.sleep(poll_interval)
            except Exception as e:
                print(f"[!] Error during polling: {e}")
                time.sleep(poll_interval)
        print("[!] OTP retrieval timed out after all attempts.")
        return None
PYEOF
