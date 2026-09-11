cat > /opt/microsoft_auth_bot/config.py << 'PYEOF'
import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
MS_TENANT_ID = os.getenv("MS_TENANT_ID")
MS_CLIENT_ID = os.getenv("MS_CLIENT_ID")
MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET")
MS_SCOPE = os.getenv("MS_SCOPE", "https://graph.microsoft.com/.default")
MS_TOKEN_URL = os.getenv("MS_TOKEN_URL", "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
POP_PORT = int(os.getenv("POP_PORT", 995))
IMAP_MAP_RAW = os.getenv("IMAP_MAP", "")
IMAP_MAP = {}
if IMAP_MAP_RAW:
    for entry in IMAP_MAP_RAW.split(","):
        parts = entry.strip().split(":")
        if len(parts) == 3:
            domain, server, port = parts[0], parts[1], int(parts[2])
            IMAP_MAP[domain] = {"server": server, "port": port}
DEFAULT_IMAP_SERVER = "outlook.office365.com"
DEFAULT_IMAP_PORT = 993
VALIDATED_FILE = "validated_credentials.json"
PASSWORD_REPORT_FILE = "password_report.json"
SESSION_FILE = "session.json"
PYEOF