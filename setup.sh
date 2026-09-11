cat > /opt/microsoft_auth_bot/setup.sh << 'SHEOF'
#!/bin/bash
set -e
echo "=========================================="
echo " Microsoft IMAP Auth Bot - Setup Script"
echo "=========================================="
echo ""
echo "[1/12] Updating system..."
apt update && apt upgrade -y
echo "[2/12] Installing Python 3.11+ and dependencies..."
apt install -y python3 python3-pip python3-venv git curl
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "    Python version: $PYTHON_VERSION"
echo "[3/12] Creating project directory..."
mkdir -p /opt/microsoft_auth_bot
mkdir -p /var/log/microsoft_auth_bot
mkdir -p /opt/microsoft_auth_bot/uploads
echo "[4/12] Setting up project files..."
cd /opt/microsoft_auth_bot
echo "[5/12] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "[6/12] Installing Python dependencies..."
pip install --upgrade pip
pip install python-telegram-bot>=20.0 imaplib2 requests>=2.28.0 python-dotenv>=1.0.0 aiohttp>=3.9.0
echo "[7/12] Configuring UFW firewall..."
ufw allow 22/tcp
ufw allow 993/tcp
ufw --force enable
echo "[8/12] Setting up .env file..."
echo "[9/12] Setting up log rotation..."
cat > /etc/logrotate.d/microsoft_auth_bot << 'LOGEOF'
/var/log/microsoft_auth_bot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
LOGEOF
echo "[10/12] Creating systemd services..."
cat > /etc/systemd/system/microsoft-auth-bot.service << 'SRVEOF'
[Unit]
Description=Microsoft IMAP Auth Bot
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/microsoft_auth_bot
ExecStart=/opt/microsoft_auth_bot/venv/bin/python /opt/microsoft_auth_bot/bot.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/microsoft_auth_bot/bot.log
StandardError=append:/var/log/microsoft_auth_bot/bot_error.log
[Install]
WantedBy=multi-user.target
SRVEOF
cat > /etc/systemd/system/microsoft-auth-orchestrator.service << 'SRVEOF'
[Unit]
Description=Microsoft Auth Orchestrator
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/microsoft_auth_bot
ExecStart=/opt/microsoft_auth_bot/venv/bin/python /opt/microsoft_auth_bot/main.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/microsoft_auth_bot/orchestrator.log
StandardError=append:/var/log/microsoft_auth_bot/orchestrator_error.log
[Install]
WantedBy=multi-user.target
SRVEOF
echo "[11/12] Enabling services..."
systemctl daemon-reload
systemctl enable microsoft-auth-bot.service
systemctl enable microsoft-auth-orchestrator.service
echo "[12/12] Starting services..."
systemctl start microsoft-auth-bot.service
systemctl start microsoft-auth-orchestrator.service
echo ""
echo "=========================================="
echo " Deployment Complete!"
echo "=========================================="
echo ""
echo "Service Status:"
systemctl status microsoft-auth-bot.service --no-pager
echo ""
echo "Useful Commands:"
echo "  Start:   systemctl start microsoft-auth-bot"
echo "  Stop:    systemctl stop microsoft-auth-bot"
echo "  Status:  systemctl status microsoft-auth-bot"
echo "  Logs:    tail -f /var/log/microsoft_auth_bot/bot.log"
echo "  Restart: systemctl restart microsoft-auth-bot"
echo ""
echo "Next Steps:"
echo "  1. Edit /opt/microsoft_auth_bot/.env with your credentials"
echo "  2. Restart the bot: systemctl restart microsoft-auth-bot"
echo "  3. Send credentials.txt to the Telegram bot"
echo ""
SHEOF
chmod +x /opt/microsoft_auth_bot/setup.sh