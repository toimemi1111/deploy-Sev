cat > /opt/microsoft_auth_bot/start.sh << 'STHEOF'
#!/bin/bash
echo "Starting Microsoft Auth Bot services..."
systemctl start microsoft-auth-bot
systemctl start microsoft-auth-orchestrator
echo "Services started. Check status with: systemctl status microsoft-auth-bot"
STHEOF
chmod +x /opt/microsoft_auth_bot/start.sh
