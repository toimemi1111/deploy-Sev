cat > /opt/microsoft_auth_bot/stop.sh << 'STHEOF'
#!/bin/bash
echo "Stopping Microsoft Auth Bot services..."
systemctl stop microsoft-auth-bot
systemctl stop microsoft-auth-orchestrator
echo "Services stopped."
STHEOF
chmod +x /opt/microsoft_auth_bot/stop.sh