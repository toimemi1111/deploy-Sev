cat > /opt/microsoft_auth_bot/status.sh << 'STHEOF'
#!/bin/bash
echo "=== Microsoft Auth Bot Service Status ==="
echo ""
echo "--- Bot ---"
systemctl status microsoft-auth-bot --no-pager
echo ""
echo "--- Orchestrator ---"
systemctl status microsoft-auth-orchestrator --no-pager
echo ""
echo "=== Recent Logs ==="
tail -20 /var/log/microsoft_auth_bot/bot.log 2>/dev/null || echo "No bot logs yet"
tail -20 /var/log/microsoft_auth_bot/orchestrator.log 2>/dev/null || echo "No orchestrator logs yet"
STHEOF
chmod +x /opt/microsoft_auth_bot/status.sh