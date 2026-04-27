#!/bin/bash
# Real-time Interlock RAT alert monitor
# Source: lab manual §11.3 — /opt/scripts/alert_monitor.sh (Router)
#
# Tails Suricata's eve.json (the only configured log output), filters for INTERLOCK alerts,
# pretty-prints them with action ([allowed] or [blocked]), and tees a copy to
# /var/log/interlock-alerts.log for after-action review.
#
# Usage:
#   chmod +x /opt/scripts/alert_monitor.sh
#   bash /opt/scripts/alert_monitor.sh &
echo '[*] Monitoring /var/log/suricata/eve.json for INTERLOCK alerts...'
sudo tail -F /var/log/suricata/eve.json | \
  jq --unbuffered -r 'select(.event_type=="alert" and (.alert.signature | contains("INTERLOCK"))) |
    "[\(.timestamp)] [\(.alert.action // "allowed")] \(.alert.signature) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' | \
  while IFS= read -r line; do
    echo "$line" | tee -a /var/log/interlock-alerts.log
  done
