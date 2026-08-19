#!/bin/bash

echo "[*] Stopping QARMRLite test cluster..."

for pidfile in node_*.pid; do
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            echo "[-] Terminated node with PID $PID"
        fi
        rm "$pidfile"
    fi
done

echo "[*] All cluster nodes stopped."
