#!/bin/bash

echo "[*] Initializing QARMRLite test cluster..."

# Launch Node 1 (Port 19001)
python qarmrlite.py --port 19001 > node_19001.log 2>&1 &
echo $! > node_19001.pid
echo "[+] Node 1 launched on port 19001 (PID: $(cat node_19001.pid))"

# Launch Node 2 (Port 19002)
python qarmrlite.py --port 19002 > node_19002.log 2>&1 &
echo $! > node_19002.pid
echo "[+] Node 2 launched on port 19002 (PID: $(cat node_19002.pid))"

# Launch Node 3 (Port 19003)
python qarmrlite.py --port 19003 > node_19003.log 2>&1 &
echo $! > node_19003.pid
echo "[+] Node 3 launched on port 19003 (PID: $(cat node_19003.pid))"

echo "[*] Cluster online. Logs are writing to node_*.log"
