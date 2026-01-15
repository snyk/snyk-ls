#!/bin/bash
# Trace which processes are modifying the config file
# Usage: sudo ./trace-config-file.sh [config-file-name]
# Example: sudo ./trace-config-file.sh "Visual Studio Code"

CONFIG_NAME="${1:-Visual Studio Code}"
CONFIG_FILE="$HOME/.config/snyk/ls-config-${CONFIG_NAME}"

echo "Tracing access to: $CONFIG_FILE"
echo "Press Ctrl+C to stop"
echo ""

# fs_usage filters:
# -w = wide output
# -f = filter to filesystem operations
sudo fs_usage -w -f filesys | grep --line-buffered "ls-config-${CONFIG_NAME}" | while read -r line; do
    # Extract timestamp, process name, PID, and operation
    echo "[$(date '+%H:%M:%S.%3N')] $line"
done
