#!/usr/bin/env bash

DIR="/home/arika/src"
PID=$$

echo "Recursive scanner started with PID: $PID"

while true; do
  echo "--- [PID: $PID] Scan at $(date +'%T') ---"
  
  while IFS= read -r -d '' FILE; do
    HASH=$(dd if="$FILE" bs=512 count=1 2>/dev/null | md5sum | awk '{print $1}')
    echo "[PID: $PID] Opened: $FILE | MD5 (512B): $HASH"
    sleep 1
  done < <(find "$DIR" -type f -print0)

  sleep 1
done
