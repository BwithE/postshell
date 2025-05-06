```
██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝██║   ██║███████╗   ██║   ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██║   ██║╚════██║   ██║   ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ╚██████╔╝███████║   ██║   ███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```
Execute commands on clients using GET/POST requests. (Bypass Firewalls for initial access)

# Disclaimer
This is not meant to be used for illegal purposes. Use at your own discretion.

# Usage
1. To start the server
```
python3 server.py <port>
```

2. Modify, then transfer a client.<script> to connect to the SERVER
  - Change IP, PORT, and CHECKIN time

3. Execute the script on the client
```
bash client.sh

python3 client.py

powershell -ep bypass client.ps1
```

4. View the Clients from the webpage

<img width="1409" alt="Screenshot 2025-05-04 at 8 50 21 PM" src="https://github.com/user-attachments/assets/965f1c5b-4d10-4d2a-949e-5d8546c8af58" />

5. Execute commands, and wait for the client to GET the command, then POST the results
  - `server.py` can be modified to allow more than 2 commands to be kept in the webpage history

<img width="580" alt="Screenshot 2025-05-04 at 8 50 47 PM" src="https://github.com/user-attachments/assets/bb562d5f-2f77-41aa-ba09-85a955eddbf2" />

6. Each session will create a command history file.

<img width="368" alt="Screenshot 2025-05-04 at 8 51 18 PM" src="https://github.com/user-attachments/assets/023d9b5b-8f5b-4506-bb6d-cdc8ca0d9b43" />
