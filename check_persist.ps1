# Hagelin Linder
$outfile = "" # Save Info
$outfile_warning = "" # Save Warnings
$reg_run = "" # Save Set Reg Keys

Add-Content -Path $outfile -Value (Get-Date)
Add-Content -Path $outfile_warning -Value (Get-Date)
Add-Content -Path $reg_run -Value (Get-Date)

####################### Sticky keys attack #######################

# Look for: sethc.exe, utilman.exe, osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, AtBroker.exe
#reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

$stick_array = @("sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe", "AtBroker.exe")

ForEach($s in $stick_array){
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$s") {
    Write-Warning "Stickey key exists for $s"
    Add-Content $outfile_warning "Stickey key exists for $s"
    }
    else{
    Write-Host "Stickey key doesnt exist for $s" -ForegroundColor Green
    Add-Content $outfile "Stickey key doesnt exist for $s"
    }
}
####################### WDigest #######################
# Plain tex passwords
# 0X1 if enabled
# reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential

$wdigest = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest | Select-Object -ExpandProperty UseLogonCredential
# is this condition enough?
if ($wdigest -eq 1)
{
    Write-Warning "Plain text passwords enabled"
    Add-Content $outfile_warning "Plain text passwords enabled"
}
Else{
Write-Host "WDigest not enabled" -ForegroundColor Green
Add-Content $outfile "WDigest not enabled"
}

####################### Defender #######################
# Excluded path from AV scan
$ex_paths = reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
$excluded_paths = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\*"
if($excluded_paths){
    Write-Warning "Path excluded from Windows Defender"
    Write-Warning $ex_paths
    Add-Content $outfile_warning "Paths excluded from Defender: $ex_path"
}
Else{
    Write-Host "No paths excluded from Windows Defender" -ForegroundColor Green
    Add-Content $outfile "No paths excluded from Defender Scan"
}


####################### RDP #######################
# Is RDP enabled == fDenyTSConnections    REG_DWORD    0x0
# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
$rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Select-Object -ExpandProperty fDenyTSConnections
if($rdp -eq 0){
    Write-Warning "RDP is anabled"
    Add-Content $outfile_warning "RDP is enabled"
}
else{
    Write-Host "RDP is not enabled" -ForegroundColor Green
    Add-Content $outfile "RDP is not enabled"
}

# RDP Shadow session enabled?
# Viewing users session without permission
# Shouldnt exist
# If 'Shadow reg_dword 0x4' == View Session without user’s permission
# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow


 If (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow") {
    $shadow = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty Shadow
    if($shadow -eq 4){
        Write-Warning "RDP Shadow Session enabled"
        Add-Content $outfile_warning "RDP shadow session is enabled"
    }
    else{
        Write-Warning "RDP Shadow session present but not set"
        Add-Content $outfile_warning "RDP is present but not enabled. Doubble check!"
    }
    }
    else{
    Write-Host "RDP Shadow session not enabled" -ForegroundColor Green
    Add-Content $outfile "RDP Shadow session is not enabled"
    }


# Multiple RDP sessions to trick admins to interactively logon to server to get NT hashes
# Single session limit removed == 0x0
# reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser

$multi_rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Select-Object -ExpandProperty fSingleSessionPerUser
if($multi_rdp -eq 0){
    Write-Warning "Multiple RDP sessions enabled"
    Add-Content $outfile_warning "Multiple RDP sessions enabled"
}
else{
    Write-Host "Multiple RDP sessions not enabled" -ForegroundColor Green
    Add-Content $outfile "Multiple RDP sessions not enabled"
}

####################### Login without password #######################
# If allow login with blank password, LimitBlankPasswordUse    REG_DWORD    0x0
# reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse

$blank_pass = Get-ItemProperty -Path "HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty LimitBlankPasswordUse
if($blank_pass -eq 0){
    Write-Warning "Blank password for local account accepted"
    Add-Content $outfile_warning "Blank password for local account accepted"
}
else{
    Write-Host "Blank password for local account not accepted" -ForegroundColor Green
    Add-Content $outfile "Blank password for local account not accepted"
}

####################### Hide account from win login screen #######################
# Dont display the username of a user that has recently logged in
# Shouldnt exist
# reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v DefaultUser



####################### Disable UAC remote restriction #######################
# If enabled, all local users connecting remotely are granted full admin rights
# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
$remote_admin = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty LocalAccountTokenFilterPolicy
if($remote_admin -eq 1){
    Write-Warning "Local users, connecting remotely, are granted admin rights"
    Add-Content $outfile_warning "Local users, connecting remotely, are granted admin rights"
}
else{
    Write-Host "Local admin will not connect remotely as a full administrator" -ForegroundColor Green
    Add-Content $outfile "Local admin will not connect remotely as a full administrator"
}

####################### Global flags #######################
# https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
# Get-ChildItem -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

# Get-ChildItem -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'


####################### Reg Run Keys #######################
#$run = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
#$runOnce = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
#$RunServices = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" 
#$RunServicesOnce = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
#$reg_run = "C:\projAcademy\reg_run.txt"
If (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run") {
    $run = Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    if($run -ne $null){
        $string = $run | Format-Table -Wrap | Out-String
        Write-Warning "Keys present under Run!"
        Write-Warning "Please check $reg_run"
        Add-Content $reg_run "\Software\Microsoft\Windows\CurrentVersion\Run:"
        Add-Content $reg_run $string
        }
    else{
    Write-Host "Nothing under Run" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RUN"
    }
}
else{
    Write-Host "Nothing under Run" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RUN"
}

If (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce") {
    $runOnce = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    if($runOnce -ne $null){
        $string = $runOnce | Format-Table -Wrap | Out-String
        Write-Warning "Keys present under RunOnce!"
        Write-Warning "Please check $reg_run"
        Add-Content $reg_run "\Software\Microsoft\Windows\CurrentVersion\RunOnce:"
        Add-Content $reg_run $string
        }
    else{
    Write-Host "Nothing under RunOnce" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RunOnce"
    }
}
else{
    Write-Host "Nothing under Run" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RUN"
}


If (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices") {
    $RunServices = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
    if($RunServices -ne $null){
        $string = $RunServices | Format-Table -Wrap | Out-String
        Write-Warning "Keys present under RunService!"
        Write-Warning "Please check $reg_run"
        Add-Content $reg_run "\Software\Microsoft\Windows\CurrentVersion\RunService:"
        Add-Content $reg_run $string
        }
    else{
    Write-Host "Nothing under RunService" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RunService"
    }
}
else{
    Write-Host "Nothing under RunService" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RunService"
}



If (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce") {
    $RunServicesOnce = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    if($RunServicesOnce -ne $null){
        $string = $RunServicesOnce | Format-Table -Wrap | Out-String
        Write-Warning "Keys present under RunServiceOnce!"
        Write-Warning "Please check $reg_run"
        Add-Content $reg_run "\Software\Microsoft\Windows\CurrentVersion\RunServiceOnce:"
        Add-Content $reg_run $string
        }
    else{
    Write-Host "Nothing under RunServiceOnce" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RunServiceOnce"
    }
}
else{
    Write-Host "Nothing under RunServiceOnce" -ForegroundColor Green
    Add-Content $reg_run "Nothing under RunServiceOnce"
}



####################### scheduled tasks #######################

####################### startup folders #######################

####################### Reg Run Keys #######################


####################### No logs to Security event logs #######################
# https://twitter.com/0gtweet/status/1182516740955226112
# reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNt”

If (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt") {
    Write-Warning "Logs to Security Log DISABLED by MiniNT key"
    Add-Content $outfile_warning "Logs to Security Log DISABLED with MiniNT key"
    }
else{
    Write-Host "MiniNT key not present" -ForegroundColor Green
    Add-Content $outfile "MiniNT key not present"
}
