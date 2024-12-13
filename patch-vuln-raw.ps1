# Variables de chemin pour l'accès au registre
$PoliciesKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$LsaKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$WinlogonKey = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$KerberosKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"


# Fonction pour définir une clé de registre
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [string]$Value
    )
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}


# Enforce password history
Write-Output "Configuring password history..."
net accounts /uniquepw:24


# Minimum password length
Write-Output "Setting minimum password length..."
net accounts /minpwlen:14


# Password must meet complexity requirements
Write-Output "Enabling password complexity requirements..."
(Get-WmiObject -Class Win32_UserAccount).PasswordRequired = $true


# Relax minimum password length limits
Write-Output "Relaxing minimum password length limits..."
Set-RegistryValue -Path $LsaKey -Name "RelaxMinimumPasswordLengthLimits" -Type "DWORD" -Value 1


# Account lockout threshold
Write-Output "Configuring account lockout threshold..."
net accounts /lockoutthreshold:5


# Block Microsoft accounts
Write-Output "Blocking Microsoft accounts..."
Set-RegistryValue -Path $PoliciesKey -Name "NoConnectedUser" -Type "DWORD" -Value 3


# Rename administrator account
Write-Output "Renaming administrator account..."
Rename-LocalUser -Name "Administrator" -NewName "AdminSecure"


# Rename guest account
Write-Output "Renaming guest account..."
Rename-LocalUser -Name "Guest" -NewName "VisitorSecure"


# Devices: Allowed to format and eject removable media
Write-Output "Configuring device settings for removable media..."
Set-RegistryValue -Path $WinlogonKey -Name "AllocateDASD" -Type "DWORD" -Value 2


# Prevent users from installing printer drivers
Write-Output "Preventing users from installing printer drivers..."
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name
"AddPrinterDrivers" -Type "DWORD" -Value 0


# Maximum machine account password age
Write-Output "Setting machine account password age..."
net accounts /maxpwage:30


# Interactive logon: Do not require CTRL+ALT+DEL
Write-Output "Disabling 'Do not require CTRL+ALT+DEL'..."
Set-RegistryValue -Path $PoliciesKey -Name "DisableCAD" -Type "DWORD" -Value 0


# Interactive logon: Don't display last signed-in
Write-Output "Enabling 'Don't display last signed-in'..."
Set-RegistryValue -Path $PoliciesKey -Name "DontDisplayLastUserName" -Type "DWORD" -Value 1


# Machine inactivity limit
Write-Output "Configuring machine inactivity limit..."
Set-RegistryValue -Path $PoliciesKey -Name "InactivityTimeoutSecs" -Type "DWORD" -Value 900


# Legal notice
Write-Output "Setting legal notice..."
Set-RegistryValue -Path $PoliciesKey -Name "LegalNoticeText" -Type "String" -Value "Unauthorized access is prohibited."
Set-RegistryValue -Path $PoliciesKey -Name "LegalNoticeCaption" -Type "String" -Value "Security Notice"


# Smart card removal behavior
Write-Output "Configuring smart card removal behavior..."
Set-RegistryValue -Path $WinlogonKey -Name "ScRemoveOption" -Type "String" -Value "1"


# Microsoft network client/server settings
Write-Output "Configuring Microsoft network client/server settings..."
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name
"RequireSecuritySignature" -Type "DWORD" -Value 1
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature"
-Type "DWORD" -Value 1
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature"
-Type "DWORD" -Value 1


# Network security configurations
Write-Output "Configuring network security settings..."
Set-RegistryValue -Path $LsaKey -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1
Set-RegistryValue -Path $LsaKey -Name "NoLMHash" -Type "DWORD" -Value 1
Set-RegistryValue -Path $LsaKey -Name "LmCompatibilityLevel" -Type "DWORD" -Value 5
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Type "DWORD" -Value
0x20080000
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Type "DWORD" -Value
0x20080000


# User Account Control settings
Write-Output "Configuring UAC settings..."
Set-RegistryValue -Path $PoliciesKey -Name "EnableLUA" -Type "DWORD" -Value 1
Set-RegistryValue -Path $PoliciesKey -Name "ConsentPromptBehaviorAdmin" -Type "DWORD" -Value 2
Set-RegistryValue -Path $PoliciesKey -Name "PromptOnSecureDesktop" -Type "DWORD" -Value 1


Write-Output "All configurations applied successfully!"
