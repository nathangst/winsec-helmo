# Liste des services à désactiver
$servicesToDisable = @(
    "TermService",   # Remote Desktop Services
    "WinRM",         # Windows Remote Management
    "LanmanServer"   # Server Message Block (SMB)
)

# Désactiver les services
foreach ($serviceName in $servicesToDisable) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service -ne $null -and $service.Status -eq 'Running') {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Host "$serviceName a été désactivé."
    } elseif ($service -ne $null) {
        Write-Host "$serviceName est déjà désactivé."
    } else {
        Write-Host "$serviceName n'a pas été trouvé."
    }
}
