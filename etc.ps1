<#
Because some things can only be used in freakin powershell, I'm making this.
I'm really bad at this
#>

if (!(Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search')) 
{     
    Write-Verbose -Message "apparently there is no registry key yet"
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'Windows Search' -Force | Out-Null
}

Write-Verbose -Message "Setting AllowCortana to 0"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Value 0 -PropertyType DWORD -Force | Out-Null

Write-Verbose -Message "Disabling all firewall rules related to Cortana"
Get-NetFirewallRule -DisplayGroup 'Cortana' | Disable-NetFirewallRule 
Get-NetFirewallRule | where {$_.DisplayGroup -like '*Microsoft*Windows*Cortana*'} | Disable-NetFirewallRule


# I hope there is only one Cortana folder in the future.

$cortanaDir = @(dir $env:windir\SystemApps\Microsoft.Windows.Cortana_*)
if ($cortanaDir.Count -ne 1)
{ 
    Write-Error -Message "idk dude something happened, delete it yourself"
    #else block below will not fail if not included
    $cortanaDir = $null
} 
else
{ $cortanaDir = $cortanaDir[0].FullName } 


# fetch executables in cortana folder
$cortanaEXEs = @(dir -Path $cortanaDir -Filter *.exe -Recurse -File -ErrorAction SilentlyContinue)


# Create outbound blocking rule for each EXE found:
if ($cortanaEXEs -eq $null -or $cortanaEXEs.Count -eq 0)
{ 
    Write-Error -Message "no exes???"
}
else
{
    ForEach ($EXE in $cortanaEXEs) 
    { 
        # Note: Do not edit the name or description text for the rules, they are used for deletions.
        # Note: The -RemoteAddress is "Internet" in case a future local intranet/subnet Cortana feature is desired later.
        $name = "pwned Cortana " + $EXE.Name
        New-NetFirewallRule -Direction Outbound -Action Block -RemoteAddress Internet -Enabled True -PolicyStore PersistentStore -Name $name -DisplayName $name -Description 'Block outbound Cortana traffic, courtesy of scripts' -Program $EXE.FullName | Out-Null
    }
}