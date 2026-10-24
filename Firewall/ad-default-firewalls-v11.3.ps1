#requires -Version 5.1
<#
.SYNOPSIS
  Configure scoped local firewall rules for a CCDC Active Directory domain controller.
.EXAMPLE
  .\ad-default-firewalls.ps1 -ClientNetworks 10.20.0.0/16 -Preview
.EXAMPLE
  .\ad-default-firewalls.ps1 -ClientNetworks 10.20.0.0/16 -PeerDCAddresses 10.30.0.10,10.30.0.11
.EXAMPLE
  .\ad-default-firewalls.ps1 -ClientNetworks 10.20.0.0/16 -ManagementHosts 10.20.1.5 -IncludeLDAPS -IncludeGlobalCatalog -IncludeADWS -IncludeWinRMHTTPS
.EXAMPLE
  .\ad-default-firewalls.ps1 -ClientNetworks 10.20.0.0/16 -ManagementHosts 10.20.1.5 -IncludeWinRM -DisableNonScriptInboundAllowRules -Preview
.EXAMPLE
  .\ad-default-firewalls.ps1 -ClientNetworks 10.20.0.0/16 -ManagementHosts 10.20.1.5 -IncludeWinRM -DisableNonScriptInboundAllowRules -ConfirmCleanup
.NOTES
  Rollback (elevated console): netsh advfirewall import "C:\path\firewall-TIMESTAMP.wfw"
  Import restores local policy; Group Policy can reapply afterward. Test RPC, DNS,
  Group Policy, DC replication, and remote access. Firewall settings alone cannot
  guarantee AD functionality. ProgramData obscurity is not security; protect backups.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()][ValidateNotNullOrEmpty()]
    [string]$BackupDirectory = 'C:\ProgramData\CCDC\FirewallBackups',
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
    [string[]]$ClientNetworks,
    [Parameter()][string[]]$PeerDCAddresses,
    [Parameter()][string[]]$ManagementHosts,
    [Parameter()][switch]$IncludeLDAPS,
    [Parameter()][switch]$IncludeGlobalCatalog,
    [Parameter()][switch]$IncludeSecureGlobalCatalog,
    [Parameter()][switch]$IncludeADWS,
    [Parameter()][switch]$IncludeLegacyNetBIOS,
    [Parameter()][switch]$IncludeICMP,
    [Parameter()][switch]$IncludeWinRM,
    [Parameter()][switch]$IncludeWinRMHTTPS,
    [Parameter()][switch]$IncludeRDP,
    [Parameter()][switch]$ExcludeNTP,
    [Parameter()][Alias('DisableOtherRules', 'Cleanup')]
    [switch]$DisableNonScriptInboundAllowRules,
    [Parameter()][switch]$ConfirmCleanup,
    [Parameter()][switch]$Preview
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Administrator privileges are required. Relaunching with elevation...' -ForegroundColor Yellow
    $elevatedArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',("`"{0}`"" -f $PSCommandPath))
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Value -is [switch]) {
            if ($entry.Value.IsPresent) { $elevatedArgs += "-$($entry.Key)" }
        } elseif ($entry.Value -is [array]) {
            $elevatedArgs += "-$($entry.Key)"
            foreach ($value in $entry.Value) { $elevatedArgs += ("`"{0}`"" -f $value) }
        } else {
            $elevatedArgs += "-$($entry.Key)"
            $elevatedArgs += ("`"{0}`"" -f $entry.Value)
        }
    }
    $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $elevatedArgs -Wait -PassThru
    exit $child.ExitCode
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dryRun = [bool]($Preview -or $WhatIfPreference)
$backup = $null
$ruleGroup = 'CCDC AD Firewall'

function Write-Stage([int]$Number, [string]$Text) {
    Write-Host ("`n[{0}/4] {1}" -f $Number, $Text) -ForegroundColor Cyan
}

function Assert-Addresses([string[]]$Values, [string]$Label) {
    foreach ($value in $Values) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw "$Label contains an empty address." }
        $parts = $value.Split('/')
        if ($parts.Count -gt 2) { throw "Invalid $Label address: $value" }
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
            throw "$Label requires literal IP addresses or CIDR subnets: $value"
        }
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $parts[0] -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
            throw "$Label requires dotted-decimal IPv4 addresses: $value"
        }
        if ($parts.Count -eq 2) {
            $prefix = 0
            $limit = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 1 -or $prefix -gt $limit) {
                throw "Invalid or unrestricted $Label CIDR prefix: $value"
            }
        } elseif ($ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any)) {
            throw "$Label cannot contain an unspecified address: $value"
        }
    }
}

function New-Spec([string]$Suffix, [string]$Protocol, [string]$Port, [string[]]$Sources) {
    [pscustomobject]@{
        Name = "CCDC-AD-DC-In-$Suffix"
        DisplayName = "CCDC AD DC inbound $Suffix"
        Protocol = $Protocol
        LocalPort = $Port
        Sources = @($Sources)
    }
}

function Get-ExactRule([string]$Name, [string]$Store) {
    # Query the indexed rule name directly instead of enumerating the entire
    # policy store for every managed rule.
    return ,@(Get-NetFirewallRule -PolicyStore $Store -Name $Name -ErrorAction SilentlyContinue)
}

function ConvertTo-CanonicalAddressScope([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($Value -eq 'Any') { return 'Any' }

    $parts = $Value.Split('/')
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $Value.ToLowerInvariant() }
    if ($parts.Count -eq 1) { return $ip.ToString() }

    $prefix = $null
    if ([int]::TryParse($parts[1], [ref]$prefix)) {
        $limit = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ($prefix -lt 0 -or $prefix -gt $limit) { return $Value.ToLowerInvariant() }
    } else {
        $mask = $null
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            -not [Net.IPAddress]::TryParse($parts[1], [ref]$mask) -or
            $mask.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            return $Value.ToLowerInvariant()
        }
        $prefix = 0
        $seenZero = $false
        foreach ($byte in $mask.GetAddressBytes()) {
            for ($bit = 7; $bit -ge 0; $bit--) {
                if (($byte -band (1 -shl $bit)) -ne 0) {
                    if ($seenZero) { return $Value.ToLowerInvariant() }
                    $prefix++
                } else { $seenZero = $true }
            }
        }
    }

    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $ip.GetAddressBytes()
        $remaining = $prefix
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bits = [Math]::Max(0, [Math]::Min(8, $remaining))
            # Do not use an inline if-expression: Windows PowerShell 5.1
            # parses that differently from PowerShell 7.
            $networkMask = 0
            if ($bits -ne 0) {
                $networkMask = (0xFF -shl (8 - $bits)) -band 0xFF
            }
            $bytes[$i] = [byte]($bytes[$i] -band $networkMask)
            $remaining -= $bits
        }
        $ip = New-Object Net.IPAddress(,$bytes)
    }
    return "$($ip.ToString())/$prefix"
}

function Get-CanonicalAddressSet([object]$Addresses) {
    return @($Addresses | ForEach-Object { ConvertTo-CanonicalAddressScope ([string]$_) } |
        Sort-Object -Unique)
}

function Test-Configuration($Rule, $Spec) {
    if ($null -eq $Rule -or $Rule.Name -cne $Spec.Name -or $Rule.Group -cne $ruleGroup -or
        $Rule.Direction -ne 'Inbound' -or
        $Rule.Action -ne 'Allow' -or [string]$Rule.Enabled -ne 'True' -or
        [string]$Rule.Profile -ne 'Any') { return $false }
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $actualRemote = Get-CanonicalAddressSet $address.RemoteAddress
    $expectedRemote = Get-CanonicalAddressSet $Spec.Sources
    $actualLocal = Get-CanonicalAddressSet $address.LocalAddress
    # Verify only properties intentionally set by this script. Windows may
    # expose omitted application/service filters differently in ActiveStore.
    if ([string]$port.Protocol -ine $Spec.Protocol -or
        (@($actualRemote) -join ',') -ne (@($expectedRemote) -join ',') -or
        (@($actualLocal) -join ',') -ne 'Any' -or
        (@($port.RemotePort) -join ',') -ne 'Any') { return $false }
    if ($Spec.Protocol -ieq 'ICMPv4') { return (@($port.IcmpType) -join ',') -eq '8' }
    return (@($port.LocalPort) -join ',') -eq $Spec.LocalPort
}

function Assert-EffectiveRule($Spec) {
    $found = Get-ExactRule $Spec.Name 'ActiveStore'
    if ($found.Count -ne 1 -or -not (Test-Configuration $found[0] $Spec)) {
        throw "Rule $($Spec.Name) is not effective as configured. Check Group Policy merging and blocking rules."
    }
}

function Get-ReportSortKey([string]$LocalPort) {
    $match = [regex]::Match($LocalPort, '\d+')
    if ($match.Success) { return [int]$match.Value }
    return [int]::MaxValue
}

function Format-RuleName([string]$Name) {
    if ($Name.Length -le 15) { return $Name }
    return $Name.Substring(0, 12) + '...'
}

function Write-FirewallReport([string]$Path, [object[]]$Rules) {
    $rows = @($Rules | Sort-Object SortKey, Name, Protocol)
    $localMaximum = [int]@($rows | ForEach-Object { ([string]$_.LocalAddress).Length } | Measure-Object -Maximum).Maximum
    $remoteMaximum = [int]@($rows | ForEach-Object { ([string]$_.RemoteAddress).Length } | Measure-Object -Maximum).Maximum
    $localWidth = [Math]::Max(15, $localMaximum)
    $remoteWidth = [Math]::Max(15, $remoteMaximum)
    $format = "{0,-15}  {1,-9}  {2,-12}  {3,-13}  {4,-$localWidth}  {5}"
    $header = $format -f 'Rule Name','Protocol','Local Port','Remote Port','Local Address','Remote Address'
    $headerLength = [int]$header.Length
    $separator = ''.PadLeft($headerLength, '-')
    $title = ' FIREWALL RULES '
    $title = $title.PadLeft([int](($headerLength + $title.Length) / 2)).PadRight($headerLength)
    $lines = @('',(''.PadLeft($headerLength, '=')),$title,'',$header,$separator)
    foreach ($row in $rows) {
        $lines += ($format -f (Format-RuleName $row.Name),$row.Protocol,$row.LocalPort,$row.RemotePort,$row.LocalAddress,$row.RemoteAddress)
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Get-EnabledRuleSummary {
    foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop) {
        $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $localPort = if ([string]$port.Protocol -eq 'ICMPv4') {
            'type:' + (@($port.IcmpType) -join ',')
        } else {
            @($port.LocalPort) -join ','
        }
        [pscustomobject]@{
            Name = [string]$rule.Name
            Protocol = [string]$port.Protocol
            LocalPort = $localPort
            RemotePort = @($port.RemotePort) -join ','
            LocalAddress = @($address.LocalAddress) -join ','
            RemoteAddress = @($address.RemoteAddress) -join ','
            SortKey = Get-ReportSortKey $localPort
            ProtocolPorts = "$($port.Protocol)/local:$localPort/remote:$(@($port.RemotePort) -join ',')"
            LocalScope = @($address.LocalAddress) -join ','
            RemoteScope = @($address.RemoteAddress) -join ','
        }
    }
}

function Save-FirewallBackup([string]$Directory, [object[]]$Summary) {
    New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $exportPath = Join-Path $Directory "firewall-$stamp-$tag.wfw"
    $reportPath = Join-Path $Directory "enabled-rules-$stamp-$tag.txt"
    & netsh.exe advfirewall export $exportPath | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exportPath) -or
        (Get-Item -LiteralPath $exportPath).Length -le 0) {
        throw "Firewall export failed; no firewall changes were made. Check $exportPath"
    }
    Write-FirewallReport $reportPath $Summary
    if ((Get-Item -LiteralPath $reportPath).Length -le 0) { throw "Rule report failed: $reportPath" }
    [pscustomobject]@{ Export = $exportPath; Report = $reportPath }
}

function Ensure-Rule($Spec) {
    $existing = Get-ExactRule $Spec.Name 'PersistentStore'
    if ($existing.Count -gt 0) {
        if ($dryRun) {
            Write-Host "Would remove and recreate existing rule: $($Spec.Name)" -ForegroundColor Yellow
        } elseif (-not $PSCmdlet.ShouldProcess($Spec.Name, 'Remove existing rule before recreation')) {
            return
        } else {
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $Spec.Name -Confirm:$false -ErrorAction Stop
        }
    }
    if ($dryRun) {
        Write-Host "Would create $($Spec.Name) $($Spec.Protocol)/$($Spec.LocalPort) from $(@($Spec.Sources) -join ',')" -ForegroundColor Yellow
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Spec.Name, 'Create scoped inbound Allow rule')) { return }

    # Set-NetFirewallRule supports protocol, ports, ICMP type, and address scope in its
    # ByName parameter set; do not combine filter InputObject parameter sets here.
    $settings = @{
        PolicyStore = 'PersistentStore'; Name = $Spec.Name; Enabled = 'True';
        Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any';
        Protocol = $Spec.Protocol; LocalAddress = 'Any'; RemoteAddress = $Spec.Sources;
        Program = 'Any'; Service = 'Any'; Confirm = $false; ErrorAction = 'Stop'
    }
    if ($Spec.Protocol -eq 'ICMPv4') { $settings.IcmpType = '8' }
    else { $settings.LocalPort = $Spec.LocalPort; $settings.RemotePort = 'Any' }
    $settings.DisplayName = $Spec.DisplayName
    $settings.Group = $ruleGroup
    New-NetFirewallRule @settings | Out-Null
    Write-Verbose "Rule created or updated without post-write verification: $($Spec.Name)"
}

try {
    Assert-Addresses $ClientNetworks 'ClientNetworks'
    if ($PeerDCAddresses) { Assert-Addresses $PeerDCAddresses 'PeerDCAddresses' }
    if ($ManagementHosts) { Assert-Addresses $ManagementHosts 'ManagementHosts' }
    if (($IncludeADWS -or $IncludeWinRM -or $IncludeWinRMHTTPS -or $IncludeRDP) -and -not $ManagementHosts) {
        throw 'Management switches require -ManagementHosts with IP addresses or CIDR subnets.'
    }
    if ($DisableNonScriptInboundAllowRules -and -not $dryRun -and -not $ConfirmCleanup) {
        throw 'Cleanup requires -ConfirmCleanup. Review -Preview output first.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run from an elevated Windows PowerShell 5.1 session.'
    }

    $clientScope = @($ClientNetworks + $PeerDCAddresses | Select-Object -Unique)
    $managementScope = @($ManagementHosts | Select-Object -Unique)
    $specs = @(
        New-Spec 'TCP-53' 'TCP' '53' $clientScope
        New-Spec 'UDP-53' 'UDP' '53' $clientScope
        New-Spec 'TCP-88' 'TCP' '88' $clientScope
        New-Spec 'UDP-88' 'UDP' '88' $clientScope
        New-Spec 'TCP-135' 'TCP' '135' $clientScope
        New-Spec 'TCP-389' 'TCP' '389' $clientScope
        New-Spec 'UDP-389' 'UDP' '389' $clientScope
        New-Spec 'TCP-445' 'TCP' '445' $clientScope
        New-Spec 'TCP-464' 'TCP' '464' $clientScope
        New-Spec 'UDP-464' 'UDP' '464' $clientScope
        New-Spec 'TCP-RPC-Dynamic' 'TCP' '49152-65535' $clientScope
    )
    if (-not $ExcludeNTP) { $specs += New-Spec 'UDP-123' 'UDP' '123' $clientScope }
    if ($IncludeLDAPS) { $specs += New-Spec 'TCP-636' 'TCP' '636' $clientScope }
    if ($IncludeGlobalCatalog) { $specs += New-Spec 'TCP-3268' 'TCP' '3268' $clientScope }
    if ($IncludeSecureGlobalCatalog) { $specs += New-Spec 'TCP-3269' 'TCP' '3269' $clientScope }
    if ($IncludeLegacyNetBIOS) {
        $specs += New-Spec 'UDP-137-138' 'UDP' '137-138' $clientScope
        $specs += New-Spec 'TCP-139' 'TCP' '139' $clientScope
    }
    if ($IncludeICMP) { $specs += New-Spec 'ICMPv4-Echo' 'ICMPv4' '8' $clientScope }
    if ($IncludeADWS) { $specs += New-Spec 'TCP-9389' 'TCP' '9389' $managementScope }
    if ($IncludeWinRM) { $specs += New-Spec 'TCP-5985' 'TCP' '5985' $managementScope }
    if ($IncludeWinRMHTTPS) { $specs += New-Spec 'TCP-5986' 'TCP' '5986' $managementScope }
    if ($IncludeRDP) { $specs += New-Spec 'TCP-3389' 'TCP' '3389' $managementScope }

    Write-Stage 1 'Back up original policy and report enabled effective rules'
    $summary = @(Get-EnabledRuleSummary)
    if ($dryRun) {
        Write-Host "Would export .wfw and write timestamped .txt report in $BackupDirectory" -ForegroundColor Yellow
    } else {
        Write-Host "Creating backup folder and firewall backup in: $BackupDirectory" -ForegroundColor Gray
        $backup = Save-FirewallBackup $BackupDirectory $summary
        if (-not $backup -or -not (Test-Path -LiteralPath $backup.Export) -or
            -not (Test-Path -LiteralPath $backup.Report)) {
            throw 'Step 1 backup did not produce both required files. No firewall changes were made.'
        }
        Write-Host "Backup: $($backup.Export)" -ForegroundColor Green
        Write-Host "Report: $($backup.Report)" -ForegroundColor Green
    }
    $summary | Format-Table -AutoSize Name, ProtocolPorts, LocalScope, RemoteScope

    Write-Stage 2 'Create scoped AD inbound rules'
    $ruleNumber = 0
    foreach ($spec in $specs) {
        $ruleNumber++
        Write-Host ("Ensuring rule {0}/{1}: {2}" -f $ruleNumber, $specs.Count, $spec.Name) -ForegroundColor Gray
        Ensure-Rule $spec
    }
    Write-Stage 3 'Enable all profiles and set default inbound Block'
    if ($dryRun) {
        Write-Host 'Would enable Domain, Private, Public and set default inbound Block.' -ForegroundColor Yellow
    } else {
        Write-Warning 'Rule verification is disabled in v5. Confirm effective policy manually after applying.'
        foreach ($name in @('Domain', 'Private', 'Public')) {
            if ($PSCmdlet.ShouldProcess($name, 'Enable firewall and set default inbound Block')) {
                Set-NetFirewallProfile -PolicyStore PersistentStore -Name $name -Enabled True -DefaultInboundAction Block -Confirm:$false -ErrorAction Stop
            }
        }
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $profile = Get-NetFirewallProfile -PolicyStore ActiveStore -Name $name -ErrorAction Stop
            if ([string]$profile.Enabled -ne 'True' -or [string]$profile.DefaultInboundAction -ne 'Block') {
                throw "Effective $name profile is not enabled with inbound Block. Check Group Policy."
            }
            if ([string]$profile.AllowInboundRules -eq 'False' -or
                [string]$profile.AllowLocalFirewallRules -eq 'False') {
                throw "Effective $name profile ignores local inbound Allow rules. Check Group Policy before proceeding."
            }
            if ([string]$profile.DefaultOutboundAction -ne 'Allow') {
                Write-Warning "$name effective default outbound policy is not Allow; this script did not change it."
            }
        }
    }

    Write-Stage 4 'Optionally disable other enabled local inbound Allow rules'
    if ($DisableNonScriptInboundAllowRules) {
        Write-Warning 'Cleanup can disrupt other services and remote administration. Review targets and retain console access.'
        $candidates = @(
            Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
                Where-Object {
                    # Rules in the script-owned group are preserved. All other
                    # enabled local inbound Allow rules are cleanup targets.
                    return ($_.Group -cne $ruleGroup)
                }
        )
        if ($candidates.Count -eq 0) {
            Write-Host 'No other enabled local inbound Allow rules found.'
        } else {
            Write-Host 'Exact local rules targeted for disabling:' -ForegroundColor Yellow
            $duplicateTargets = @($candidates | Group-Object -Property Name | Where-Object { $_.Count -gt 1 })
            if ($duplicateTargets.Count -gt 0) { throw 'Duplicate local rule names found in cleanup targets; refusing ambiguous changes.' }
            foreach ($rule in $candidates) {
                Write-Host ("Name={0}; DisplayName={1}; Direction={2}; Action={3}; Enabled={4}" -f
                    $rule.Name, $rule.DisplayName, $rule.Direction, $rule.Action, $rule.Enabled)
            }
            if (-not $dryRun) {
                if ($PSCmdlet.ShouldProcess(("{0} rule(s)" -f $candidates.Count), 'Disable local inbound Allow rules')) {
                    # Disable the collected rules in one operation instead of
                    # starting a separate firewall operation for every rule.
                    $candidates | Set-NetFirewallRule -Enabled False -Confirm:$false -ErrorAction Stop
                    Write-Host "Disabled $($candidates.Count) local inbound Allow rule(s)." -ForegroundColor Green
                }
            }
        }
    } else {
        Write-Host 'Cleanup was not selected.'
        Write-Warning 'Other existing inbound Allow rules may still permit these ports from broader networks. Review the saved rule report.'
    }

    if ($backup) { Write-Host "Rollback (elevated): netsh advfirewall import `"$($backup.Export)`"" -ForegroundColor Magenta }
    Write-Host 'Test RPC, DNS, Group Policy, DC replication and remote access from intended sources; firewall changes alone cannot guarantee AD functionality.'
    Write-Host 'ProgramData obscurity is not security. Protect and copy the backup.'
} catch {
    Write-Warning "Firewall configuration stopped: $($_.Exception.Message)"
    if ($backup) { Write-Host "Rollback (elevated): netsh advfirewall import `"$($backup.Export)`"" -ForegroundColor Magenta }
    throw
}
