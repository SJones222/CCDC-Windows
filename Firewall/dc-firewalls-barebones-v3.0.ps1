#requires -Version 5.1
<##
.SYNOPSIS
  Barebones scoped firewall policy for a CCDC Active Directory domain controller.

.DESCRIPTION
  With no parameters, detects the primary IPv4 subnet, creates the barebones
  AD rules, verifies them, and disables other enabled local inbound rules.
  -ClientNetworks optionally replaces the detected subnet with explicit IPv4
  addresses or scopes. -Modify updates only enabled local barebones rules and
  requires an explicit -ClientNetworks value.
#>
[CmdletBinding()]
param(
    [string[]]$ClientNetworks,
    [switch]$Modify
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Administrator privileges are required. Relaunching with elevation...' -ForegroundColor Yellow
    $elevatedArguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',("`"{0}`"" -f $PSCommandPath))
    foreach ($network in @($ClientNetworks)) { $elevatedArguments += @('-ClientNetworks', ("`"{0}`"" -f $network)) }
    if ($Modify) { $elevatedArguments += '-Modify' }
    $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $elevatedArguments -Wait -PassThru
    exit $child.ExitCode
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPrefix = 'CCDC-DC-Barebones-'
$ruleGroup = 'CCDC DC Barebones'
$dryRun = $false
$backupDirectory = 'C:\CCDC\FirewallBackups'
$beforeBackup = $null

function Write-Step([int]$Number, [string]$Text) {
    Write-Host ("`n[{0}/9] {1}" -f $Number, $Text) -ForegroundColor Cyan
}

function ConvertTo-IPv4Bytes([string]$Address) {
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Invalid IPv4 address: $Address"
    }
    return $ip.GetAddressBytes()
}

function ConvertTo-PrefixLength([string]$Mask) {
    $bytes = ConvertTo-IPv4Bytes $Mask
    $prefix = 0
    $seenZero = $false
    foreach ($byte in $bytes) {
        for ($bit = 7; $bit -ge 0; $bit--) {
            if (($byte -band (1 -shl $bit)) -ne 0) {
                if ($seenZero) { throw "Non-contiguous IPv4 netmask: $Mask" }
                $prefix++
            } else { $seenZero = $true }
        }
    }
    return $prefix
}

function ConvertTo-NetworkCidr([string]$Address, [int]$PrefixLength) {
    $bytes = ConvertTo-IPv4Bytes $Address
    if ($PrefixLength -lt 1 -or $PrefixLength -gt 32) {
        throw "IPv4 prefix must be between /1 and /32: /$PrefixLength"
    }
    $remaining = $PrefixLength
    for ($i = 0; $i -lt 4; $i++) {
        $bits = [Math]::Max(0, [Math]::Min(8, $remaining))
        $mask = 0
        if ($bits -ne 0) { $mask = (0xFF -shl (8 - $bits)) -band 0xFF }
        $bytes[$i] = [byte]($bytes[$i] -band $mask)
        $remaining -= $bits
    }
    return "{0}.{1}.{2}.{3}/{4}" -f $bytes[0],$bytes[1],$bytes[2],$bytes[3],$PrefixLength
}

function ConvertTo-CanonicalScope([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($Value -eq 'Any') { return 'Any' }
    $parts = $Value.Split('/')
    $bytes = ConvertTo-IPv4Bytes $parts[0]
    if ($parts.Count -eq 1) { return ("{0}.{1}.{2}.{3}" -f $bytes[0],$bytes[1],$bytes[2],$bytes[3]) }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { $prefix = ConvertTo-PrefixLength $parts[1] }
    return ConvertTo-NetworkCidr $parts[0] $prefix
}

function Get-CanonicalSet([object]$Values) {
    return @($Values | ForEach-Object { ConvertTo-CanonicalScope ([string]$_) } | Sort-Object -Unique)
}

function Resolve-Subnet {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($routes.Count -eq 0) { throw 'No active IPv4 default route was found.' }
    $bestMetric = "{0}:{1}" -f $routes[0].RouteMetric, $routes[0].InterfaceMetric
    $best = @($routes | Where-Object { ("{0}:{1}" -f $_.RouteMetric,$_.InterfaceMetric) -eq $bestMetric })
    $interfaces = @($best | Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($interfaces.Count -ne 1) { throw 'Primary IPv4 adapter is ambiguous; cannot continue safely.' }
    $config = Get-NetIPConfiguration -InterfaceIndex $interfaces[0] -ErrorAction Stop
    $ipv4 = @($config.IPv4Address)
    if ($ipv4.Count -ne 1) { throw 'Primary adapter does not have exactly one IPv4 address.' }
    return ConvertTo-NetworkCidr $ipv4[0].IPv4Address ([int]$ipv4[0].PrefixLength)
}

function Assert-IPv4Scopes([string[]]$Values, [string]$Label) {
    foreach ($value in $Values) {
        foreach ($entry in ([string]$value -split '[,;]')) {
            $scope = $entry.Trim()
            if ([string]::IsNullOrWhiteSpace($scope)) { continue }
            $canonical = ConvertTo-CanonicalScope $scope
            if ($canonical -eq '0.0.0.0/0') { throw "$Label cannot contain /0." }
        }
    }
}

function ConvertTo-FirewallIPv4Scope([string[]]$Values) {
    $scopes = @()
    foreach ($value in $Values) {
        foreach ($entry in ([string]$value -split '[,;]')) {
            $scope = $entry.Trim()
            if ([string]::IsNullOrWhiteSpace($scope)) { continue }
            $canonical = ConvertTo-CanonicalScope $scope
            if ($canonical -eq '0.0.0.0/0') { throw 'ClientNetworks cannot contain /0.' }
            $scopes += [string]$canonical
        }
    }
    $scopes = @($scopes | Sort-Object -Unique)
    if ($scopes.Count -eq 0) { throw 'ClientNetworks must contain at least one IPv4 address or scope.' }
    return ,([string[]]$scopes)
}

function Get-ReportSortKey([string]$LocalPort) {
    if ($LocalPort -notmatch '^\d') { return [int]::MaxValue }
    $matches = [regex]::Matches($LocalPort, '\d+')
    if ($matches.Count -gt 0) {
        $lowest = [int]::MaxValue
        foreach ($match in $matches) {
            $number = [int]$match.Value
            if ($number -lt $lowest) { $lowest = $number }
        }
        return $lowest
    }
    return [int]::MaxValue
}

function Format-RuleName([string]$Name) {
    if ($Name.Length -le 30) { return $Name }
    return $Name.Substring(0, 27) + '...'
}

function Format-Source([object]$SourceType) {
    # The report row retains the original PolicyStoreSourceType value.
    # Only the text output translates it for the reader.
    switch ([string]$SourceType) {
        'Local' { return 'Local' }
        'GroupPolicy' { return 'Group Policy' }
        'Dynamic' { return 'Dynamic' }
        default { return 'Other/Unknown' }
    }
}

function Write-FirewallReport([string]$Path, [object[]]$Rules) {
    $rows = @($Rules | Sort-Object SortKey, DisplayName, Protocol)
    $widths = @(30, 8, 10, 11, 13, 14, 13)
    foreach ($row in $rows) {
        $values = @((Format-RuleName ([string]$row.DisplayName)), [string]$row.Protocol,
            [string]$row.LocalPort, [string]$row.RemotePort,
            [string]$row.LocalAddress, [string]$row.RemoteAddress,
            (Format-Source $row.PolicyStoreSourceType))
        for ($i = 1; $i -lt $widths.Count; $i++) {
            $widths[$i] = [Math]::Max($widths[$i], $values[$i].Length)
        }
    }
    $headers = @('Display Name','Protocol','Local Port','Remote Port','Local Address','Remote Address','Source')
    $headerParts = @()
    for ($i = 0; $i -lt $headers.Count; $i++) { $headerParts += $headers[$i].PadRight($widths[$i]) }
    $header = $headerParts -join '  '
    $lines = @($header, (''.PadLeft($header.Length, '-')))
    foreach ($row in $rows) {
        $values = @((Format-RuleName ([string]$row.DisplayName)), [string]$row.Protocol,
            [string]$row.LocalPort, [string]$row.RemotePort,
            [string]$row.LocalAddress, [string]$row.RemoteAddress,
            (Format-Source $row.PolicyStoreSourceType))
        $parts = @()
        for ($i = 0; $i -lt $values.Count; $i++) { $parts += $values[$i].PadRight($widths[$i]) }
        $lines += ($parts -join '  ').TrimEnd()
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Get-RuleReport {
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)) {
        $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $localPort = if ([string]$port.Protocol -ieq 'ICMPv4') {
            'type:' + (@($port.IcmpType) -join ',')
        } else {
            @($port.LocalPort) -join ','
        }
        [pscustomobject]@{
            DisplayName = [string]$rule.DisplayName
            Protocol = [string]$port.Protocol
            LocalPort = $localPort
            RemotePort = @($port.RemotePort) -join ','
            LocalAddress = @($address.LocalAddress) -join ','
            RemoteAddress = @($address.RemoteAddress) -join ','
            SortKey = Get-ReportSortKey $localPort
            PolicyStoreSourceType = $rule.PolicyStoreSourceType
        }
    }
}

function Write-RuleReport([string]$Path, [object[]]$Rules) {
    Write-FirewallReport $Path $Rules
}

function Export-Policy([string]$Directory, [string]$BaseName, [object[]]$Rules) {
    New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $wfw = Join-Path $Directory "$BaseName-$stamp.wfw"
    $txt = Join-Path $Directory "$BaseName-$stamp.txt"
    if ((Test-Path -LiteralPath $wfw) -or (Test-Path -LiteralPath $txt)) { throw "Refusing to overwrite backup: $wfw" }
    & netsh.exe advfirewall export $wfw | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $wfw) -or (Get-Item -LiteralPath $wfw).Length -le 0) {
        throw "Firewall export failed: $wfw"
    }
    Write-RuleReport $txt $Rules
    if ((Get-Item -LiteralPath $txt).Length -le 0) { throw "Rule report failed: $txt" }
    [pscustomobject]@{ Wfw = $wfw; Txt = $txt }
}

function New-ADSpec([string]$Suffix, [string]$Protocol, [string]$Port, [string[]]$Remote) {
    [pscustomobject]@{ Name = "$scriptPrefix$Suffix"; DisplayName = "CCDC DC Barebones $Suffix"; Protocol = $Protocol; LocalPort = $Port; Remote = [string[]]@($Remote) }
}

function Get-RuleMismatches($Spec, $Rule) {
    if ($null -eq $Rule) { return 'rule is missing' }
    $fail = @()
    if ([string]$Rule.Group -cne $ruleGroup) { $fail += "Group=$ruleGroup" }
    if ([string]$Rule.Enabled -ne 'True') { $fail += 'Enabled=True' }
    if ([string]$Rule.Direction -ne 'Inbound') { $fail += 'Direction=Inbound' }
    if ([string]$Rule.Action -ne 'Allow') { $fail += 'Action=Allow' }
    if ([string]$Rule.Profile -ne 'Any') { $fail += 'Profile=Any' }
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    if ([string]$port.Protocol -ine $Spec.Protocol) { $fail += "Protocol=$($Spec.Protocol)" }
    if ((@($port.LocalPort) -join ',') -ne $Spec.LocalPort) { $fail += "LocalPort=$($Spec.LocalPort)" }
    if ((@($port.RemotePort) -join ',') -ne 'Any') { $fail += 'RemotePort=Any' }
    if ((@($address.LocalAddress) -join ',') -ne 'Any') { $fail += 'LocalAddress=Any' }
    $actual = (Get-CanonicalSet $address.RemoteAddress) -join ','
    $expected = (Get-CanonicalSet $Spec.Remote) -join ','
    if ($actual -ne $expected) { $fail += "RemoteAddress=$expected (actual $actual)" }
    return $fail
}

function Assert-CreatedRule($Spec) {
    $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Spec.Name -ErrorAction SilentlyContinue)
    if ($rule.Count -ne 1) { throw "Verification failed for $($Spec.Name): expected one local rule, found $($rule.Count)." }
    $r = $rule[0]
    $fail = @(Get-RuleMismatches $Spec $r)
    if ($fail.Count -gt 0) { throw "Verification failed for $($Spec.Name): $($fail -join '; ')" }
}

function Write-ModifyChangeReport([string]$Path, [object[]]$Changes) {
    $lines = @(
        'CCDC DC Barebones remote-address modification'
        ("Created: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
        ''
        'Rule Name | Protocol | Local Port | Remote Address: Before --> After | Status'
        ('-' * 120)
    )
    foreach ($change in $Changes) {
        $line = "{0} | {1} | {2} | {3} --> {4} | {5}" -f $change.Name,$change.Protocol,$change.LocalPort,$change.Before,$change.After,$change.Status
        if (-not [string]::IsNullOrWhiteSpace([string]$change.Error)) { $line += " | Error: $($change.Error)" }
        $lines += $line
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Update-EnabledBarebonesRules([string[]]$RemoteScope) {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $ruleGroup -Direction Inbound -Enabled True -ErrorAction Stop |
        Where-Object { $_.Name -like "$scriptPrefix*" })
    if ($rules.Count -eq 0) {
        throw 'No enabled local CCDC DC Barebones rules were found to modify.'
    }

    $expected = (Get-CanonicalSet $RemoteScope) -join ','
    $changes = @(
        foreach ($rule in $rules) {
            $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            [pscustomobject]@{
                Name = [string]$rule.Name
                Protocol = [string]$port.Protocol
                LocalPort = (@($port.LocalPort) -join ',')
                Before = ((Get-CanonicalSet $address.RemoteAddress) -join ',')
                After = $expected
                Status = 'Pending'
                Error = ''
                Rule = $rule
            }
        }
    )

    $modifyError = $null
    foreach ($change in $changes) {
        try {
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $change.Name -RemoteAddress ([string[]]$RemoteScope) -Confirm:$false -ErrorAction Stop
            $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $change.Rule -ErrorAction Stop
            $actual = (Get-CanonicalSet $address.RemoteAddress) -join ','
            if ($actual -ne $expected) {
                throw "RemoteAddress expected $expected but was $actual."
            }
            $change.Status = 'Updated and verified'
            Write-Host "Updated $($change.Name) -> $expected" -ForegroundColor Green
        } catch {
            $change.Status = 'Failed'
            $change.Error = $_.Exception.Message
            $modifyError = "Modification failed for $($change.Name): $($_.Exception.Message)"
            break
        }
    }

    # Export the resulting firewall state after all attempted updates, then pair it with the change report.
    $backup = Export-Policy $backupDirectory 'firewall-modify-after' @(Get-RuleReport)
    Write-ModifyChangeReport $backup.Txt $changes
    Write-Host "After-modification backup: $($backup.Wfw)" -ForegroundColor Green
    Write-Host "Change report: $($backup.Txt)" -ForegroundColor Green
    if ($modifyError) { throw "$modifyError After-state backup: $($backup.Wfw); change report: $($backup.Txt)" }
    Write-Host ("Modified {0} enabled local barebones rule(s)." -f $rules.Count) -ForegroundColor Green
}

try {
    Write-Step 1 'Check administrator privileges and firewall cmdlets'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }
    foreach ($command in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Set-NetFirewallRule','Get-NetFirewallProfile','Set-NetFirewallProfile')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required firewall cmdlet is unavailable: $command" }
    }

    $providedNetworks = @($ClientNetworks | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($Modify -and $providedNetworks.Count -eq 0) {
        throw '-Modify requires -ClientNetworks with one or more IPv4 addresses or scopes.'
    }
    if ($providedNetworks.Count -gt 0) {
        Assert-IPv4Scopes $providedNetworks 'ClientNetworks'
        $remoteScope = ConvertTo-FirewallIPv4Scope $providedNetworks
        $subnetValue = $null
    } else {
        $subnetValue = Resolve-Subnet
        $remoteScope = @($subnetValue)
    }

    if ($Modify) {
        Write-Step 1 'Modify enabled local DC barebones rule scopes'
        Write-Host ("New remote scope: {0}" -f ($remoteScope -join ', ')) -ForegroundColor Gray
        Update-EnabledBarebonesRules $remoteScope
        return
    }

    $specs = @(
        (New-ADSpec 'TCP-53' 'TCP' '53' $remoteScope); (New-ADSpec 'UDP-53' 'UDP' '53' $remoteScope)
        (New-ADSpec 'TCP-88' 'TCP' '88' $remoteScope); (New-ADSpec 'UDP-88' 'UDP' '88' $remoteScope)
        (New-ADSpec 'TCP-389' 'TCP' '389' $remoteScope); (New-ADSpec 'UDP-389' 'UDP' '389' $remoteScope)
        (New-ADSpec 'TCP-464' 'TCP' '464' $remoteScope); (New-ADSpec 'UDP-464' 'UDP' '464' $remoteScope)
        (New-ADSpec 'TCP-445' 'TCP' '445' $remoteScope); (New-ADSpec 'TCP-135' 'TCP' '135' $remoteScope)
        (New-ADSpec 'TCP-RPC-Dynamic' 'TCP' '49152-65535' $remoteScope); (New-ADSpec 'UDP-123' 'UDP' '123' $remoteScope)
        (New-ADSpec 'TCP-3268' 'TCP' '3268' $remoteScope)
    )

    Write-Step 2 'Back up original firewall configuration'
    $beforeRules = @(Get-RuleReport)
    $beforeBackup = Export-Policy $backupDirectory 'firewall-before' $beforeRules
    Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
    Write-Host "Before report: $($beforeBackup.Txt)" -ForegroundColor Green

    Write-Step 3 'Enable Domain, Private, and Public firewall profiles'
    Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -Confirm:$false -ErrorAction Stop

    Write-Step 4 'Record enabled firewall rules'
    if ($subnetValue) { Write-Host ("Detected subnet: {0}" -f $subnetValue) -ForegroundColor Gray }
    Write-Host ("Remote scope: {0}" -f ($remoteScope -join ', ')) -ForegroundColor Gray
    Write-Host ("Enabled rules found: {0}" -f $beforeRules.Count) -ForegroundColor Gray

    Write-Step 5 'Detect primary IPv4 subnet'
    Write-Host "Using subnet: $subnetValue" -ForegroundColor Green

    Write-Step 6 'Create inbound AD allow rules'
    $localRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    foreach ($spec in $specs) {
        $managed = @($localRules | Where-Object {
            $_.Group -ceq $ruleGroup -and $_.DisplayName -ceq $spec.DisplayName -and
            $_.Name -like "$($spec.Name)*"
        })
        if ($managed.Count -gt 1) { throw "Multiple script-managed rules found for $($spec.DisplayName); review them before continuing." }
        if ($managed.Count -eq 1) {
            $spec.Name = [string]$managed[0].Name
            $differences = @(Get-RuleMismatches $spec $managed[0])
            if ($differences.Count -eq 0) {
                Write-Host "Reusing $($spec.Name)" -ForegroundColor Green
                continue
            }
            Write-Host "Updating $($spec.Name): $($differences -join '; ')" -ForegroundColor Yellow
            # Disable the existing allow rule before changing its scope and ports.
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -Enabled False -Confirm:$false -ErrorAction Stop
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -Direction Inbound -Action Allow -Profile Any -Protocol $spec.Protocol -LocalPort $spec.LocalPort -RemotePort Any -LocalAddress Any -RemoteAddress ([string[]]$spec.Remote) -Program Any -Service Any -Confirm:$false -ErrorAction Stop
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -Enabled True -Confirm:$false -ErrorAction Stop
            continue
        }
        $baseName = $spec.Name
        $suffix = 0
        while (@($localRules | Where-Object { $_.Name -ceq $spec.Name }).Count -gt 0 -or
            @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.Name -ErrorAction SilentlyContinue).Count -gt 0) {
            $suffix++
            if ($suffix -gt 1000) { throw "Could not allocate a unique rule name for $baseName." }
            $spec.Name = "$baseName-Managed$suffix"
        }
        $newRule = New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -DisplayName $spec.DisplayName -Group $ruleGroup -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $spec.Protocol -LocalPort $spec.LocalPort -LocalAddress Any -RemoteAddress ([string[]]$spec.Remote) -RemotePort Any -Program Any -Service Any -Confirm:$false -ErrorAction Stop
        $localRules += $newRule
        Write-Host "Created $($spec.Name)" -ForegroundColor Green
    }

    Write-Step 7 'Verify every created rule'
    foreach ($spec in $specs) { Assert-CreatedRule $spec }
    Write-Host 'All created rules verified.' -ForegroundColor Green

    Write-Step 8 'Disable other local inbound rules'
    Write-Warning 'Disabling other enabled local inbound rules can interrupt AD replication, remote management, and CCDC scoring.'
    $created = @($specs | ForEach-Object { $_.Name })
    $targets = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Enabled True -ErrorAction Stop |
        Where-Object { $created -notcontains $_.Name })
    Write-Host ("Local inbound rules to disable: {0}" -f $targets.Count) -ForegroundColor Yellow
    if ($targets.Count -gt 0) {
        $targets | Set-NetFirewallRule -Enabled False -Confirm:$false -ErrorAction Stop
        Write-Host 'Other enabled local inbound rules disabled.' -ForegroundColor Green
    }
    $effectiveNonLocal = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
        Where-Object { $created -notcontains $_.Name -and [string]$_.PolicyStoreSourceType -ne 'Local' })
    if ($effectiveNonLocal.Count -gt 0) {
        Write-Warning ("{0} effective inbound Allow rule(s) remain outside local policy and were not disabled (likely Group Policy)." -f $effectiveNonLocal.Count)
        $effectiveNonLocal | ForEach-Object { Write-Warning ("Remaining effective rule: {0}" -f $_.Name) }
    }

    Write-Step 9 'Export final firewall configuration and report'
    $afterRules = @(Get-RuleReport)
    $afterBackup = Export-Policy $backupDirectory 'firewall-after' $afterRules
    Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green
    Write-Host "After report: $($afterBackup.Txt)" -ForegroundColor Green
    $remainingAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
    if ($remainingAllows.Count -gt $specs.Count) { Write-Warning "Effective policy contains additional enabled inbound Allow rules; the firewall is not fully restricted to this script's rules." }
    Write-Host "Rollback: netsh advfirewall import `"$($beforeBackup.Wfw)`"" -ForegroundColor Magenta
} catch {
    Write-Warning "Barebones firewall configuration stopped: $($_.Exception.Message)"
    if ($beforeBackup) { Write-Host "Rollback: netsh advfirewall import `"$($beforeBackup.Wfw)`"" -ForegroundColor Magenta }
    throw
}
