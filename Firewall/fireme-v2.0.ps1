#requires -Version 5.1
<##
.SYNOPSIS
  CCDC Windows Firewall baseline for Client and Domain Controller systems.

.DESCRIPTION
  Applies a blocking inbound baseline, creates the required AD rules on a
  Domain Controller, disables other enabled local inbound rules, and exports
  before/after state. -Log enables append-only detailed firewall logging.
#>
[CmdletBinding()]
param(
    [string[]]$ClientNetworks,
    [switch]$Modify,
    [ValidateSet('DC','Client')][string]$Role,
    [switch]$Print,
    [switch]$Log,
    [switch]$Export,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArguments
)

if (($Print -or $Export) -and ($Modify -or $PSBoundParameters.ContainsKey('Role') -or
    $PSBoundParameters.ContainsKey('ClientNetworks'))) {
    throw '-Print and -Export cannot be combined with -Modify, -Role, or -ClientNetworks.'
}
if ($Print -and $Export) { throw '-Print cannot be combined with -Export.' }

$backupDirectory = 'C:\CCDC\FirewallBackups'
$scriptPrefix = 'CCDC-DC-Barebones-'
$adGroup = 'CCDC DC Barebones'
$beforeBackup = $null
$logPath = $null
$runArguments = ($PSBoundParameters.Keys -join ',')
$resolvedLogArguments = @()
$printDirections = @()

function Resolve-LogPath {
    param([switch]$Enabled, [string[]]$Arguments)
    if (-not $Enabled) { return $null }
    if (@($Arguments).Count -gt 1) { throw '-Log accepts at most one optional path.' }
    if (@($Arguments).Count -eq 1) {
        $text = ([string]$Arguments[0]).Trim()
        if ($text.StartsWith('-')) { throw "Invalid -Log path: $text" }
        if (-not [string]::IsNullOrWhiteSpace($text)) { return $text }
    }
    return (Join-Path $backupDirectory 'firewall.log')
}

function Normalize-PrintDirections([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return @('Inbound','Outbound') }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($part in $Value.Split(',')) {
        $direction = $part.Trim()
        if ($direction -notin @('Inbound','Outbound')) { throw "Invalid -Print direction: $direction. Use Inbound, Outbound, or both." }
        [void]$seen.Add($direction)
    }
    $ordered = @()
    if ($seen.Contains('Inbound')) { $ordered += 'Inbound' }
    if ($seen.Contains('Outbound')) { $ordered += 'Outbound' }
    if (-not $ordered) { throw 'At least one -Print direction is required.' }
    return $ordered
}

function Resolve-PrintAndLogArguments([switch]$PrintEnabled, [switch]$LogEnabled, [string[]]$Arguments) {
    $printValue = $null
    $logArgs = @()
    foreach ($argument in @($Arguments)) {
        $text = ([string]$argument).Trim()
        $isDirectionValue = $text -match '^(?i:(Inbound|Outbound)(\s*,\s*(Inbound|Outbound))*)$'
        if ($PrintEnabled -and $null -eq $printValue -and $isDirectionValue) {
            $printValue = $text
            continue
        }
        if ($LogEnabled -and $logArgs.Count -eq 0) {
            $logArgs += $text
            continue
        }
        throw "Unexpected argument: $text"
    }
    if ($PrintEnabled -and $null -eq $printValue) { $printValue = 'Inbound,Outbound' }
    if ($PrintEnabled -and $null -eq $printValue -and -not $LogEnabled -and @($Arguments).Count -gt 0) {
        throw "Invalid -Print direction: $($Arguments -join ', '). Use Inbound, Outbound, or both."
    }
    if (-not $PrintEnabled -and -not $LogEnabled -and @($Arguments).Count -gt 0) { throw "Unexpected argument: $($Arguments -join ' ')" }
    [pscustomobject]@{ PrintDirections = if ($PrintEnabled) { @(Normalize-PrintDirections $printValue) } else { @() }; LogArguments = $logArgs }
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Event, [string]$Detail = '')
    if (-not $script:logPath) { return }
    $line = '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Event
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $line += " | $Detail" }
    Add-Content -LiteralPath $script:logPath -Value $line -Encoding UTF8 -ErrorAction Stop
}

function Start-RunLog {
    $script:logPath = Resolve-LogPath -Enabled:$Log -Arguments $script:resolvedLogArguments
    if (-not $script:logPath) { return }
    $parent = Split-Path -Parent $script:logPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
    Add-Content -LiteralPath $script:logPath -Value @('', '===== RUN START =====',
        ("Time={0}" -f (Get-Date -Format 'o')),
        ("Computer={0}" -f $env:COMPUTERNAME),
        'ScriptVersion=2.0',
        ("Arguments={0}" -f $script:runArguments),
        ("LogPath={0}" -f $script:logPath)) -Encoding UTF8 -ErrorAction Stop
    Write-Host "Detailed firewall logging enabled: $script:logPath" -ForegroundColor Gray
}

function Get-Role {
    $role = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    switch ([int]$role.DomainRole) {
        0 { $name = 'Standalone workstation'; $workflow = 'Client' }
        1 { $name = 'Domain-joined workstation'; $workflow = 'Client' }
        2 { $name = 'Standalone server'; $workflow = 'Client' }
        3 { $name = 'Domain-joined member server'; $workflow = 'Client' }
        4 { $name = 'Domain Controller'; $workflow = 'DC' }
        5 { $name = 'Domain Controller'; $workflow = 'DC' }
        default { throw "Unknown Windows DomainRole: $($role.DomainRole)" }
    }
    [pscustomobject]@{ DomainRole = [int]$role.DomainRole; Name = $name; Workflow = $workflow }
}

function Assert-Role([string]$Actual, [string]$Requested) {
    if ($Requested -and $Actual -ne $Requested) { throw "Requested -Role $Requested but detected $Actual." }
}

function Set-Baseline {
    Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false -ErrorAction Stop
    foreach ($p in @(Get-NetFirewallProfile -Name Domain,Private,Public -ErrorAction Stop)) {
        if (-not $p.Enabled -or [string]$p.DefaultInboundAction -ne 'Block' -or [string]$p.DefaultOutboundAction -ne 'Allow') {
            throw "Firewall baseline verification failed for profile $($p.Name)."
        }
    }
    Write-Log 'BASELINE' 'Profiles=Domain,Private,Public | Inbound=Block | Outbound=Allow'
}

function New-UniquePaths([string]$Base, [string[]]$Extensions) {
    New-Item -ItemType Directory -Path $backupDirectory -Force -ErrorAction Stop | Out-Null
    $stamp = Get-Date -Format 'HHmm-MMddyyyy'
    $safeComputer = ($env:COMPUTERNAME -replace '[^A-Za-z0-9_.-]', '_')
    for ($i = 0; $i -lt 1000; $i++) {
        $suffix = if ($i) { '-{0:D2}' -f $i } else { '' }
        $stem = "$Base-$safeComputer-$stamp$suffix"
        $paths = @{}; $ok = $true
        foreach ($ext in $Extensions) { $paths[$ext] = Join-Path $backupDirectory "$stem.$ext"; if (Test-Path $paths[$ext]) { $ok = $false } }
        if ($ok) { return $paths }
    }
    throw "Could not allocate output paths for $Base."
}

function Get-RuleRows {
    $rows = foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Enabled -eq 'True' })) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        $a = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        [pscustomobject]@{ DisplayName=$r.DisplayName; Direction=$r.Direction; Protocol=$p.Protocol; LocalPort=(@($p.LocalPort)-join ','); RemotePort=(@($p.RemotePort)-join ','); LocalAddress=(@($a.LocalAddress)-join ','); RemoteAddress=(@($a.RemoteAddress)-join ','); Source=[string]$r.PolicyStoreSourceType }
    }
    return @($rows)
}

function Get-PrintSortKey([string]$LocalPort) {
    $match = [regex]::Match($LocalPort, '\d+')
    if ($match.Success) { return [int]$match.Value }
    return [int]::MaxValue
}

function Write-PrintReport([string[]]$Directions, [object[]]$Rows) {
    $selected = @($Rows | Where-Object { $Directions -contains [string]$_.Direction })
    Write-Host "`nEnabled firewall rules" -ForegroundColor Cyan
    Write-Host ("Directions: {0}" -f ($Directions -join ', ')) -ForegroundColor Gray
    Write-Host ("Count: {0}" -f $selected.Count) -ForegroundColor Gray
    Write-Log 'PRINT' "Directions=$($Directions -join ',') | EnabledRules=$($selected.Count)"
    foreach ($direction in $Directions) {
        Write-Host ("`n================ {0} RULES ================" -f $direction.ToUpperInvariant()) -ForegroundColor Cyan
        $section = @($selected | Where-Object { [string]$_.Direction -eq $direction } | Select-Object *, @{Name='PrintSortKey';Expression={ Get-PrintSortKey ([string]$_.LocalPort) }} | Sort-Object PrintSortKey,DisplayName,Protocol)
        if (-not $section) { Write-Host "No enabled $direction rules found."; continue }
        $section | Format-Table DisplayName,Protocol,LocalPort,RemoteAddress,Source -AutoSize | Out-Host
        foreach ($row in $section) { Write-Log 'PRINT-RULE' "Direction=$direction | Name=$($row.DisplayName) | Protocol=$($row.Protocol) | LocalPort=$($row.LocalPort) | Remote=$($row.RemoteAddress) | Source=$($row.Source)" }
    }
}

function Write-Report([string]$Path, [object[]]$Rows) {
    $lines = @('CCDC Windows Firewall report', ("Created: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')), '')
    foreach ($direction in @('Inbound','Outbound')) {
        $lines += "[$direction]"
        $selected = @($Rows | Where-Object Direction -eq $direction | Sort-Object LocalPort,DisplayName)
        if (-not $selected) { $lines += 'No enabled rules found.' }
        foreach ($r in $selected) { $lines += ('{0} | {1} | {2} | Local={3}:{4} | Remote={5}:{6}' -f $r.DisplayName,$r.Protocol,$r.Direction,$r.LocalAddress,$r.LocalPort,$r.RemoteAddress,$r.RemotePort) }
        $lines += ''
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Export-State([string]$Base) {
    $paths = New-UniquePaths $Base @('wfw','txt')
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $proc = Start-Process -FilePath $netsh -ArgumentList "advfirewall export `"$($paths.wfw)`"" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0 -or -not (Test-Path $paths.wfw)) { throw "Firewall export failed: $($paths.wfw)" }
    $rows = @(Get-RuleRows); Write-Report $paths.txt $rows
    Write-Log 'EXPORT' "Wfw=$($paths.wfw) | Txt=$($paths.txt) | EnabledRules=$($rows.Count)"
    [pscustomobject]@{ Wfw=$paths.wfw; Txt=$paths.txt }
}

function ConvertTo-Scope([string[]]$Values) {
    $out = @()
    foreach ($v in $Values) { foreach ($part in ([string]$v -split '[,;]')) { $x=$part.Trim(); if ($x) { if ($x -notmatch '^(?i:Any|LocalSubnet4)$' -and $x -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { throw "Invalid IPv4 scope: $x" }; if ($x -eq '0.0.0.0/0') { throw 'IPv4 /0 is not allowed.' }; $out += $x } } }
    if (-not $out) { throw 'At least one IPv4 scope is required.' }
    return @($out | Sort-Object -Unique)
}

function Invoke-ADRules([string[]]$Remote) {
    $specs = @(
        @('TCP','53'),@('UDP','53'),@('TCP','88'),@('UDP','88'),@('TCP','389'),@('UDP','389'),@('TCP','464'),@('UDP','464'),
        @('TCP','445'),@('TCP','135'),@('TCP','49152-65535'),@('UDP','123'),@('TCP','3268'))
    $created = @()
    foreach ($s in $specs) {
        $name = "$scriptPrefix$($s[0])-$($s[1] -replace '[^0-9-]','')"
        $display = "CCDC DC Barebones $($s[0])-$($s[1])"
        $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
        if ($rule.Count -eq 0) { New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $display -Group $adGroup -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $s[0] -LocalPort $s[1] -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop | Out-Null; $action='Create' }
        else { Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled False -Confirm:$false -ErrorAction Stop; Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled True -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop; $action='Update' }
        $created += $name
        Write-Host ("{0} AD rule: {1} ({2}/{3}, Remote={4})" -f $action,$name,$s[0],$s[1],($Remote -join ',')) -ForegroundColor Green
        Write-Log 'AD-RULE' "Action=$action | Name=$name | Protocol=$($s[0]) | LocalPort=$($s[1]) | Remote=$($Remote -join ',')"
    }
    return $created
}

function Update-ADRules([string[]]$Remote) {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
        Where-Object { [string]$_.Group -ceq $adGroup -and [string]$_.Direction -eq 'Inbound' -and [string]$_.Enabled -eq 'True' -and $_.Name -like "$scriptPrefix*" })
    if (-not $rules) { throw 'No enabled local AD rules were found to modify.' }
    foreach ($rule in $rules) {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop
        Write-Log 'AD-RULE' "Action=Update | Name=$($rule.Name) | Remote=$($Remote -join ',')"
    }
    Write-Host "Updated enabled AD rules: $($rules.Count)" -ForegroundColor Green
}

function Disable-OtherInbound([string[]]$Preserve) {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
        Where-Object { [string]$_.Direction -eq 'Inbound' -and [string]$_.Enabled -eq 'True' })
    $targets = @($rules | Where-Object { $Preserve -notcontains $_.Name })
    foreach ($r in $targets) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        $a = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -Enabled False -Confirm:$false -ErrorAction Stop
        Write-Log 'DISABLE' "Name=$($r.Name) | Protocol=$($p.Protocol) | LocalPort=$(@($p.LocalPort)-join ',') | Remote=$(@($a.RemoteAddress)-join ',')"
    }
    $nonlocal = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { [string]$_.Direction -eq 'Inbound' -and [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Allow' -and $Preserve -notcontains $_.Name -and [string]$_.PolicyStoreSourceType -ne 'Local' })
    Write-Log 'CLEANUP' "LocalFound=$($rules.Count) | Disabled=$($targets.Count) | NonlocalRemaining=$($nonlocal.Count)"
    Write-Host "Enabled local inbound rules found: $($rules.Count)" -ForegroundColor Gray
    Write-Host "Script-created inbound rules preserved: $($rules.Count - $targets.Count)" -ForegroundColor Gray
    Write-Host "Non-script-created inbound rules disabled: $($targets.Count)" -ForegroundColor Gray
    Write-Host "Nonlocal inbound rules reported separately: $($nonlocal.Count)" -ForegroundColor Gray
    if ($nonlocal.Count) { Write-Warning "$($nonlocal.Count) nonlocal inbound rule(s) remain enabled and could not be disabled locally." }
}

try {
    $resolvedArguments = Resolve-PrintAndLogArguments -PrintEnabled:$Print -LogEnabled:$Log -Arguments $RemainingArguments
    $script:printDirections = @($resolvedArguments.PrintDirections)
    $script:resolvedLogArguments = @($resolvedArguments.LogArguments)
    Start-RunLog
    Write-Host 'Checking administrator privileges and firewall cmdlets...' -ForegroundColor Cyan
    $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $pr=New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }
    $commands = if ($Export -or $Print) { @('Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter') } else { @('Get-NetFirewallRule','New-NetFirewallRule','Set-NetFirewallRule','Get-NetFirewallProfile','Set-NetFirewallProfile','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter') }
    foreach ($c in $commands) { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "Required firewall cmdlet is unavailable: $c" } }
    if ($Print) { Write-PrintReport $script:printDirections @(Get-RuleRows); Write-Log 'STATUS' 'Print completed'; return }
    if ($Export) { $out=New-UniquePaths 'firewall-export' @('txt'); Write-Report $out.txt @(Get-RuleRows); Write-Host "Enabled firewall report: $($out.txt)"; Write-Log 'STATUS' 'Export completed'; return }
    if ($ClientNetworks) { $ClientNetworks=ConvertTo-Scope $ClientNetworks }
    if ($Modify) {
        if (-not $ClientNetworks) { throw '-Modify requires -ClientNetworks.' }
        $detectedRole=Get-Role; Assert-Role -Actual ([string]$detectedRole.Workflow) -Requested $Role
        if ($detectedRole.Workflow -ne 'DC') { throw '-Modify is only available on a Domain Controller.' }
        $beforeBackup=Export-State 'firewall-modify-before'; Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
        Update-ADRules $ClientNetworks
        $afterBackup=Export-State 'firewall-modify-after'; Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green
        Write-Log 'STATUS' "Modify completed | AfterBackup=$($afterBackup.Wfw)"
        Write-Host "Modify workflow completed. Log: $(if ($logPath) { $logPath } else { 'not enabled' })" -ForegroundColor Green
        return
    }
    Set-Baseline; $beforeBackup=Export-State 'firewall-before'; Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
    $detectedRole=Get-Role; Assert-Role -Actual ([string]$detectedRole.Workflow) -Requested $Role; Write-Log 'ROLE' "Detected=$($detectedRole.Name) | DomainRole=$($detectedRole.DomainRole) | Workflow=$($detectedRole.Workflow)"; Write-Host "Detected machine: $($detectedRole.Name) (DomainRole $($detectedRole.DomainRole)); workflow: $($detectedRole.Workflow)" -ForegroundColor Gray
    $preserve=@()
    if ($detectedRole.Workflow -eq 'DC') { $remote=if ($ClientNetworks) { $ClientNetworks } else { @('LocalSubnet4') }; $preserve += Invoke-ADRules $remote; Write-Host "AD rules created or updated: $($preserve.Count)" -ForegroundColor Gray }
    Disable-OtherInbound $preserve
    $afterBackup=Export-State 'firewall-after'; Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green; Write-Host "After report: $($afterBackup.Txt)" -ForegroundColor Green
    Write-Log 'STATUS' "Completed | Workflow=$($detectedRole.Workflow) | AfterBackup=$($afterBackup.Wfw)"
    Write-Host "Workflow completed. Log: $(if ($logPath) { $logPath } else { 'not enabled' })" -ForegroundColor Green
} catch {
    try { Write-Log 'ERROR' $_.Exception.Message; if ($beforeBackup) { Write-Log 'ROLLBACK' "netsh advfirewall import `"$($beforeBackup.Wfw)`"" } } catch { }
    Write-Warning "Firewall configuration stopped: $($_.Exception.Message)"
    throw
}
