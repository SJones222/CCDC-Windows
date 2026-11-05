#requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free synthetic tests; run with Windows PowerShell 5.1.
.DESCRIPTION
    Loads only collector function ASTs. All network/CIM sources are mocked.
    Synthetic reports use an invocation-owned TEMP directory, never real inventory.
#>
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this suite on Windows PowerShell 5.1.' }
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Inventory\Get-NetworkRelationships.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Collector syntax parsing failed.' }
$definitions = @{}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    $definitions[$node.Name] = $node.Body.GetScriptBlock()
}
$script:Passed = 0; $script:Failed = 0
$script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('CCDC-Relationships-Tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:TestRoot)
$script:Allowed = @('S-1-5-21-1-2-3-1001', 'S-1-5-18', 'S-1-5-32-544')

function Assert-True {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Synthetic assertion failed.' }
}
function Assert-Throws {
    param([scriptblock]$Action)
    $raised = $false
    try { & $Action } catch { $raised = $true }
    Assert-True $raised
}
function New-Connection {
    param([uint32]$Number = 123, [string]$Local = '10.0.26.141', [string]$Remote = '10.0.26.157')
    [pscustomobject]@{ LocalAddress = $Local; LocalPort = [uint16]3389; RemoteAddress = $Remote; RemotePort = [uint16]50000; State = 'Established'; OwningProcess = $Number }
}
function New-Address {
    param([string]$IP = '10.0.26.141', [uint32]$Index = 12, [uint32]$Prefix = 24)
    [pscustomobject]@{ InterfaceIndex = $Index; InterfaceAlias = 'Synthetic'; IPAddress = $IP; PrefixLength = $Prefix; AddressState = 'Preferred' }
}
function Read-FixtureSource {
    [CmdletBinding()]
    param([string]$Key)
    $script:SourceCalls.Add($Key)
    switch ($script:Modes[$Key]) {
        Denied { throw [UnauthorizedAccessException]::new('SYNTHETIC_SECRET') }
        Failed { throw [InvalidOperationException]::new('SYNTHETIC_SECRET') }
        Missing { throw [System.Management.Automation.CommandNotFoundException]::new('SYNTHETIC_SECRET') }
        Timeout { throw [TimeoutException]::new('SYNTHETIC_SECRET') }
        NoMatch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new([Exception]::new('Synthetic'), 'CmdletizationQuery_NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        UnknownNotFound {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new([Exception]::new('Synthetic'), 'UnexpectedNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        AfterOne { $script:Rows[$Key][0]; throw [InvalidOperationException]::new('SYNTHETIC_SECRET') }
    }
    $script:Rows[$Key]
}
function Reset-Fixture {
    foreach ($name in $definitions.Keys) { Set-Item -Path ('Function:script:' + $name) -Value $definitions[$name] }
    $script:CollectionIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:OutputIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:WarningCount = 0
    $script:Modes = @{}; $script:Rows = @{}
    $script:SourceCalls = New-Object 'System.Collections.Generic.List[string]'
    $script:Batches = New-Object 'System.Collections.Generic.List[object]'
    $script:CimModes = @{ Processes = 'Success'; Services = 'Success' }
    $script:ProcessRows = @{}; $script:ServiceRows = @{}
    $script:ClockCalls = 0; $script:ExpireAt = 0
    $script:ProtectionFailure = $false; $script:Preparations = 0; $script:PreparationFailures = 0
    $script:LastLocation = $null
    $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection))
    foreach ($id in @('LocalAddresses', 'Interfaces', 'DnsServers', 'Routes')) {
        foreach ($family in @('IPv4', 'IPv6')) { $script:Rows[($id + ':' + $family)] = @() }
    }
    $script:Rows['LocalAddresses:IPv4'] = @((New-Address))
    $script:Rows['LocalAddresses:IPv6'] = @((New-Address 'fe80::abcd' 12 64))
    $script:Rows['Interfaces:IPv4'] = @([pscustomobject]@{ InterfaceIndex = [uint32]12; InterfaceAlias = 'Synthetic'; ConnectionState = 'Connected'; InterfaceMetric = [uint32]25 })
    $script:Rows['Interfaces:IPv6'] = @($script:Rows['Interfaces:IPv4'][0].PSObject.Copy())
    $script:Rows['DnsServers:IPv4'] = @([pscustomobject]@{ InterfaceIndex = [uint32]12; InterfaceAlias = 'Synthetic'; ServerAddresses = [string[]]@('10.0.26.141') })
    $script:Rows['Routes:IPv4'] = @([pscustomobject]@{ InterfaceIndex = [uint32]12; DestinationPrefix = '0.0.0.0/0'; NextHop = '10.0.26.1'; RouteMetric = [uint32]10 })
    function script:Get-NetTCPConnection { [CmdletBinding()]param($State); Assert-True ($State -eq 'Established'); Read-FixtureSource 'TCPConnections:EstablishedTCP' }
    function script:Get-NetIPAddress { [CmdletBinding()]param($AddressFamily); Read-FixtureSource ('LocalAddresses:' + $AddressFamily) }
    function script:Get-NetIPInterface { [CmdletBinding()]param($AddressFamily); Read-FixtureSource ('Interfaces:' + $AddressFamily) }
    function script:Get-DnsClientServerAddress { [CmdletBinding()]param($AddressFamily); Read-FixtureSource ('DnsServers:' + $AddressFamily) }
    function script:Get-NetRoute { [CmdletBinding()]param($AddressFamily,$PolicyStore); Assert-True ($PolicyStore -eq 'ActiveStore'); Read-FixtureSource ('Routes:' + $AddressFamily) }
    function script:Get-ContextElapsedSeconds {
        param($Clock)
        $script:ClockCalls++
        if ($script:ExpireAt -gt 0 -and $script:ClockCalls -ge $script:ExpireAt) { return 60 }
        0
    }
    function script:Get-CimInstance {
        [CmdletBinding()]
        param($ClassName, [string[]]$Property, $Filter, $OperationTimeoutSec)
        Assert-True ($OperationTimeoutSec -eq 30)
        $kind = if ($ClassName -eq 'Win32_Process') { 'Processes' } elseif ($ClassName -eq 'Win32_Service') { 'Services' } else { throw 'Unapproved CIM source.' }
        if ($kind -eq 'Processes') {
            Assert-True (($Property -join ',') -eq 'ProcessId,Name,CreationDate')
            Assert-True ($Filter -match '^ProcessId = [0-9]+( OR ProcessId = [0-9]+)*$')
        }
        else {
            Assert-True (($Property -join ',') -eq 'Name,DisplayName,State,ProcessId')
            Assert-True ($Filter -match "^State = 'Running' AND \(ProcessId = [0-9]+( OR ProcessId = [0-9]+)*\)$")
        }
        $numbers = @([regex]::Matches($Filter, 'ProcessId = ([0-9]+)') | ForEach-Object { [uint32]$_.Groups[1].Value })
        Assert-True ($numbers.Count -gt 0 -and $numbers.Count -le 32 -and -not ($numbers -contains 0))
        $script:Batches.Add([pscustomobject]@{ Kind = $kind; Pids = $numbers })
        switch ($script:CimModes[$kind]) {
            Denied { throw [UnauthorizedAccessException]::new('SYNTHETIC_SECRET') }
            Missing { throw [System.Management.Automation.CommandNotFoundException]::new('SYNTHETIC_SECRET') }
            Failed { throw [InvalidOperationException]::new('SYNTHETIC_SECRET') }
            Empty { return }
        }
        foreach ($number in $numbers) {
            $key = [string]$number
            if ($kind -eq 'Processes') {
                if ($script:ProcessRows.ContainsKey($key)) { $script:ProcessRows[$key] }
                else { [pscustomobject]@{ ProcessId = $number; Name = 'SyntheticProcess'; CreationDate = [datetime]::Parse('2000-01-01T00:00:00Z').ToUniversalTime() } }
            }
            elseif ($script:ServiceRows.ContainsKey($key)) { $script:ServiceRows[$key] }
            if ($script:CimModes[$kind] -eq 'AfterOne') { throw [InvalidOperationException]::new('SYNTHETIC_SECRET') }
        }
    }
    function script:Assert-ProtectedReportPath { param($Path,$AllowedSids); if ($script:ProtectionFailure) { throw 'Synthetic protection failure' } }
}
function Invoke-Fixture {
    $datasets = @(foreach ($id in @('TCPConnections','LocalAddresses','Interfaces','DnsServers','Routes')) { Get-NetworkDataset $id })
    Set-InterfaceReferences $datasets[2] @($datasets[1],$datasets[3],$datasets[4])
    Set-ConnectionRelationships $datasets[0] $datasets[1]
    $budget = [ordered]@{}
    $context = Get-ConnectionContext $datasets[0] $budget
    [pscustomobject]@{ Datasets = @($datasets) + @($context.Processes,$context.Services); Budget = $budget }
}
function Assert-References {
    param($Result)
    $map = @{}
    foreach ($dataset in $Result.Datasets) {
        $ids = @($dataset.Items | ForEach-Object { $_.Id })
        Assert-True (@($ids | Select-Object -Unique).Count -eq $ids.Count)
        Assert-True ($null -eq $dataset.Count -or $dataset.Count -eq $ids.Count)
        $map[$dataset.Id] = $ids
    }
    foreach ($dataset in $Result.Datasets) {
        foreach ($item in $dataset.Items) {
            foreach ($field in @('ProcessRecordId','RelatedServiceIds','ConnectionIds','LocalAddressIds','LocalInterfaceIds','InterfaceIds')) {
                if (-not $item.PSObject.Properties[$field]) { continue }
                $target = switch ($field) {
                    ProcessRecordId { 'Processes' } RelatedServiceIds { 'Services' } ConnectionIds { 'TCPConnections' }
                    LocalAddressIds { 'LocalAddresses' } default { 'Interfaces' }
                }
                foreach ($id in @($item.$field)) { if ($null -ne $id) { Assert-True ($map[$target] -contains $id) } }
            }
        }
    }
    foreach ($name in @('Processes','Services')) {
        $usage = $Result.Budget[$name]
        if ($null -ne $usage.CandidateCount) { Assert-True ($usage.CandidateCount -eq $usage.AttemptedCount + $usage.SkippedCount) }
        Assert-True ($usage.AttemptedCount -eq $usage.CompletedCount + $usage.UnusableCount)
    }
}
function New-TestLocation {
    $directory = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    $location = [pscustomobject]@{ Directory = $directory; TemporaryPaths = [ordered]@{}; CreatedPaths = (New-Object 'System.Collections.Generic.List[string]') }
    foreach ($name in (Get-RelationshipReportNames)) {
        $path = Join-Path $directory ($name + '.tmp')
        [IO.File]::Open($path,[IO.FileMode]::CreateNew).Dispose()
        $location.TemporaryPaths[$name] = $path; $location.CreatedPaths.Add($path)
    }
    $location
}
function New-TestReport {
    param($Location)
    $result = Invoke-Fixture
    [ordered]@{
        ModuleId = 'network-relationships'; Version = '0.1.0'; SchemaVersion = '0.1.0'
        DevelopmentStage = 'Milestone 1.3'; ReleaseReady = $false; RunId = 'SYNTHETIC-RUN'; Hostname = 'SYNTHETIC'
        StartedAt = '2000-01-01T00:00:00Z'; CompletedAt = '2000-01-01T00:00:01Z'
        Collection = [ordered]@{ Status = Get-AggregateStatus $result.Datasets; Datasets = $result.Datasets; BudgetUsage = $result.Budget; Issues = @($script:CollectionIssues.ToArray()) }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{ Status = 'Failed'; Directory = $Location.Directory; FallbackUsed = $false; ProtectionStatus = 'VerifiedRestricted'; Files = @(Get-RelationshipReportNames); Issues = @() }
    }
}
function Run-Test {
    param([string]$Name,[scriptblock]$Action)
    Reset-Fixture
    try { & $Action; $script:Passed++; Write-Host ('PASS: ' + $Name) }
    catch { $script:Failed++; Write-Host ('FAIL: ' + $Name + ' / ' + $_.Exception.GetType().Name) }
}

try {
    Run-Test 'cross-machine IPv4 evidence preserves source endpoints and unknown initiator' {
        $result = Invoke-Fixture; $row = $result.Datasets[0].Items[0]
        Assert-True ($row.Relationship -eq 'CrossMachineObserved' -and $row.Initiator -eq 'Unknown' -and $row.LocalAddress -eq '10.0.26.141' -and $row.LocalPort -eq 3389)
        Assert-True ($script:SourceCalls.Count -eq 9 -and $row.LocalAddressIds.Count -eq 1)
        Assert-References $result
    }
    Run-Test 'equal scoped IPv6 endpoints are same host with preserved zones' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 'fe80::abcd%12' 'fe80:0:0:0:0:0:0:ABCD%12'))
        $result = Invoke-Fixture; $row = $result.Datasets[0].Items[0]
        Assert-True ($row.Relationship -eq 'SameHostObserved' -and $row.RelationshipReason -eq 'EqualEndpointAddresses' -and $row.LocalScopeId -eq 12 -and $row.RemoteScopeId -eq 12)
        Assert-References $result
    }
    Run-Test 'conflicting scoped IPv6 endpoints cannot create cross-machine evidence' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 'fe80::abcd%12' 'fe80::abcd%7'))
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'Unknown' -and $result.Datasets[0].Items[0].RelationshipReason -eq 'AmbiguousScope')
    }
    Run-Test 'missing zones resolve only through a unique local interface' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 'fe80::abcd' 'fe80::abcd'))
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'SameHostObserved' -and $null -eq $result.Datasets[0].Items[0].LocalScopeId)
        $script:Rows['LocalAddresses:IPv6'] += New-Address 'fe80::abcd' 7 64
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'Unknown')
    }
    Run-Test 'loopback and mapped IPv4 loopback remain same host without addresses' {
        $script:Modes['LocalAddresses:IPv4'] = 'Denied'; $script:Modes['LocalAddresses:IPv6'] = 'Denied'
        foreach ($pair in @(@('127.0.0.1','127.9.8.7'),@('::1','::1'),@('::ffff:127.0.0.1','::ffff:127.0.0.2'))) {
            $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 $pair[0] $pair[1]))
            $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'SameHostObserved')
        }
    }
    Run-Test 'different assigned IPv4 addresses are same-host evidence' {
        $script:Rows['LocalAddresses:IPv4'] += New-Address '10.0.26.157' 7 24
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].RelationshipReason -eq 'RemoteMatchesLocalAddress')
    }
    Run-Test 'mapped IPv4 compares numerically without altering raw strings' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 '::ffff:10.0.26.141' '::ffff:10.0.26.157'))
        $result = Invoke-Fixture; $row = $result.Datasets[0].Items[0]
        Assert-True ($row.Relationship -eq 'CrossMachineObserved' -and $row.AddressFamily -eq 'IPv6' -and $row.LocalAddressNormalized -eq '10.0.26.141' -and $row.LocalAddress.StartsWith('::ffff:'))
    }
    Run-Test 'unsupported and malformed endpoints never become remote machines' {
        foreach ($remote in @('not-an-address','123','010.0.26.157','0.0.0.0','224.0.0.1','255.255.255.255','10.0.26.255','fe80::1%NamedZone','ff02::1')) {
            $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 123 '10.0.26.141' $remote))
            $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'Unknown')
        }
    }
    Run-Test 'missing address coverage prevents negative local-membership claims' {
        $script:Modes['LocalAddresses:IPv6'] = 'Denied'
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[1].Status -eq 'Partial' -and $result.Datasets[0].Items[0].RelationshipReason -eq 'LocalCoverageIncomplete')
        Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Partial')
    }
    Run-Test 'unknown local context and duplicate interfaces are not guessed' {
        $script:Rows['LocalAddresses:IPv4'] = @((New-Address '10.0.26.140'))
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].RelationshipReason -eq 'LocalContextUnknown')
        $script:Rows['LocalAddresses:IPv4'] = @((New-Address),(New-Address '10.0.26.141' 7))
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'Unknown')
    }
    Run-Test 'optional interface failure does not erase required address context' {
        $script:Modes['Interfaces:IPv4'] = 'Denied'; $script:Modes['Interfaces:IPv6'] = 'Denied'
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[0].Items[0].Relationship -eq 'CrossMachineObserved' -and $result.Datasets[0].Items[0].LocalInterfaceIds.Count -eq 0)
        Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Success')
        Assert-References $result
    }
    Run-Test 'repeated TCP tuples remain distinct observations' {
        $script:Rows['TCPConnections:EstablishedTCP'] += New-Connection
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Count -eq 2 -and $result.Datasets[5].Count -eq 1)
        Assert-References $result
    }
    Run-Test 'enum fields convert while unexpected arrays are rejected as scalars' {
        $script:Rows['TCPConnections:EstablishedTCP'][0].State = [Net.NetworkInformation.TcpState]::Established
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Status -eq 'Success')
        $script:Rows['TCPConnections:EstablishedTCP'][0].OwningProcess = @(123)
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Status -eq 'Partial' -and $null -eq $result.Datasets[0].Items[0].ProcessId)
    }
    Run-Test 'ports prefixes and missing required properties remain visibly partial' {
        $script:Rows['TCPConnections:EstablishedTCP'][0].LocalPort = 65536
        $script:Rows['LocalAddresses:IPv4'][0].PrefixLength = 33
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[0].Status -eq 'Partial' -and $null -eq $result.Datasets[0].Items[0].LocalPort)
        Assert-True ($result.Datasets[1].Status -eq 'Partial' -and $null -eq $result.Datasets[1].Items[0].PrefixLength)
    }
    Run-Test 'absent connection creation time is not replaced by observation time' {
        $result = Invoke-Fixture; $row = $result.Datasets[0].Items[0]
        Assert-True ($row.RecordStatus -eq 'Success' -and $null -eq $row.ConnectionCreatedAt -and $row.ObservedAt.EndsWith('Z'))
    }
    Run-Test 'unreadable properties preserve wrapped access-denied identity' {
        $script:Rows['TCPConnections:EstablishedTCP'][0].PSObject.Properties.Remove('OwningProcess')
        $script:Rows['TCPConnections:EstablishedTCP'][0] | Add-Member ScriptProperty OwningProcess { throw [UnauthorizedAccessException]::new('SYNTHETIC_SECRET') }
        $result = Invoke-Fixture
        Assert-True ($null -eq $result.Datasets[0].Items[0].ProcessId -and @($script:CollectionIssues | Where-Object { $_.Code -eq 'AccessDenied' }).Count -gt 0)
    }
    Run-Test 'each source distinguishes no-match denied missing timeout and failed queries' {
        foreach ($id in @('TCPConnections','LocalAddresses','Interfaces','DnsServers','Routes')) {
            foreach ($mode in @('NoMatch','Denied','Missing','Timeout','Failed','UnknownNotFound')) {
                $keys = if ($id -eq 'TCPConnections') { @('EstablishedTCP') } else { @('IPv4','IPv6') }
                foreach ($key in $keys) { $script:Modes[($id + ':' + $key)] = $mode }
                $dataset = Get-NetworkDataset $id
                $expected = if ($mode -eq 'NoMatch') { 'Success' } elseif ($mode -in @('Denied','Missing')) { 'Unavailable' } else { 'Failed' }
                Assert-True ($dataset.Status -eq $expected)
                Assert-True (($expected -eq 'Success' -and $dataset.Count -eq 0) -or ($expected -ne 'Success' -and $null -eq $dataset.Count))
            }
        }
    }
    Run-Test 'denied minimum endpoint identity is unavailable rather than an invalid-address failure' {
        $row = $script:Rows['TCPConnections:EstablishedTCP'][0]
        $row.PSObject.Properties.Remove('LocalAddress')
        $row | Add-Member ScriptProperty LocalAddress { throw [UnauthorizedAccessException]::new('SYNTHETIC_SECRET') }
        $dataset = Get-NetworkDataset TCPConnections
        Assert-True ($dataset.Status -eq 'Unavailable' -and $null -eq $dataset.Count)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'InvalidAddress' }).Count -eq 0)
    }
    Run-Test 'partial source emission preserves records and unknown target totals' {
        $script:Modes['TCPConnections:EstablishedTCP'] = 'AfterOne'
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[0].Status -eq 'Partial' -and $result.Datasets[0].Count -eq 1 -and $null -eq $result.Budget.Processes.CandidateCount -and $result.Datasets[5].Status -eq 'Partial')
        Assert-References $result
    }
    Run-Test 'successful empty required sources produce zero and no context queries' {
        foreach ($key in @($script:Rows.Keys)) { $script:Rows[$key] = @() }
        $result = Invoke-Fixture
        Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Success' -and $result.Datasets[5].Count -eq 0 -and $script:Batches.Count -eq 0)
        Assert-References $result
    }
    Run-Test 'all failed required queries are failed while optional successes cannot rescue them' {
        foreach ($key in @('TCPConnections:EstablishedTCP','LocalAddresses:IPv4','LocalAddresses:IPv6')) { $script:Modes[$key] = 'Failed' }
        $result = Invoke-Fixture; Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Failed' -and $result.Datasets[5].Status -eq 'Failed' -and $script:Batches.Count -eq 0)
    }
    Run-Test 'unavailable required sources remain unavailable with null counts' {
        foreach ($key in @('TCPConnections:EstablishedTCP','LocalAddresses:IPv4','LocalAddresses:IPv6')) { $script:Modes[$key] = 'Denied' }
        $result = Invoke-Fixture; Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Unavailable' -and $null -eq $result.Datasets[0].Count)
    }
    Run-Test 'empty DNS lists differ from unavailable lists and preserve valid preceding addresses' {
        $script:Rows['DnsServers:IPv4'][0].ServerAddresses = [string[]]@()
        $result = Invoke-Fixture; Assert-True ($result.Datasets[3].Items[0].ServerAddressesState -eq 'Collected' -and $result.Datasets[3].Items[0].ServerAddresses.Count -eq 0)
        $script:Rows['DnsServers:IPv4'][0].ServerAddresses = @('10.0.26.141','bad-name','10.0.26.1')
        $result = Invoke-Fixture; Assert-True ($result.Datasets[3].Items[0].ServerAddressesState -eq 'Unavailable' -and $result.Datasets[3].Items[0].ServerAddresses.Count -eq 2)
    }
    Run-Test 'high-PID cross-machine target precedes more than 128 lower same-host PIDs' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @(foreach ($number in 1..130) { New-Connection $number '127.0.0.1' '127.0.0.1' }) + @((New-Connection 9000))
        $result = Invoke-Fixture
        Assert-True ($script:Batches[0].Pids[0] -eq 9000 -and $script:Batches[0].Pids[1] -eq 1)
        Assert-True ($result.Datasets[5].TargetOutcomes[0].ProcessId -eq 9000 -and $result.Datasets[5].TargetOutcomes[0].Outcome -eq 'Returned')
        Assert-True ($result.Budget.Processes.CandidateCount -eq 131 -and $result.Budget.Processes.AttemptedCount -eq 128 -and $result.Budget.Processes.SkippedCount -eq 3)
        Assert-References $result
    }
    Run-Test 'multi-tier PIDs deduplicate at highest priority with numeric order within tiers' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 9 '127.0.0.1' '127.0.0.1'),(New-Connection 900),(New-Connection 800),(New-Connection 700 '10.0.26.141' 'bad'),(New-Connection 9))
        $result = Invoke-Fixture
        Assert-True (($script:Batches[0].Pids -join ',') -eq '9,800,900,700' -and $result.Datasets[5].Count -eq 4)
        Assert-References $result
    }
    Run-Test '32 and 128 boundary batches preserve every selected target once per context source' {
        foreach ($size in @(32,33,128,129)) {
            $script:Batches.Clear()
            $script:Rows['TCPConnections:EstablishedTCP'] = @(foreach ($number in 1..$size) { New-Connection $number })
            $result = Invoke-Fixture
            $batchCount = [int][Math]::Ceiling([Math]::Min(128,$size) / 32.0)
            Assert-True ($script:Batches.Count -eq 2 * $batchCount -and $result.Budget.Processes.AttemptedCount -eq [Math]::Min(128,$size))
            Assert-References $result
        }
    }
    Run-Test 'unknown PID context precedes lower same-host PIDs and shares only one target' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @(
            (New-Connection 1 '127.0.0.1' '127.0.0.1'), (New-Connection 900),
            (New-Connection 500 '10.0.26.141' 'bad'), (New-Connection 500 '127.0.0.1' '127.0.0.1')
        )
        $result = Invoke-Fixture
        Assert-True (($script:Batches[0].Pids -join ',') -eq '900,500,1' -and $result.Datasets[5].Count -eq 3)
        Assert-References $result
    }
    Run-Test 'pre-first-query expiration records skipped unknown-free targets without CIM calls' {
        $script:ExpireAt = 1
        $result = Invoke-Fixture
        Assert-True ($script:Batches.Count -eq 0 -and $result.Budget.Processes.SkippedCount -eq 1 -and $result.Datasets[5].Status -eq 'Unavailable')
        Assert-True ($result.Datasets[5].TargetOutcomes[0].Outcome -eq 'Skipped' -and $null -eq $result.Datasets[5].TargetOutcomes[0].QueryStartedAt)
        Assert-References $result
    }
    Run-Test 'time skips and cap skips are disjoint with independent process and service outcomes' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @(foreach ($number in 1..129) { New-Connection $number })
        $script:ExpireAt = 2
        $result = Invoke-Fixture
        Assert-True ($result.Budget.Processes.AttemptedCount -eq 32 -and $result.Budget.Processes.SkippedCount -eq 97)
        Assert-True ($result.Budget.Services.AttemptedCount -eq 0 -and $result.Budget.Services.SkippedCount -eq 129)
        Assert-References $result
    }
    Run-Test 'denied process collection does not prevent running-service associations' {
        $script:CimModes.Processes = 'Denied'
        $script:ServiceRows['123'] = @([pscustomobject]@{ Name = 'Alpha'; DisplayName = 'Synthetic'; State = 'Running'; ProcessId = [uint32]123 })
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[5].Status -eq 'Unavailable' -and $result.Datasets[6].Status -eq 'Success' -and $result.Datasets[0].Items[0].RelatedServiceIds.Count -eq 1)
        Assert-True ((Get-AggregateStatus $result.Datasets) -eq 'Success')
        Assert-References $result
    }
    Run-Test 'shared PID services remain many-to-one candidate associations' {
        $script:ServiceRows['123'] = @(foreach ($name in @('Alpha','Beta')) { [pscustomobject]@{ Name = $name; DisplayName = 'Synthetic'; State = 'Running'; ProcessId = [uint32]123 } })
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[6].Count -eq 2 -and $result.Datasets[0].Items[0].RelatedServiceIds.Count -eq 2 -and $result.Datasets[5].Items[0].RelatedServiceIds.Count -eq 2)
        Assert-True ($result.Datasets[0].Items[0].ServiceAssociationStatus -eq 'UnconfirmedPidMatch')
        Assert-References $result
    }
    Run-Test 'empty service matches are not confused with unavailable service lookup' {
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].ServiceAssociationStatus -eq 'NoObservedMatch')
        $script:CimModes.Services = 'Denied'
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].ServiceAssociationStatus -eq 'Unknown' -and $result.Datasets[6].TargetOutcomes[0].Outcome -eq 'Unavailable')
    }
    Run-Test 'not-returned PIDs differ from denied or failed process lookups' {
        foreach ($mode in @('Empty','Denied','Failed')) {
            $script:CimModes.Processes = $mode; $result = Invoke-Fixture
            $expected = switch ($mode) { Empty { 'NotReturned' } Denied { 'Unavailable' } Failed { 'Failed' } }
            Assert-True ($result.Datasets[5].TargetOutcomes[0].Outcome -eq $expected -and $null -eq $result.Datasets[0].Items[0].ProcessRecordId)
            Assert-References $result
        }
    }
    Run-Test 'missing process metadata is retained as partial rather than invented' {
        $script:ProcessRows['123'] = [pscustomobject]@{ ProcessId = [uint32]123; Name = 'Synthetic'; CreationDate = $null }
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[5].Status -eq 'Partial' -and $null -eq $result.Datasets[5].Items[0].CreatedAt -and $result.Datasets[0].Items[0].ProcessAssociationStatus -eq 'UnconfirmedPidMatch')
        Assert-References $result
    }
    Run-Test 'denied process identity remains unavailable with an explicit target outcome' {
        $row = [pscustomobject]@{ Name = 'Synthetic'; CreationDate = [datetime]::UtcNow }
        $row | Add-Member ScriptProperty ProcessId { throw [UnauthorizedAccessException]::new('SYNTHETIC_SECRET') }
        $script:ProcessRows['123'] = $row
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[5].Status -eq 'Unavailable' -and $result.Datasets[5].TargetOutcomes[0].Outcome -eq 'Unavailable')
        Assert-True ($result.Datasets[6].Status -eq 'Success')
        Assert-References $result
    }
    Run-Test 'creation after observation flags possible PID reuse without dropping references' {
        $script:ProcessRows['123'] = [pscustomobject]@{ ProcessId = [uint32]123; Name = 'Synthetic'; CreationDate = [datetime]::UtcNow.AddDays(1) }
        $result = Invoke-Fixture
        Assert-True ($result.Datasets[0].Items[0].ProcessAssociationStatus -eq 'PossiblePidReuse' -and $result.Datasets[0].Items[0].ProcessRecordId)
        Assert-References $result
    }
    Run-Test 'zero and absent source PIDs do not become process targets' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @((New-Connection 0))
        $result = Invoke-Fixture; Assert-True ($result.Datasets[0].Items[0].ProcessAssociationStatus -eq 'NotApplicable' -and $script:Batches.Count -eq 0)
        $script:Rows['TCPConnections:EstablishedTCP'][0].PSObject.Properties.Remove('OwningProcess')
        $result = Invoke-Fixture; Assert-True ($null -eq $result.Datasets[0].Items[0].ProcessId -and $result.Datasets[5].Status -eq 'Partial')
    }
    Run-Test 'partially emitted CIM records survive later failures' {
        $script:CimModes.Processes = 'AfterOne'
        $result = Invoke-Fixture; Assert-True ($result.Datasets[5].Count -eq 1 -and $result.Datasets[5].Status -eq 'Partial')
        Assert-References $result
    }
    Run-Test 'all four exits and required-only aggregation follow standards' {
        Assert-True ((Get-InventoryExitCode Success $true) -eq 0 -and (Get-InventoryExitCode Failed $true) -eq 1 -and (Get-InventoryExitCode Partial $true) -eq 2 -and (Get-InventoryExitCode Unavailable $true) -eq 2 -and (Get-InventoryExitCode Success $false) -eq 3)
        $a = New-InventoryDataset A $true Success @() @(); $b = New-InventoryDataset B $true Failed @() @()
        Assert-True ((Get-AggregateStatus @($a,$b)) -eq 'Partial')
    }
    Run-Test 'nine reports round trip all exact dataset schemas and array references' {
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'network-relationships.json')) | ConvertFrom-Json
        Assert-True ($json.Output.Files.Count -eq 9 -and $json.Collection.Datasets.Count -eq 7 -and $report.Output.Status -eq 'Success')
        $layout = Get-RelationshipReportLayout
        foreach ($id in $layout.Keys) {
            $dataset = @($json.Collection.Datasets | Where-Object { $_.Id -eq $id })[0]
            $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory $layout[$id].File))
            Assert-True ($csv.Count -eq $dataset.Items.Count)
            foreach ($item in $dataset.Items) {
                $actual = ($item.PSObject.Properties.Name | Sort-Object) -join ','
                $expected = ($layout[$id].Columns | Sort-Object) -join ','
                Assert-True ($actual -eq $expected)
            }
        }
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'connections.csv'))
        $addressIds = ConvertFrom-Json -InputObject $csv[0].LocalAddressIds
        Assert-True ($addressIds.Count -eq 1)
        Assert-True ([IO.File]::ReadAllText((Join-Path $location.Directory 'summary.txt')).Contains('pending final verification'))
    }
    Run-Test 'empty and unavailable datasets still publish header-only CSV files' {
        foreach ($key in @($script:Rows.Keys)) { $script:Rows[$key] = @() }
        $script:Modes['Interfaces:IPv4'] = 'Denied'; $script:Modes['Interfaces:IPv6'] = 'Denied'
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'interfaces.csv'))
        Assert-True ($csv.Count -eq 0 -and [IO.File]::ReadAllText((Join-Path $location.Directory 'interfaces.csv')).StartsWith('"Id"'))
    }
    Run-Test 'JSON is published last and supporting text does not announce success' {
        $script:Written = New-Object 'System.Collections.Generic.List[string]'
        function script:Write-ProtectedReportText {
            param($Path,$Text,$AllowedSids)
            $script:Written.Add([IO.Path]::GetFileName($Path))
            [IO.File]::WriteAllText($Path,$Text)
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        Assert-True ($script:Written.Count -eq 9 -and $script:Written[8] -eq 'network-relationships.json.tmp')
    }
    Run-Test 'failed supporting writes leave failed live status and clean only owned artifacts' {
        function script:Write-ProtectedReportText { param($Path,$Text,$AllowedSids); throw 'Synthetic write failure' }
        $location = New-TestLocation; $report = New-TestReport $location
        $unrelated = Join-Path $location.Directory 'unrelated.txt'; [IO.File]::WriteAllText($unrelated,'Synthetic unrelated')
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed' -and -not [IO.File]::Exists((Join-Path $location.Directory 'network-relationships.json')))
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ([IO.File]::Exists($unrelated) -and @(Get-ChildItem -LiteralPath $location.Directory).Count -eq 1)
    }
    Run-Test 'identity verification rejects published JSON and cleanup removes it' {
        function script:Write-ProtectedReportText { param($Path,$Text,$AllowedSids); [IO.File]::WriteAllText($Path,$Text.Replace('SYNTHETIC-RUN','WRONG-RUN')) }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed')
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True (-not [IO.File]::Exists((Join-Path $location.Directory 'network-relationships.json')))
    }
    Run-Test 'changed protection blocks publication and reports unsafe cleanup' {
        $location = New-TestLocation; $report = New-TestReport $location; $script:ProtectionFailure = $true
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True (@($script:OutputIssues | Where-Object { $_.Code -eq 'CleanupFailed' }).Count -gt 0 -and $report.Output.Status -eq 'Failed')
    }
    Run-Test 'two unverifiable destinations stop before collection with exit three' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); throw 'Synthetic protection failure' }
        $output = @(Invoke-NetworkRelationships 'C:\SyntheticPrivate')
        Assert-True ($output[-1] -eq 3 -and $script:SourceCalls.Count -eq 0 -and $script:Batches.Count -eq 0)
    }
    Run-Test 'preflight fallback succeeds and collection is not repeated' {
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $script:Preparations++
            if ($script:Preparations -eq 1) { throw 'Synthetic preflight denial' }
            $script:LastLocation = New-TestLocation; $script:LastLocation
        }
        $output = @(Invoke-NetworkRelationships 'C:\SyntheticPrivate')
        Assert-True ($output[-1] -eq 0 -and $script:SourceCalls.Count -eq 9 -and $script:Preparations -eq 2)
        $json = [IO.File]::ReadAllText((Join-Path $script:LastLocation.Directory 'network-relationships.json')) | ConvertFrom-Json
        Assert-True ($json.Output.FallbackUsed -and $json.Output.Issues.Count -gt 0)
    }
    Run-Test 'report protection policy rejects broad readers and trusts Windows ancestors separately' {
        $sddl = 'O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)'
        $private = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        Assert-True (Test-RestrictedDescriptor $private $script:Allowed)
        $broad = [Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FR;;;BU)'))
        Assert-True (-not (Test-RestrictedDescriptor $broad $script:Allowed))
        $owner = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $ancestor = [Security.AccessControl.RawSecurityDescriptor]::new(('O:' + $owner + 'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'))
        Assert-True (Test-RestrictedDescriptor $ancestor $script:Allowed -Ancestor)
        Assert-True (-not (Test-RestrictedDescriptor $ancestor $script:Allowed))
    }
    Run-Test 'inherit-only disallowed principals cannot acquire report access' {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new('O:BAD:(A;;FA;;;BA)(A;OIIO;FR;;;BU)')
        Assert-True (-not (Test-RestrictedDescriptor $descriptor $script:Allowed))
    }
    Run-Test 'network and provider roots are rejected without remote filesystem access' {
        Assert-True (-not (Test-LocalNonReparsePath '\\synthetic-host\share' $false))
        Assert-True (-not (Test-LocalNonReparsePath 'FileSystem::C:\Synthetic' $false))
        Assert-Throws { & $definitions['New-ProtectedReportLocation'] '\\synthetic-host\share' 'Synthetic' 'Run' $script:Allowed }
    }
    Run-Test 'publication fallback reuses the snapshot and reports the actual fresh location' {
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $script:Preparations++; $script:LastLocation = New-TestLocation; $script:LastLocation
        }
        $script:WriteCalls = 0
        function script:Write-ProtectedReportText {
            param($Path,$Text,$AllowedSids)
            $script:WriteCalls++
            if ($script:WriteCalls -eq 1) { throw 'Synthetic first-location failure' }
            [IO.File]::WriteAllText($Path,$Text)
        }
        $output = @(Invoke-NetworkRelationships 'C:\SyntheticPrivate')
        Assert-True ($output[-1] -eq 0 -and $script:SourceCalls.Count -eq 9 -and $script:Preparations -eq 2)
        $json = [IO.File]::ReadAllText((Join-Path $script:LastLocation.Directory 'network-relationships.json')) | ConvertFrom-Json
        Assert-True ($json.Output.FallbackUsed -and $json.Output.Directory -eq $script:LastLocation.Directory -and $json.Output.Status -eq 'Success')
    }
    Run-Test 'total publication failure returns three without repeating collection' {
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $script:Preparations++; New-TestLocation
        }
        function script:Write-ProtectedReportText { param($Path,$Text,$AllowedSids); throw 'Synthetic total failure' }
        $output = @(Invoke-NetworkRelationships 'C:\SyntheticPrivate')
        Assert-True ($output[-1] -eq 3 -and $script:SourceCalls.Count -eq 9 -and $script:Preparations -eq 2)
    }
    Run-Test 'console and TXT limits do not truncate saved data' {
        $script:Rows['TCPConnections:EstablishedTCP'] = @(foreach ($number in 1..60) { New-Connection $number })
        $location = New-TestLocation; $report = New-TestReport $location
        $console = Get-NetworkRelationshipSummary $report
        $txt = Get-NetworkRelationshipSummary $report -Detailed
        Assert-True ([regex]::Matches($console,'(?m)^connection:[0-9]+:').Count -eq 20 -and [regex]::Matches($txt,'(?m)^connection:[0-9]+:').Count -eq 50)
        Publish-InventoryReports $report $location $script:Allowed
        Assert-True (@(Import-Csv -LiteralPath (Join-Path $location.Directory 'connections.csv')).Count -eq 60)
    }
    Run-Test 'sanitized issues and summaries never include exception secret markers' {
        $script:Modes['Routes:IPv4'] = 'Failed'; $script:CimModes.Processes = 'Denied'
        $location = New-TestLocation; $report = New-TestReport $location
        $text = ($report | ConvertTo-Json -Depth 12) + (Get-NetworkRelationshipSummary $report -Detailed)
        Assert-True (-not $text.Contains('SYNTHETIC_SECRET'))
        foreach ($issue in $script:CollectionIssues) { foreach ($field in @('DatasetId','Stage','Code','Message')) { Assert-True ($null -ne $issue.PSObject.Properties[$field]) } }
    }
}
finally {
    if ([IO.Directory]::Exists($script:TestRoot)) { [IO.Directory]::Delete($script:TestRoot,$true) }
}
Write-Host ('RESULT: ' + $script:Passed + ' passed; ' + $script:Failed + ' failed.')
if ($script:Failed -gt 0) { exit 1 }
exit 0
