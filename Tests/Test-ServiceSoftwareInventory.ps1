#requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free synthetic tests for Milestone 1.2C. Run in Windows PowerShell 5.1.
.DESCRIPTION
    Loads function ASTs only, never the collector's entry point. CIM, registry roots,
    and filesystem ACL probes are mocked. Writes synthetic reports to its own temp
    directory; does not enumerate real services/software or modify system settings.
#>
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'This synthetic suite requires 64-bit Windows; use Windows PowerShell 5.1 for compatibility validation.'
}
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Inventory\Get-ServiceSoftwareInventory.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Collector syntax parsing failed.' }
$definitions = @{}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    $definitions[$node.Name] = $node.Body.GetScriptBlock()
    Set-Item -Path ('Function:script:' + $node.Name) -Value $definitions[$node.Name]
}
$script:Passed = 0; $script:Failed = 0
$script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('CCDC-ServiceSoftware-Tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:TestRoot)
$script:UserSid = 'S-1-5-21-1-2-3-1001'
$script:Allowed = @($script:UserSid, 'S-1-5-18', 'S-1-5-32-544')

function Assert-True {
    param([bool]$Condition, [string]$Reason = 'Assertion failed')
    if (-not $Condition) { throw $Reason }
}

function Assert-Throws {
    param([scriptblock]$Action)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw 'An expected failure was not raised.'
}

function New-FakeKey {
    param([hashtable]$Values = @{}, [hashtable]$Children = @{}, [string[]]$Denied = @())
    $key = [pscustomobject]@{ Values = $Values; Children = $Children; Denied = $Denied; Disposed = $false }
    $key | Add-Member ScriptMethod GetValueNames { return ,[string[]]@($this.Values.Keys) }
    $key | Add-Member ScriptMethod GetSubKeyNames { return ,[string[]]@($this.Children.Keys) }
    $key | Add-Member ScriptMethod OpenSubKey {
        param($Name, $Writable)
        if ($Writable) { throw 'Writable registry access attempted.' }
        if ($this.Denied -contains $Name) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        return $this.Children[$Name]
    }
    $key | Add-Member ScriptMethod GetValue {
        param($Name, $Default, $Options)
        if ($this.Denied -contains $Name) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        return $this.Values[$Name]
    }
    $key | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
    $key
}

function New-FakeProcessRecord {
    param([uint32]$Number)
    [pscustomobject]@{
        ProcessId = $Number; Name = 'SyntheticProcess_' + $Number
        CreationDate = [datetime]::Parse('2000-01-01T00:00:00Z').ToUniversalTime()
        ExecutablePath = 'C:\Fixture\Process.exe'; CommandLine = 'Synthetic command SYNTHETIC_PROCESS_SECRET'
    }
}

function New-FakeEndpointRecord {
    param([uint32]$OwnerId, [int]$Port = 80, [string]$Address = '127.0.0.1')
    [pscustomobject]@{ OwningProcess = $OwnerId; LocalPort = $Port; LocalAddress = $Address }
}

function Invoke-TestProcessCollection {
    $services = Get-ServiceDataset
    $endpoints = Get-EndpointDataset
    $budget = [ordered]@{}
    $processes = Get-ProcessDataset $services $endpoints $budget
    [pscustomobject]@{ Services = $services; Endpoints = $endpoints; Processes = $processes; Budget = $budget }
}

function Invoke-TestFileCollection {
    param([bool]$Supported = $true)
    $script:FileHostSupported = $Supported
    if (-not $script:ProcessRows.ContainsKey('123')) {
        $process = New-FakeProcessRecord 123
        $process.ExecutablePath = 'C:\Fixture\Service.exe'
        $script:ProcessRows['123'] = $process
    }
    $result = Invoke-TestProcessCollection
    $files = Get-ExecutableDataset $result.Services $result.Processes $result.Budget
    $result | Add-Member -NotePropertyName Files -NotePropertyValue $files
    $result
}

function New-VirtualExecutableStream {
    param([string]$Path, [long]$Length, [byte[]]$Payload)
    $stream = [pscustomobject]@{ Path = $Path; Length = $Length; Position = [long]0; Payload = $Payload; Calls = 0; Disposed = $false }
    $stream | Add-Member ScriptMethod Read {
        param([byte[]]$Buffer, [int]$Offset, [int]$Count)
        $this.Calls++
        if ($script:ReadFailures.ContainsKey($this.Path) -and $this.Calls -ge $script:ReadFailures[$this.Path]) {
            $advance = [Math]::Min([long]$script:AdvanceBeforeReadFailure, [Math]::Min([long]$Count, $this.Length - $this.Position))
            $this.Position += $advance; $script:ObservedReadBytes += $advance
            throw [IO.IOException]::new('Synthetic read failure')
        }
        $countRead = [int][Math]::Min([long]$Count, $this.Length - $this.Position)
        if ($this.Payload.Length -gt 0) { [array]::Copy($this.Payload, [int]$this.Position, $Buffer, $Offset, $countRead) }
        else { [array]::Clear($Buffer, $Offset, $countRead) }
        $this.Position += $countRead; $script:ObservedReadBytes += $countRead
        if ($Count -gt $script:MaxReadRequest) { $script:MaxReadRequest = $Count }
        if ($script:StopAfterRead) { $script:FileElapsed = 60 }
        if ($script:GrowAfterRead) { $this.Length++ }
        if ($script:MutateAfterRead) { $script:ChangedFacts[$this.Path] = 1 }
        return $countRead
    }
    $stream | Add-Member ScriptMethod Dispose {
        $this.Disposed = $true; $script:DisposedStreams++
        if ($script:FailStreamDispose) { throw [IO.IOException]::new('Synthetic disposal failure') }
    }
    $stream
}

function Assert-FileReferences {
    param($Result)
    $ids = @($Result.Files.Items | ForEach-Object { $_.Id })
    Assert-True (@($ids | Select-Object -Unique).Count -eq $ids.Count)
    foreach ($source in @($Result.Services.Items) + @($Result.Processes.Items)) {
        if ($source.FileRecordId) { Assert-True ($ids -contains $source.FileRecordId) }
    }
    foreach ($file in $Result.Files.Items) {
        Assert-True ($file.SignatureMode -eq 'NotInvoked' -and $file.SignatureStatus -eq 'Skipped' -and $null -eq $file.SignerSubject)
        foreach ($reference in $file.SourceRefs) {
            $records = if ($reference.DatasetId -eq 'Services') { $Result.Services.Items } else { $Result.Processes.Items }
            $source = @($records | Where-Object { $_.Id -eq $reference.RecordId })[0]
            Assert-True ($null -ne $source -and $source.FileRecordId -eq $file.Id)
        }
    }
    foreach ($name in @('Files', 'Hashes', 'Signatures')) {
        $usage = $Result.Budget[$name]
        if ($null -ne $usage.CandidateCount) { Assert-True ($usage.CandidateCount -eq $usage.AttemptedCount + $usage.SkippedCount) }
        Assert-True ($usage.AttemptedCount -eq $usage.CompletedCount + $usage.UnusableCount)
    }
    Assert-True ($Result.Budget.HashBytesRead -le 536870912 -and $script:SignatureCalls -eq 0)
}

function Assert-ProcessReferences {
    param($Result)
    Assert-True ((Get-AggregateStatus $Result.Processes.Coverage) -eq $Result.Processes.Status)
    $serviceIds = @($Result.Services.Items | ForEach-Object { $_.Id })
    $endpointIds = @($Result.Endpoints.Items | ForEach-Object { $_.Id })
    $processIds = @($Result.Processes.Items | ForEach-Object { $_.Id })
    Assert-True (@($processIds | Select-Object -Unique).Count -eq $processIds.Count)
    Assert-True (@($endpointIds | Select-Object -Unique).Count -eq $endpointIds.Count)
    foreach ($item in @($Result.Services.Items) + @($Result.Endpoints.Items)) {
        if ($null -ne $item.ProcessRecordId) { Assert-True ($processIds -contains $item.ProcessRecordId) }
    }
    foreach ($item in $Result.Processes.Items) {
        foreach ($reference in $item.RelatedServiceIds) { Assert-True ($serviceIds -contains $reference) }
        foreach ($reference in $item.EndpointIds) { Assert-True ($endpointIds -contains $reference) }
    }
    foreach ($item in $Result.Endpoints.Items) {
        foreach ($reference in $item.RelatedServiceIds) { Assert-True ($serviceIds -contains $reference) }
    }
    foreach ($target in $Result.Processes.TargetOutcomes) {
        if ($null -ne $target.ProcessRecordId) { Assert-True ($processIds -contains $target.ProcessRecordId) }
    }
    foreach ($usage in $Result.Budget.Values) {
        if ($null -ne $usage.CandidateCount) { Assert-True ($usage.CandidateCount -eq $usage.AttemptedCount + $usage.SkippedCount) }
        Assert-True ($usage.AttemptedCount -eq $usage.CompletedCount + $usage.UnusableCount)
    }
}

function Reset-Fixture {
    foreach ($name in $definitions.Keys) { Set-Item -Path ('Function:script:' + $name) -Value $definitions[$name] }
    $script:CollectionIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:OutputIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:WarningCount = 0
    $script:CimMode = 'Success'; $script:CimCalls = 0
    $script:FakeServices = @([pscustomobject]@{
        Name = 'SyntheticService'; DisplayName = 'Synthetic service'; State = 'Running'
        StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 123
        PathName = '"C:\Fixture\Service.exe" --synthetic-token SYNTHETIC_SECRET_MARKER'
    })
    $script:FakeRoots = @{ Registry64 = New-FakeKey; Registry32 = New-FakeKey }
    $script:DeniedViews = @(); $script:ProtectionFailure = $false
    $script:MissingViews = @(); $script:FailedViews = @()
    $script:PreparationFailures = 0; $script:FailWrites = $false
    $script:WrittenNames = New-Object 'System.Collections.Generic.List[string]'
    $script:AncestorChecks = New-Object 'System.Collections.Generic.List[string]'
    $script:UnsafeAncestor = $null
    $script:AncestorOwners = @{}
    $script:ProcessMode = 'Success'; $script:ProcessBatchModes = @{}; $script:ProcessRows = @{}
    $script:ProcessBatches = New-Object 'System.Collections.Generic.List[object]'
    $script:EndpointModes = @{ TCP = 'Success'; UDP = 'Success' }
    $script:EndpointCalls = @{ TCP = 0; UDP = 0 }
    $script:FakeEndpoints = @{ TCP = @(); UDP = @() }
    $script:FileHostSupported = $false; $script:FileElapsed = 0; $script:ClockCalls = 0; $script:ExpireClockAt = 0
    $script:FileStates = @{}; $script:FileFacts = @{}; $script:FactCalls = @{}; $script:ChangedFacts = @{}
    $script:FilePayloads = @{}; $script:VersionFailures = @{}; $script:ReadFailures = @{}; $script:OpenFailures = @{}
    $script:AttributeCalls = New-Object 'System.Collections.Generic.List[string]'
    $script:ContentCalls = New-Object 'System.Collections.Generic.List[string]'
    $script:StopAfterRead = $false; $script:GrowAfterRead = $false; $script:MutateAfterRead = $false
    $script:AdvanceBeforeReadFailure = 0; $script:FailStreamDispose = $false
    $script:ObservedReadBytes = [long]0; $script:MaxReadRequest = 0; $script:DisposedStreams = 0; $script:SignatureCalls = 0
    function script:Test-FileEnrichmentHost { $script:FileHostSupported }
    function script:Get-WindowsDirectory { 'C:\Windows' }
    function script:Get-ExecutableDriveType {
        param($Root)
        if ($Root -eq 'Z:\') { return [IO.DriveType]::Network }
        [IO.DriveType]::Fixed
    }
    function script:Get-ExecutableAttributes {
        param($Path)
        $script:AttributeCalls.Add($Path)
        switch ($script:FileStates[$Path]) {
            'Missing' { throw [IO.FileNotFoundException]::new('Synthetic missing file') }
            'Denied' { throw [UnauthorizedAccessException]::new('Synthetic file denial') }
            'Failed' { throw [IO.IOException]::new('Synthetic filesystem failure') }
            'Reparse' { return [IO.FileAttributes]([int][IO.FileAttributes]::Directory -bor [int][IO.FileAttributes]::ReparsePoint) }
            'Directory' { return [IO.FileAttributes]::Directory }
        }
        if ($Path -match '\.[^\\]+$') { return [IO.FileAttributes]::Normal }
        [IO.FileAttributes]::Directory
    }
    function script:Get-ExecutableFacts {
        param($Path)
        $script:ContentCalls.Add('Facts:' + $Path)
        if (-not $script:FactCalls.ContainsKey($Path)) { $script:FactCalls[$Path] = 0 }
        $script:FactCalls[$Path]++
        $facts = if ($script:FileFacts.ContainsKey($Path)) { $script:FileFacts[$Path].PSObject.Copy() }
            else { [pscustomobject]@{ LengthBytes = [long]3; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' } }
        if ($script:ChangedFacts.ContainsKey($Path) -and $script:FactCalls[$Path] -ge $script:ChangedFacts[$Path]) {
            $facts.LastWriteTimeUtc = '2001-01-01T00:00:00.0000000Z'
        }
        $facts
    }
    function script:Get-ExecutableVersion {
        param($Path)
        $script:ContentCalls.Add('Version:' + $Path)
        if ($script:VersionFailures.ContainsKey($Path)) { throw [UnauthorizedAccessException]::new('Synthetic version denial') }
        [pscustomobject]@{ FileVersion = $null; ProductVersion = $null; CompanyName = $null; ProductName = $null }
    }
    function script:Open-ExecutableStream {
        param($Path)
        $script:ContentCalls.Add('Stream:' + $Path)
        if ($script:OpenFailures.ContainsKey($Path)) { throw [UnauthorizedAccessException]::new('Synthetic stream denial') }
        $length = if ($script:FileFacts.ContainsKey($Path)) { $script:FileFacts[$Path].LengthBytes } else { 3 }
        $payload = if ($script:FilePayloads.ContainsKey($Path)) { $script:FilePayloads[$Path] } else { [Text.Encoding]::UTF8.GetBytes('abc') }
        New-VirtualExecutableStream $Path $length $payload
    }
    function script:Get-FilePhaseElapsedSeconds {
        param($Clock)
        $script:ClockCalls++
        if ($script:ExpireClockAt -gt 0 -and $script:ClockCalls -ge $script:ExpireClockAt) { $script:FileElapsed = 60 }
        $script:FileElapsed
    }
    function script:Get-AuthenticodeSignature { $script:SignatureCalls++; throw 'Signature verification is prohibited.' }
    function script:Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string[]]$Property, [int]$OperationTimeoutSec, [string]$Filter)
        if ($ClassName -eq 'Win32_Process') {
            if (($Property -join ',') -ne 'ProcessId,Name,CreationDate,ExecutablePath,CommandLine' -or
                $OperationTimeoutSec -ne 30 -or $Filter -notmatch '^ProcessId = [0-9]+( OR ProcessId = [0-9]+)*$') { throw 'Unexpected process query.' }
            $numbers = [uint32[]]@([regex]::Matches($Filter, 'ProcessId = ([0-9]+)') | ForEach-Object { [uint32]$_.Groups[1].Value })
            if ($numbers.Count -gt 32 -or $numbers.Count -eq 0 -or $numbers -contains 0) { throw 'Unexpected process batch.' }
            $batchNumber = $script:ProcessBatches.Count
            $script:ProcessBatches.Add([pscustomobject]@{ Pids = $numbers; Filter = $Filter })
            $mode = $script:ProcessMode
            if ($script:ProcessBatchModes.ContainsKey($batchNumber)) { $mode = $script:ProcessBatchModes[$batchNumber] }
            if ($mode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic process denial') }
            if ($mode -eq 'Missing') { throw [System.Management.Automation.CommandNotFoundException]::new('Synthetic capability') }
            if ($mode -eq 'Failed') { throw [InvalidOperationException]::new('Synthetic process failure') }
            if ($mode -eq 'Empty') { return }
            foreach ($number in $numbers) {
                if ($script:ProcessRows.ContainsKey([string]$number)) { $script:ProcessRows[[string]$number] }
                else {
                    New-FakeProcessRecord $number
                }
                if ($mode -eq 'AfterOne') { throw [InvalidOperationException]::new('Synthetic late process failure') }
            }
            return
        }
        if ($ClassName -ne 'Win32_Service' -or $OperationTimeoutSec -ne 30) { throw 'Unexpected query.' }
        if ($Filter) { throw 'Unexpected service filter.' }
        $script:CimCalls++
        if ($script:CimMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        if ($script:CimMode -eq 'Missing') { throw [System.Management.Automation.CommandNotFoundException]::new('Synthetic capability') }
        if ($script:CimMode -eq 'Failed') { throw [InvalidOperationException]::new('Synthetic provider failure') }
        if ($script:CimMode -eq 'AfterOne') { Write-Output $script:FakeServices[0]; throw 'Synthetic late failure' }
        $script:FakeServices
    }
    function script:Get-FakeEndpointRows {
        [CmdletBinding()]
        param([string]$Protocol)
        $script:EndpointCalls[$Protocol]++
        $mode = $script:EndpointModes[$Protocol]
        if ($mode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic endpoint denial') }
        if ($mode -eq 'Missing') { throw [System.Management.Automation.CommandNotFoundException]::new('Synthetic endpoint capability') }
        if ($mode -eq 'Failed') { throw [InvalidOperationException]::new('Synthetic endpoint failure') }
        if ($mode -in @('NoMatch', 'GenericNoMatch', 'UnknownNotFound')) {
            $errorId = switch ($mode) {
                'NoMatch' { 'CmdletizationQuery_NotFound_State' }
                'GenericNoMatch' { 'CmdletizationQuery_NotFound' }
                default { 'SyntheticUnknownNotFound' }
            }
            $record = [System.Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Synthetic no match'),
                $errorId, [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            $PSCmdlet.ThrowTerminatingError($record)
        }
        foreach ($row in $script:FakeEndpoints[$Protocol]) {
            $row
            if ($mode -eq 'AfterOne') { throw [InvalidOperationException]::new('Synthetic late endpoint failure') }
        }
    }
    function script:Get-NetTCPConnection {
        [CmdletBinding()]
        param([string]$State)
        if ($State -ne 'Listen') { throw 'Unexpected TCP query.' }
        Get-FakeEndpointRows TCP
    }
    function script:Get-NetUDPEndpoint {
        [CmdletBinding()]
        param()
        Get-FakeEndpointRows UDP
    }
    function script:Open-UninstallRoot {
        param([string]$View)
        if ($script:DeniedViews -contains $View) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        if ($script:MissingViews -contains $View) { throw [PlatformNotSupportedException]::new('Synthetic capability') }
        if ($script:FailedViews -contains $View) { throw [InvalidOperationException]::new('Synthetic provider failure') }
        [pscustomobject]@{ BaseKey = (New-FakeKey); Key = $script:FakeRoots[$View] }
    }
    # Filesystem publication tests isolate ACL decisions; descriptor tests below
    # exercise the actual policy without changing any real ACL.
    function script:Assert-ProtectedReportPath {
        param([string]$Path, [string[]]$AllowedSids)
        if ($script:ProtectionFailure) { throw 'Synthetic protection failure' }
    }
    function script:Assert-ReportAncestors { param([string]$Path, [string[]]$AllowedSids) }
    function script:Get-Acl {
        [CmdletBinding()]
        param([string]$LiteralPath)
        $script:AncestorChecks.Add($LiteralPath)
        $owner = $script:UserSid
        if ($script:AncestorOwners.ContainsKey($LiteralPath)) { $owner = $script:AncestorOwners[$LiteralPath] }
        $sddl = 'O:' + $owner + 'G:SYD:(A;;FA;;;' + $owner + ')(A;;FA;;;' + $script:UserSid + ')(A;;FRFX;;;AU)'
        if ($LiteralPath -eq $script:UnsafeAncestor) { $sddl += '(A;;0x00000040;;;AU)' }
        $acl = [pscustomobject]@{ Descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl) }
        $acl | Add-Member ScriptMethod GetSecurityDescriptorBinaryForm {
            $bytes = New-Object byte[] $this.Descriptor.BinaryLength
            $this.Descriptor.GetBinaryForm($bytes, 0)
            return ,$bytes
        }
        $acl
    }
}

function Run-Test {
    param([string]$Name, [scriptblock]$Test)
    Reset-Fixture
    try { & $Test; $script:Passed++; Write-Host ('PASS: ' + $Name) }
    catch { $script:Failed++; Write-Host ('FAIL: ' + $Name + ' (' + $_.Exception.GetType().Name + ')') }
}

function New-TestLocation {
    $directory = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    $location = [pscustomobject]@{
        Directory = $directory; TemporaryPaths = [ordered]@{}
        CreatedPaths = (New-Object 'System.Collections.Generic.List[string]')
    }
    foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv', 'service-software.json')) {
        $path = Join-Path $directory ($name + '.tmp')
        [IO.File]::Open($path, [IO.FileMode]::CreateNew).Dispose()
        $location.TemporaryPaths[$name] = $path
        $location.CreatedPaths.Add($path)
    }
    $location
}

function New-TestReport {
    param($Location, [switch]$IncludeFiles)
    $services = Get-ServiceDataset
    $software = Get-SoftwareDataset
    $endpoints = Get-EndpointDataset
    $budget = [ordered]@{}
    $processes = Get-ProcessDataset $services $endpoints $budget
    foreach ($name in @('Files', 'Hashes', 'Signatures')) {
        $budget[$name] = [ordered]@{ CandidateCount = $null; AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0 }
    }
    $budget.HashBytesRead = 0; $budget.FilePhaseElapsedSeconds = 0
    $files = if ($IncludeFiles) { Get-ExecutableDataset $services $processes $budget }
        else { New-InventoryDataset ExecutableFiles $false Unavailable @() @('Synthetic file data is not supplied for legacy publication fixtures.') }
    $datasets = @($services, $software, $endpoints, $processes, $files)
    [ordered]@{
        SchemaVersion = '0.1.0'; ModuleId = 'service-software-inventory'; Version = '0.1.0'
        DevelopmentStage = 'Milestone 1.2C'; ReleaseReady = $false
        RunId = [guid]::NewGuid().ToString(); Hostname = 'SYNTHETIC_HOST'
        StartedAt = [datetime]::UtcNow.ToString('o'); CompletedAt = [datetime]::UtcNow.ToString('o')
        Collection = [ordered]@{ Status = Get-AggregateStatus $datasets; Datasets = $datasets; Issues = @($script:CollectionIssues.ToArray()); BudgetUsage = $budget }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{
            Status = 'Failed'; Directory = $Location.Directory; FallbackUsed = $false
            ProtectionStatus = 'VerifiedRestricted'
            Files = @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv', 'service-software.json'); Issues = @()
        }
    }
}

try {
    Run-Test 'status aggregation and all four exits' {
        $success = New-InventoryDataset A $true Success @() @()
        $failed = New-InventoryDataset B $true Failed @() @()
        $unavailable = New-InventoryDataset C $true Unavailable @() @()
        $optional = New-InventoryDataset D $false Failed @() @()
        Assert-True ((Get-AggregateStatus @($success, $optional)) -eq 'Success')
        Assert-True ((Get-AggregateStatus @($success, $failed)) -eq 'Partial')
        Assert-True ((Get-AggregateStatus @($failed, $unavailable)) -eq 'Failed')
        Assert-True ((Get-AggregateStatus @($unavailable)) -eq 'Unavailable')
        Assert-True ((Get-InventoryExitCode Success $true) -eq 0)
        Assert-True ((Get-InventoryExitCode Failed $true) -eq 1)
        Assert-True ((Get-InventoryExitCode Partial $true) -eq 2)
        Assert-True ((Get-InventoryExitCode Unavailable $true) -eq 2)
        Assert-True ((Get-InventoryExitCode Success $false) -eq 3)
    }
    Run-Test 'zero/one/many JSON arrays and unknown counts' {
        foreach ($size in @(0, 1, 2)) {
            $items = @(for ($i = 0; $i -lt $size; $i++) { [pscustomobject]@{ Id = $i } })
            $dataset = New-InventoryDataset A $true Success $items @()
            $json = $dataset | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            Assert-True ($json.Items -is [array] -and $json.Items.Count -eq $size -and $json.Count -eq $size)
        }
        $missing = New-InventoryDataset A $true Unavailable @() @()
        Assert-True ($null -eq $missing.Count -and $missing.Items.Count -eq 0)
    }
    Run-Test 'all service states, PID zero, raw-only separation' {
        $stopped = $script:FakeServices[0].PSObject.Copy()
        $stopped.Name = 'Stopped'; $stopped.State = 'Stopped'; $stopped.StartMode = 'Disabled'; $stopped.ProcessId = 0
        $manual = $stopped.PSObject.Copy()
        $manual.Name = 'Manual'; $manual.StartMode = 'Manual'
        $script:FakeServices += @($stopped, $manual)
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 3)
        Assert-True ($data.Items[1].ProcessId -eq 0 -and $null -eq $data.Items[0].ExecutablePath)
        Assert-True ($data.Items[0].RawCommandLine.Contains('SYNTHETIC_SECRET_MARKER'))
    }
    Run-Test 'successful empty service query' {
        $script:FakeServices = @()
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0 -and $data.Items.Count -eq 0)
    }
    Run-Test 'denied, genuine failure, and late partial service queries' {
        $script:FakeServices[0].StartName = $null
        foreach ($mode in @('Denied', 'Missing', 'Failed', 'AfterOne')) {
            $script:CimMode = $mode
            $data = Get-ServiceDataset
            $expectedByMode = @{ Denied = 'Unavailable'; Missing = 'Unavailable'; Failed = 'Failed'; AfterOne = 'Partial' }
            $expected = $expectedByMode[$mode]
            Assert-True ($data.Status -eq $expected)
            $codeByMode = @{ Denied = 'AccessDenied'; Missing = 'CapabilityMissing'; Failed = 'QueryFailed'; AfterOne = 'QueryFailed' }
            Assert-True ($script:CollectionIssues[$script:CollectionIssues.Count - 1].Code -eq $codeByMode[$mode])
            if ($mode -ne 'AfterOne') { Assert-True ($null -eq $data.Count) }
            else { Assert-True ($data.Count -eq 1 -and $data.Items[0].RecordStatus -eq 'Success' -and $null -eq $data.Items[0].ServiceAccount) }
        }
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'RecordReadFailed' }).Count -eq 0)
    }
    Run-Test 'wrapped exception and CIM error identities use stable codes' {
        $denial = [InvalidOperationException]::new('Synthetic wrapper', [UnauthorizedAccessException]::new('Synthetic secret'))
        $record = [System.Management.Automation.ErrorRecord]::new($denial, 'Synthetic', 'NotSpecified', $null)
        Assert-True ((Get-CollectionFailure $record).Code -eq 'AccessDenied')
        foreach ($nativeCode in @('AccessDenied', 'InvalidClass', 'InvalidNamespace', 'NotSupported')) {
            $exception = [Exception]::new('Synthetic secret')
            $exception | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue $nativeCode
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'Synthetic', 'NotSpecified', $null)
            $problem = Get-CollectionFailure $record
            $expected = if ($nativeCode -eq 'AccessDenied') { 'AccessDenied' } else { 'CapabilityMissing' }
            Assert-True ($problem.Status -eq 'Unavailable' -and $problem.Code -eq $expected)
        }
    }
    Run-Test 'nullable service account is successful, empty command is not unknown' {
        $script:FakeServices[0].StartName = $null
        foreach ($command in @($script:FakeServices[0].PathName, '')) {
            $script:FakeServices[0].PathName = $command
            $data = Get-ServiceDataset
            Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 1 -and $data.Items[0].RecordStatus -eq 'Success')
            Assert-True ($null -eq $data.Items[0].ServiceAccount -and $script:CollectionIssues.Count -eq 0)
            $expected = if ($command -ceq '') { 'Empty' } else { 'Collected' }
            Assert-True ($data.Items[0].RawCommandLineState -eq $expected -and $data.Items[0].RawCommandLine -ceq $command)
        }
    }
    Run-Test 'missing properties and other required null metadata remain partial' {
        $original = $script:FakeServices[0]
        foreach ($mode in @('Missing', 'Null')) {
            foreach ($field in @('DisplayName', 'State', 'StartMode', 'StartName', 'ProcessId', 'PathName')) {
                if ($mode -eq 'Null' -and $field -eq 'StartName') { continue }
                $row = $original.PSObject.Copy()
                if ($mode -eq 'Missing') { $row.PSObject.Properties.Remove($field) }
                else { $row.$field = $null }
                $script:FakeServices = @($row)
                $before = $script:CollectionIssues.Count
                $data = Get-ServiceDataset
                Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1 -and $data.Items[0].RecordStatus -eq 'Partial')
                Assert-True ($script:CollectionIssues.Count -eq $before + 1)
                $issue = $script:CollectionIssues[$before]
                Assert-True ($issue.Code -eq 'RecordReadFailed' -and $issue.DatasetId -eq 'Services' -and $issue.Stage -eq 'Parse')
                if ($field -eq 'PathName') {
                    Assert-True ($null -eq $data.Items[0].RawCommandLine -and $data.Items[0].RawCommandLineState -eq 'Unavailable')
                }
            }
        }
    }
    Run-Test 'unreadable account and required properties remain partial with access issues' {
        $ErrorActionPreference = 'Continue'
        $original = $script:FakeServices[0]
        foreach ($field in @('StartName', 'State')) {
            $row = $original.PSObject.Copy()
            $row | Add-Member -MemberType ScriptProperty -Name $field -Value { throw [UnauthorizedAccessException]::new('Synthetic denial') } -Force
            $script:FakeServices = @($row)
            $before = $script:CollectionIssues.Count
            $data = Get-ServiceDataset
            Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1 -and $data.Items[0].RecordStatus -eq 'Partial')
            Assert-True ($script:CollectionIssues.Count -eq $before + 1 -and $script:CollectionIssues[$before].Code -eq 'AccessDenied')
            Assert-True (-not $script:CollectionIssues[$before].Message.Contains('Synthetic denial'))
        }
    }
    Run-Test 'invalid service field types are not silently coerced' {
        $original = $script:FakeServices[0]
        foreach ($fixture in @(
            @{ Field = 'DisplayName'; Value = 123 }, @{ Field = 'StartName'; Value = 123 },
            @{ Field = 'PathName'; Value = @('one', 'two') }, @{ Field = 'ProcessId'; Value = '123' },
            @{ Field = 'ProcessId'; Value = $true }, @{ Field = 'ProcessId'; Value = 1.5 },
            @{ Field = 'ProcessId'; Value = -1 }, @{ Field = 'ProcessId'; Value = [uint64]::MaxValue }
        )) {
            $row = $original.PSObject.Copy()
            $row.($fixture.Field) = $fixture.Value
            $script:FakeServices = @($row)
            $before = $script:CollectionIssues.Count
            $data = Get-ServiceDataset
            Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1)
            Assert-True ($script:CollectionIssues.Count -eq $before + 1 -and $script:CollectionIssues[$before].Code -eq 'RecordReadFailed')
        }
        $row = $original.PSObject.Copy(); $row.Name = 123
        $script:FakeServices = @($row)
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Failed' -and $null -eq $data.Count -and $data.Items.Count -eq 0)
    }
    Run-Test 'nullable service account survives report serialization and count checks' {
        $script:FakeServices[0].StartName = $null
        $second = $script:FakeServices[0].PSObject.Copy()
        $second.Name = 'SecondSyntheticService'; $second.StartName = 'LocalSystem'
        $script:FakeServices += $second
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')) | ConvertFrom-Json
        $services = @($json.Collection.Datasets | Where-Object { $_.Id -eq 'Services' })[0]
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'services.csv'))
        Assert-True ($services.Status -eq 'Success' -and $services.Count -eq 2 -and $services.Items.Count -eq 2 -and $csv.Count -eq 2)
        Assert-True ($null -eq $services.Items[0].ServiceAccount -and [string]::IsNullOrEmpty($csv[0].ServiceAccount))
        Assert-True ($services.Items[1].ServiceAccount -eq 'LocalSystem' -and $csv[1].ServiceAccount -eq 'LocalSystem')
        Assert-True (@($json.Collection.Issues).Count -eq 0 -and $report.Output.Status -eq 'Success')
    }
    Run-Test 'both software views preserve duplicates and missing values' {
        foreach ($view in @('Registry64', 'Registry32')) {
            $script:FakeRoots[$view] = New-FakeKey -Children @{ Duplicate = New-FakeKey -Values @{ DisplayName = 'Synthetic app' } }
        }
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 2)
        Assert-True ($data.Items[0].Id -ne $data.Items[1].Id)
        Assert-True ($data.Items[0].MissingValueNames.Count -eq 2)
    }
    Run-Test 'absent uninstall roots are successful empty sources' {
        $script:FakeRoots = @{ Registry64 = $null; Registry32 = $null }
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0)
    }
    Run-Test 'denied view is partial overall, not successful empty' {
        $script:DeniedViews = @('Registry64')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Coverage[0].Status -eq 'Unavailable')
        Assert-True ($script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'unavailable registry capability differs from genuine view failure' {
        $script:MissingViews = @('Registry64', 'Registry32')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Unavailable' -and $null -eq $data.Count)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -ne 'CapabilityMissing' }).Count -eq 0)
        $script:MissingViews = @(); $script:FailedViews = @('Registry64', 'Registry32')
        $before = $script:CollectionIssues.Count
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Failed' -and $null -eq $data.Count)
        Assert-True ($script:CollectionIssues[$before].Code -eq 'QueryFailed')
    }
    Run-Test 'denied child registration retains identity and one access issue' {
        $script:FakeRoots.Registry64 = New-FakeKey -Children @{ SyntheticKey = New-FakeKey } -Denied @('SyntheticKey')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1)
        Assert-True ($data.Items[0].Id -eq 'software:Registry64:SyntheticKey' -and $data.Items[0].RecordStatus -eq 'Partial')
        Assert-True ($script:CollectionIssues.Count -eq 1 -and $script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'denied software value differs from absent value' {
        $key = New-FakeKey -Values @{ DisplayName = 'Synthetic'; Publisher = 'Synthetic publisher' } -Denied @('Publisher')
        $row = Read-SoftwareRegistration Registry64 SyntheticKey $key
        Assert-True ($row.RecordStatus -eq 'Partial' -and $null -eq $row.Publisher)
        Assert-True ($row.MissingValueNames -contains 'DisplayVersion' -and $row.MissingValueNames -notcontains 'Publisher')
        Assert-True ($script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'PowerShell 5.1 enum masks handle untrusted ACEs with varied inheritance flags' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')'
        foreach ($flags in @('', 'OI', 'CI', 'OICI', 'OICIIO')) {
            $read = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;' + $flags + ';FR;;;AU)'))
            Assert-True ($read.DiscretionaryAcl[1].AceFlags -is [System.Security.AccessControl.AceFlags])
            Assert-True (-not (Test-RestrictedDescriptor $read $script:Allowed))
            Assert-True (Test-RestrictedDescriptor $read $script:Allowed -Ancestor)
            $write = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;' + $flags + ';FA;;;AU)'))
            Assert-True (-not (Test-RestrictedDescriptor $write $script:Allowed))
            $expectedAncestor = $flags -eq 'OICIIO'
            Assert-True ((Test-RestrictedDescriptor $write $script:Allowed -Ancestor) -eq $expectedAncestor)
        }
    }
    Run-Test 'creator-owner inheritance template is not an effective broad grant' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')'
        $template = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;OICIIO;FA;;;CO)'))
        Assert-True (Test-RestrictedDescriptor $template $script:Allowed)
        $effective = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FA;;;CO)'))
        Assert-True (-not (Test-RestrictedDescriptor $effective $script:Allowed))
        $broadTemplate = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;OICIIO;FR;;;AU)'))
        Assert-True (-not (Test-RestrictedDescriptor $broadTemplate $script:Allowed))
    }
    Run-Test 'ancestors permit traversal but reject replacement and DACL/owner rights' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')'
        $readOnly = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FRFX;;;AU)'))
        Assert-True (Test-RestrictedDescriptor $readOnly $script:Allowed -Ancestor)
        foreach ($mask in @('0x00000040', '0x00010000', '0x00040000', '0x00080000', '0x10000000', '0x40000000')) {
            $unsafe = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;' + $mask + ';;;AU)'))
            Assert-True (-not (Test-RestrictedDescriptor $unsafe $script:Allowed -Ancestor))
        }
        $unknownOwner = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl.Replace(('O:' + $script:UserSid), 'O:AU')))
        Assert-True (-not (Test-RestrictedDescriptor $unknownOwner $script:Allowed -Ancestor))
    }
    Run-Test 'Windows ancestor ownership does not broaden report access' {
        $servicingSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        foreach ($owner in @($script:UserSid, 'S-1-5-18', 'S-1-5-32-544', $servicingSid)) {
            $sddl = 'O:' + $owner + 'G:SYD:(A;;FA;;;' + $owner + ')(A;;FA;;;' + $servicingSid + ')(A;;FRFX;;;BU)(A;;0x00000004;;;AU)'
            $normal = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
            Assert-True (Test-RestrictedDescriptor $normal $script:Allowed -Ancestor)
            Assert-True (-not (Test-RestrictedDescriptor $normal $script:Allowed))
            $unsafe = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;0x00000040;;;AU)'))
            Assert-True (-not (Test-RestrictedDescriptor $unsafe $script:Allowed -Ancestor))
        }
        # Even an otherwise private DACL cannot give a report an unexpected owner
        # or grant its contents to the ancestor-only servicing principal.
        $private = 'G:SYD:(A;;FA;;;' + $script:UserSid + ')(A;;FA;;;SY)(A;;FA;;;BA)'
        $servicingOwner = [System.Security.AccessControl.RawSecurityDescriptor]::new(('O:' + $servicingSid + $private))
        Assert-True (-not (Test-RestrictedDescriptor $servicingOwner $script:Allowed))
        $servicingRead = [System.Security.AccessControl.RawSecurityDescriptor]::new(('O:' + $script:UserSid + $private + '(A;;FR;;;' + $servicingSid + ')'))
        Assert-True (-not (Test-RestrictedDescriptor $servicingRead $script:Allowed))
    }
    Run-Test 'existing ancestors are checked before creating a missing report tree' {
        Set-Item -Path Function:script:Assert-ReportAncestors -Value $definitions['Assert-ReportAncestors']
        $missing = Join-Path $script:TestRoot 'MissingRoot\Host\Run'
        $script:AncestorOwners[[IO.Path]::GetPathRoot($missing)] = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $script:AncestorOwners[[IO.Directory]::GetParent($script:TestRoot).FullName] = 'S-1-5-18'
        $script:AncestorOwners[$script:TestRoot] = 'S-1-5-32-544'
        Assert-ReportAncestors $missing $script:Allowed
        Assert-True ($script:AncestorChecks -contains $script:TestRoot)
        Assert-True ($script:AncestorChecks -contains [IO.Path]::GetPathRoot($missing))
        Assert-True (-not [IO.Directory]::Exists((Join-Path $script:TestRoot 'MissingRoot')))
        $script:UnsafeAncestor = $script:TestRoot
        Assert-Throws { Assert-ReportAncestors $missing $script:Allowed }
    }
    Run-Test 'local path checks reject files used as intermediate directories' {
        $file = Join-Path $script:TestRoot 'IntermediateFile'
        [IO.File]::WriteAllText($file, 'Synthetic fixture')
        Assert-True (-not (Test-LocalNonReparsePath (Join-Path $file 'MissingChild') $false))
        Assert-True (-not (Test-LocalNonReparsePath '\\SYNTHETIC\Share' $false))
    }
    Run-Test 'ACL allowlist, broad access, unknown owner, null DACL' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')(A;;FA;;;SY)(A;;FA;;;BA)'
        $safe = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        Assert-True (Test-RestrictedDescriptor $safe $script:Allowed)
        $broad = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FR;;;AU)'))
        Assert-True (-not (Test-RestrictedDescriptor $broad $script:Allowed))
        $other = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl.Replace(('O:' + $script:UserSid), 'O:AU')))
        Assert-True (-not (Test-RestrictedDescriptor $other $script:Allowed))
        $nullDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
            [System.Security.Principal.SecurityIdentifier]::new($script:UserSid), $null, $null, $null)
        Assert-True (-not (Test-RestrictedDescriptor $nullDacl $script:Allowed))
    }
    Run-Test 'structured issues do not serialize native exception text' {
        $script:CimMode = 'Denied'; $null = Get-ServiceDataset
        $issue = $script:CollectionIssues[0]
        Assert-True ($issue.DatasetId -eq 'Services' -and $issue.Stage -eq 'Collect' -and $issue.Code -eq 'AccessDenied')
        Assert-True (-not $issue.Message.Contains('Synthetic denial'))
    }
    Run-Test 'report round trip, CSV headers, Unicode and command-line confinement' {
        $script:FakeServices[0].DisplayName = "Synthetic, quoted `"display`"`nsecond line " + [char]0x03A9
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')) | ConvertFrom-Json
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'services.csv'))
        Assert-True ($json.RunId -eq $report.RunId -and $csv.Count -eq 1)
        Assert-True ($report.Output.Status -eq 'Success' -and $json.Output.Status -eq 'Success')
        $summary = [IO.File]::ReadAllText((Join-Path $location.Directory 'summary.txt'))
        Assert-True ($summary.Contains('not certified by this supporting report') -and -not $summary.Contains('Report-save status: Success'))
        Assert-True ($csv[0].DisplayName -ceq $script:FakeServices[0].DisplayName)
        foreach ($name in @('summary.txt','services.csv','software.csv')) {
            Assert-True (-not [IO.File]::ReadAllText((Join-Path $location.Directory $name)).Contains('SYNTHETIC_SECRET_MARKER'))
        }
        Assert-True ([IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')).Contains('SYNTHETIC_SECRET_MARKER'))
        Assert-True (([IO.File]::ReadAllLines((Join-Path $location.Directory 'software.csv'))).Count -eq 1)
    }
    Run-Test 'publication order and failure before canonical JSON' {
        function script:Write-ProtectedReportText {
            param($Path, $Text, $AllowedSids)
            $name = [IO.Path]::GetFileName($Path)
            $script:WrittenNames.Add($name)
            if ($name -eq 'software.csv.tmp') { throw 'Synthetic write failure' }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed')
        Assert-True (-not [IO.File]::Exists((Join-Path $location.Directory 'service-software.json')))
        # Surviving supporting files must not certify the incomplete report set.
        $script:ProtectionFailure = $true
        Remove-IncompleteReportFiles $location $script:Allowed
        $summary = [IO.File]::ReadAllText((Join-Path $location.Directory 'summary.txt'))
        Assert-True ($summary.Contains('not certified by this supporting report') -and -not $summary.Contains('Report-save status: Success'))
        $script:ProtectionFailure = $false
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ((Get-ChildItem -LiteralPath $location.Directory -Force).Count -eq 0)
        Assert-True (($script:WrittenNames.ToArray() -join ',') -eq 'summary.txt.tmp,services.csv.tmp,software.csv.tmp')
    }
    Run-Test 'candidate JSON does not mark live output successful during publication' {
        function script:Write-ProtectedReportText {
            param($Path, $Text, $AllowedSids)
            Assert-True ($script:PublishingReport.Output.Status -eq 'Failed')
            $script:WrittenNames.Add([IO.Path]::GetFileName($Path))
            if ([IO.Path]::GetFileName($Path) -eq 'service-software.json.tmp') {
                foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv')) {
                    Assert-True ([IO.File]::Exists((Join-Path ([IO.Path]::GetDirectoryName($Path)) $name)))
                }
                Assert-True (($Text | ConvertFrom-Json).Output.Status -eq 'Success')
                $script:CandidateChecked = $true
                throw 'Synthetic canonical write failure'
            }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $location = New-TestLocation; $script:PublishingReport = New-TestReport $location
        $script:CandidateChecked = $false
        Assert-Throws { Publish-InventoryReports $script:PublishingReport $location $script:Allowed }
        Assert-True ($script:PublishingReport.Output.Status -eq 'Failed' -and $script:CandidateChecked)
        Assert-True (($script:WrittenNames.ToArray() -join ',') -eq 'summary.txt.tmp,services.csv.tmp,software.csv.tmp,network-endpoints.csv.tmp,processes.csv.tmp,files.csv.tmp,service-software.json.tmp')
    }
    Run-Test 'post-promotion failure retains failed status and cleans canonical JSON first' {
        function script:Assert-ProtectedReportPath {
            param($Path, $AllowedSids)
            if ([IO.Path]::GetFileName($Path) -eq 'service-software.json') { throw 'Synthetic final verification failure' }
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed')
        Assert-True ([IO.File]::Exists((Join-Path $location.Directory 'service-software.json')))
        $script:CleanupChecks = New-Object 'System.Collections.Generic.List[string]'
        function script:Assert-ProtectedReportPath {
            param($Path, $AllowedSids)
            $script:CleanupChecks.Add([IO.Path]::GetFileName($Path))
        }
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ($script:CleanupChecks[1] -eq 'service-software.json')
        Assert-True ((Get-ChildItem -LiteralPath $location.Directory -Force).Count -eq 0)
    }
    Run-Test 'protection failure prevents writes and cleanup records its refusal' {
        $location = New-TestLocation; $report = New-TestReport $location
        $script:ProtectionFailure = $true
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        foreach ($path in $location.CreatedPaths) { Assert-True ((Get-Item -LiteralPath $path).Length -eq 0) }
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ($script:OutputIssues.Count -gt 0)
    }
    Run-Test 'both output preparations rejected before service/software collection' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); throw 'Synthetic unverified output' }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 3 -and $script:CimCalls -eq 0)
        Assert-True ($script:ProcessBatches.Count -eq 0 -and $script:EndpointCalls.TCP -eq 0 -and $script:EndpointCalls.UDP -eq 0)
    }
    Run-Test 'preflight fallback, development placeholders, and saved exit 2' {
        # Retain the partial-collection exit test now that processes are implemented.
        $script:ProcessMode = 'Denied'
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $script:PreparationFailures++
            if ($script:PreparationFailures -eq 1) { throw 'Synthetic primary denial' }
            $script:LastLocation = New-TestLocation
            $script:LastLocation
        }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 2 -and $script:CimCalls -eq 1)
        $report = [IO.File]::ReadAllText((Join-Path $script:LastLocation.Directory 'service-software.json')) | ConvertFrom-Json
        $processes = @($report.Collection.Datasets | Where-Object { $_.Id -eq 'Processes' })[0]
        Assert-True ($processes.Required -and $processes.Status -eq 'Unavailable' -and $null -eq $processes.Count)
        Assert-True ($report.Output.FallbackUsed -and -not $report.ReleaseReady)
        Assert-True ($report.Output.Files.Count -eq 7)
        $files = @($report.Collection.Datasets | Where-Object { $_.Id -eq 'ExecutableFiles' })[0]
        Assert-True ($files.Status -eq 'Unavailable' -and $null -eq $files.Count)
    }
    Run-Test 'total publication failure returns 3, never a saved success' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); New-TestLocation }
        function script:Write-ProtectedReportText { param($Path,$Text,$AllowedSids); throw 'Synthetic persistent write failure' }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 3)
        Assert-True (-not (($result[0..($result.Count-2)] -join ' ').Contains('Report-save status: Success')))
    }
    Run-Test 'write failure falls back without collecting twice' {
        $script:ProcessMode = 'Denied'
        $script:Locations = New-Object 'System.Collections.Generic.List[object]'
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $location = New-TestLocation
            $script:Locations.Add($location)
            $location
        }
        function script:Write-ProtectedReportText {
            param($Path,$Text,$AllowedSids)
            if (-not $script:FailWrites) { $script:FailWrites = $true; throw 'Synthetic first write failure' }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 2 -and $script:CimCalls -eq 1 -and $script:Locations.Count -eq 2)
        Assert-True ($script:ProcessBatches.Count -eq 1 -and $script:EndpointCalls.TCP -eq 1 -and $script:EndpointCalls.UDP -eq 1)
        $report = [IO.File]::ReadAllText((Join-Path $script:Locations[1].Directory 'service-software.json')) | ConvertFrom-Json
        Assert-True ($report.Output.FallbackUsed -and @($report.Output.Issues).Count -gt 0)
        Assert-True ((Get-ChildItem -LiteralPath $script:Locations[0].Directory -Force).Count -eq 0)
    }
    Run-Test 'provider scalar strings UInt32 and DateTime retain their types and values' {
        $date = [datetime]::Parse('2000-01-01T00:00:00Z').ToUniversalTime()
        $source = [pscustomobject]@{ Text = 'Synthetic text'; Number = [uint32]123; Zero = [uint32]0; Date = $date; Empty = '' }
        $text = Read-ObservedProperty $source Text
        $number = Read-ObservedProperty $source Number
        $zero = Read-ObservedProperty $source Zero
        $time = Read-ObservedProperty $source Date
        $empty = Read-ObservedProperty $source Empty
        Assert-True ($text -is [string] -and $text -ceq 'Synthetic text')
        Assert-True ($number -is [uint32] -and $number -eq 123 -and $zero -is [uint32] -and $zero -eq 0)
        Assert-True ($time -is [datetime] -and $time -eq $date -and $time.Kind -eq $date.Kind)
        Assert-True ($empty -is [string] -and $empty -ceq '')
    }
    Run-Test 'present null provider values remain null while absent properties throw' {
        $source = [pscustomobject]@{ Present = $null }
        $value = Read-ObservedProperty $source Present
        Assert-True ($null -eq $value)
        Assert-Throws { $null = Read-ObservedProperty $source Absent }
    }
    Run-Test 'wrapped provider access denials remain exceptions and structured access issues' {
        $source = New-FakeEndpointRecord 123
        $source | Add-Member ScriptProperty LocalAddress {
            throw [InvalidOperationException]::new('Synthetic wrapper', [UnauthorizedAccessException]::new('Synthetic protected value'))
        } -Force
        $caught = $null
        try { $null = Read-ObservedProperty $source LocalAddress } catch { $caught = $_ }
        Assert-True ($null -ne $caught)
        $failure = Get-CollectionFailure $caught RecordReadFailed
        Assert-True ($failure.Status -eq 'Unavailable' -and $failure.Code -eq 'AccessDenied')
        $script:FakeEndpoints.TCP = @($source)
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Endpoints.Status -eq 'Partial' -and $result.Endpoints.Items[0].RecordStatus -eq 'Partial')
        $issue = @($script:CollectionIssues | Where-Object { $_.DatasetId -eq 'NetworkEndpoints' -and $_.Code -eq 'AccessDenied' })
        Assert-True ($issue.Count -eq 1 -and -not $issue[0].Message.Contains('Synthetic protected value'))
        Assert-True ($result.Processes.Status -eq 'Success')
    }
    Run-Test 'array-valued provider fields are rejected before singleton scalar coercion' {
        $date = [datetime]::Parse('2000-01-01T00:00:00Z').ToUniversalTime()
        $source = [pscustomobject]@{
            Text = [string[]]@('one'); Number = [uint32[]]@(123); Date = [datetime[]]@($date)
            Empty = [object[]]@(); Multiple = [string[]]@('one', 'two')
        }
        foreach ($name in @('Text', 'Number', 'Date', 'Empty', 'Multiple')) {
            Assert-Throws { $null = Read-ObservedProperty $source $name }
        }
        $endpoint = New-FakeEndpointRecord 123; $endpoint.LocalPort = [uint32[]]@(80)
        $script:FakeEndpoints.TCP = @($endpoint)
        $process = New-FakeProcessRecord 123; $process.Name = [string[]]@('SyntheticProcess_123')
        $script:ProcessRows['123'] = $process
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Endpoints.Status -eq 'Partial' -and $null -eq $result.Endpoints.Items[0].LocalPort)
        Assert-True ($result.Processes.Status -eq 'Partial' -and $null -eq $result.Processes.Items[0].Name)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'RecordReadFailed' }).Count -eq 2)
    }
    Run-Test 'valid scalar endpoint and process metadata are retained as successful records' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 123 443))
        $script:FakeEndpoints.UDP = @((New-FakeEndpointRecord 123 53 '::'))
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Endpoints.Status -eq 'Success' -and $result.Endpoints.Count -eq 2)
        Assert-True (@($result.Endpoints.Items | Where-Object { $_.RecordStatus -ne 'Success' }).Count -eq 0)
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 1 -and $result.Processes.Items[0].RecordStatus -eq 'Success')
        Assert-True ($result.Processes.Items[0].Name -is [string] -and $result.Processes.Items[0].ProcessId -is [uint32])
        Assert-True ($script:CollectionIssues.Count -eq 0)
        Assert-ProcessReferences $result
    }
    Run-Test 'empty and known no-match endpoint sources are successful without invented records' {
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0 -and $data.Items.Count -eq 0)
        Assert-True ($data.Coverage.Count -eq 2 -and $script:EndpointCalls.TCP -eq 1 -and $script:EndpointCalls.UDP -eq 1)
        $script:EndpointModes.TCP = 'NoMatch'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0 -and $script:CollectionIssues.Count -eq 0)
        $script:EndpointModes.TCP = 'GenericNoMatch'; $script:EndpointModes.UDP = 'GenericNoMatch'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0 -and $script:CollectionIssues.Count -eq 0)
        $script:EndpointModes.UDP = 'NoMatch'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 0 -and $data.Coverage[1].Status -eq 'Failed')
        $script:EndpointModes.UDP = 'UnknownNotFound'
        $data = Get-EndpointDataset
        Assert-True ($data.Coverage[1].Status -eq 'Failed')
    }
    Run-Test 'endpoint sources retain partial results and distinguish denied and failed enumeration' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 123), (New-FakeEndpointRecord 456))
        $script:EndpointModes.TCP = 'AfterOne'; $script:EndpointModes.UDP = 'Denied'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1 -and $data.Coverage[0].Status -eq 'Partial' -and $data.Coverage[1].Status -eq 'Unavailable')
        $script:EndpointModes.TCP = 'Failed'; $script:EndpointModes.UDP = 'Failed'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Failed' -and $null -eq $data.Count -and $data.Items.Count -eq 0)
        $script:EndpointModes.TCP = 'Missing'; $script:EndpointModes.UDP = 'Denied'
        $data = Get-EndpointDataset
        Assert-True ($data.Status -eq 'Unavailable' -and $null -eq $data.Count)
    }
    Run-Test 'shared service PIDs preserve all endpoints and correlate without individual ownership' {
        $second = $script:FakeServices[0].PSObject.Copy(); $second.Name = 'SecondService'
        $stopped = $script:FakeServices[0].PSObject.Copy(); $stopped.Name = 'StoppedService'; $stopped.State = 'Stopped'
        $script:FakeServices += @($second, $stopped)
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 123 443 '::'), (New-FakeEndpointRecord 123 443 '::'))
        $script:FakeEndpoints.UDP = @((New-FakeEndpointRecord 123 53 '0.0.0.0'))
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 1 -and $script:ProcessBatches.Count -eq 1)
        $process = $result.Processes.Items[0]
        Assert-True ($process.RelatedServiceIds.Count -eq 2 -and $process.EndpointIds.Count -eq 3 -and $process.SourceKinds.Count -eq 3)
        Assert-True ($result.Endpoints.Count -eq 3 -and $result.Endpoints.Items[2].EndpointType -eq 'Bound')
        Assert-True ($result.Services.Items[2].ProcessAssociationStatus -eq 'NotApplicable' -and $null -eq $result.Services.Items[2].ProcessRecordId)
        foreach ($endpoint in $result.Endpoints.Items) {
            Assert-True ($endpoint.RelatedServiceIds.Count -eq 2 -and $endpoint.AssociationBasis -eq 'PID-only, non-atomic')
            Assert-True ($endpoint.ServiceAssociationStatus -eq 'UnconfirmedPidMatch' -and $endpoint.ProcessRecordId -eq 'process:123')
        }
        Assert-ProcessReferences $result
    }
    Run-Test 'endpoint-only processes have optional scope and empty service references' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        $result = Invoke-TestProcessCollection
        $optional = @($result.Processes.Items | Where-Object { -not $_.RequiredForCollection })[0]
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 2)
        Assert-True ($optional.ProcessId -eq 900 -and $optional.RelatedServiceIds.Count -eq 0 -and $optional.SourceKinds[0] -eq 'TCPListener')
        Assert-True ($result.Endpoints.Items[0].ServiceAssociationStatus -eq 'NoObservedMatch')
        Assert-True ($script:ProcessBatches.Count -eq 2 -and $script:ProcessBatches[0].Pids[0] -eq 123 -and $script:ProcessBatches[1].Pids[0] -eq 900)
        $roundTrip = $result.Processes | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        Assert-True ($roundTrip.Items[1].RelatedServiceIds -is [array] -and $roundTrip.Items[1].RelatedServiceIds.Count -eq 0)
        Assert-ProcessReferences $result
    }
    Run-Test 'endpoint failures never downgrade complete required service-process coverage' {
        $script:EndpointModes.TCP = 'Failed'; $script:EndpointModes.UDP = 'Denied'
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Endpoints.Status -eq 'Failed' -and $result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 1)
        Assert-True ($result.Processes.Coverage[0].Status -eq 'Success' -and $result.Processes.Coverage[1].Status -eq 'Failed')
        Assert-True ($null -eq $result.Budget.AdditionalProcesses.CandidateCount -and $script:ProcessBatches.Count -eq 1)
        Assert-ProcessReferences $result
    }
    Run-Test 'unknown required service scope skips process discovery without guessing optional targets' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        foreach ($mode in @('Denied', 'Failed', 'Missing')) {
            $script:CimMode = $mode
            $result = Invoke-TestProcessCollection
            Assert-True ($result.Processes.Status -eq $result.Services.Status -and $null -eq $result.Processes.Count)
            Assert-True ($result.Processes.TargetOutcomes.Count -eq 0 -and $script:ProcessBatches.Count -eq 0)
            Assert-True ($result.Endpoints.Items[0].ProcessId -eq 900 -and $result.Endpoints.Items[0].ServiceAssociationStatus -eq 'Unknown')
            Assert-True ($result.Endpoints.Items[0].ProcessAssociationStatus -eq 'Skipped' -and $null -eq $result.Budget.ServiceProcesses.CandidateCount)
        }
    }
    Run-Test 'complete empty service targets succeed while partial service selection remains partial' {
        $script:FakeServices[0].State = 'Stopped'; $script:FakeServices[0].ProcessId = 0
        $script:EndpointModes.TCP = 'Denied'; $script:EndpointModes.UDP = 'Denied'
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 0 -and $script:ProcessBatches.Count -eq 0)
        Assert-True ($result.Budget.ServiceProcesses.CandidateCount -eq 0)
        $script:CimMode = 'AfterOne'
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 0 -and $null -eq $result.Budget.ServiceProcesses.CandidateCount)
    }
    Run-Test 'required missing, denied, unavailable, and failed targets have explicit outcomes' {
        $script:ProcessMode = 'Empty'
        $empty = Invoke-TestProcessCollection
        Assert-True ($empty.Processes.Status -eq 'Partial' -and $empty.Processes.Count -eq 0 -and $empty.Processes.TargetOutcomes[0].Outcome -eq 'NotReturned')
        $script:ProcessMode = 'Success'
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        foreach ($mode in @('Empty', 'Denied', 'Missing', 'Failed')) {
            # Optional queries would succeed; only the required batch is varied.
            $script:ProcessBatchModes = @{ 0 = $mode }; $script:ProcessBatches.Clear()
            $result = Invoke-TestProcessCollection
            $expectedStatus = @{ Empty = 'Partial'; Denied = 'Unavailable'; Missing = 'Unavailable'; Failed = 'Failed' }
            $expectedOutcome = @{ Empty = 'NotReturned'; Denied = 'Unavailable'; Missing = 'Unavailable'; Failed = 'Failed' }
            Assert-True ($result.Processes.Status -eq $expectedStatus[$mode])
            Assert-True ($result.Processes.TargetOutcomes[0].Outcome -eq $expectedOutcome[$mode])
            Assert-True ($null -eq $result.Processes.TargetOutcomes[0].ProcessRecordId)
            if ($mode -eq 'Empty') {
                Assert-True ($result.Processes.Count -eq 1 -and -not $result.Processes.Items[0].RequiredForCollection)
                Assert-True ($result.Services.Items[0].ProcessAssociationStatus -eq 'NotReturned' -and $result.Processes.Coverage[0].Status -eq 'Partial')
                Assert-True ($result.Budget.ServiceProcesses.UnusableCount -eq 1)
            }
            else {
                Assert-True ($null -eq $result.Processes.Count -and $result.Processes.Items.Count -eq 0)
                Assert-True ($result.Processes.TargetOutcomes[1].Outcome -eq 'Skipped' -and $script:ProcessBatches.Count -eq 1)
            }
            Assert-ProcessReferences $result
        }
    }
    Run-Test 'partial process queries retain rows and mark unreturned failed-batch targets' {
        $second = $script:FakeServices[0].PSObject.Copy(); $second.Name = 'Second'; $second.ProcessId = 124
        $script:FakeServices += $second
        $script:ProcessMode = 'AfterOne'
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 1)
        Assert-True ($result.Processes.TargetOutcomes[0].Outcome -eq 'Returned' -and $result.Processes.TargetOutcomes[1].Outcome -eq 'Failed')
        Assert-True ($null -eq $result.Services.Items[1].ProcessRecordId -and $result.Budget.ServiceProcesses.UnusableCount -eq 1)
        Assert-ProcessReferences $result
    }
    Run-Test 'more than 512 running-service PIDs are queried once in batches no larger than 32' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 1..513) {
            $row = $base.PSObject.Copy(); $row.Name = 'BulkService_' + $number; $row.ProcessId = $number; $row
        })
        $result = Invoke-TestProcessCollection
        $queried = @($script:ProcessBatches.ToArray() | ForEach-Object { $_.Pids })
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 513)
        Assert-True ($queried.Count -eq 513 -and @($queried | Select-Object -Unique).Count -eq 513)
        Assert-True ($script:ProcessBatches.Count -eq 17 -and $script:ProcessBatches[0].Pids.Count -eq 32 -and $script:ProcessBatches[16].Pids.Count -eq 1)
        Assert-True ($result.Budget.ServiceProcesses.CandidateCount -eq 513 -and $result.Budget.ServiceProcesses.SkippedCount -eq 0)
        Assert-ProcessReferences $result
    }
    Run-Test 'additional PID cap is deterministic at 128 and one over without limiting endpoints' {
        foreach ($size in @(128, 129)) {
            $script:ProcessBatches.Clear()
            $script:FakeEndpoints.TCP = @(for ($number = 1000 + $size - 1; $number -ge 1000; $number--) { New-FakeEndpointRecord $number })
            $result = Invoke-TestProcessCollection
            $additional = @($result.Processes.Items | Where-Object { -not $_.RequiredForCollection })
            Assert-True ($result.Processes.Status -eq 'Success' -and $additional.Count -eq 128 -and $result.Endpoints.Count -eq $size)
            Assert-True ($additional[0].ProcessId -eq 1000 -and $additional[127].ProcessId -eq 1127)
            Assert-True ($result.Budget.AdditionalProcesses.CandidateCount -eq $size -and $result.Budget.AdditionalProcesses.SkippedCount -eq $size - 128)
            $expected = if ($size -eq 128) { 'Success' } else { 'Partial' }
            Assert-True ($result.Processes.Coverage[1].Status -eq $expected)
            if ($size -eq 129) {
                Assert-True ($result.Processes.TargetOutcomes[-1].ProcessId -eq 1128 -and $result.Processes.TargetOutcomes[-1].Outcome -eq 'Skipped')
                Assert-True ($result.Endpoints.Items[-1].ProcessAssociationStatus -eq 'Skipped')
            }
            Assert-ProcessReferences $result
        }
    }
    Run-Test 'successful additional rows cannot hide missing required coverage across batches' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 1..33) {
            $row = $base.PSObject.Copy(); $row.Name = 'BatchService_' + $number; $row.ProcessId = $number; $row
        })
        $script:ProcessBatchModes[0] = 'Denied'
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 2)
        Assert-True ($result.Processes.Coverage[0].Status -eq 'Partial' -and $result.Processes.Coverage[1].Status -eq 'Success')
        Assert-True ($result.Budget.ServiceProcesses.UnusableCount -eq 32 -and $result.Budget.ServiceProcesses.CompletedCount -eq 1)
        Assert-True ($result.Processes.Items[1].ProcessId -eq 900 -and -not $result.Processes.Items[1].RequiredForCollection)
        Assert-ProcessReferences $result
    }
    Run-Test 'partial service selection never becomes complete through endpoint-only rows' {
        $script:CimMode = 'AfterOne'
        $script:FakeServices[0].State = 'Stopped'; $script:FakeServices[0].ProcessId = 0
        $script:FakeEndpoints.UDP = @((New-FakeEndpointRecord 900 53))
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 1 -and -not $result.Processes.Items[0].RequiredForCollection)
        Assert-True ($result.Endpoints.Items[0].ServiceAssociationStatus -eq 'Unknown' -and $null -eq $result.Budget.ServiceProcesses.CandidateCount)
        Assert-ProcessReferences $result
    }
    Run-Test 'incomplete endpoint fields remain null and cannot create false associations' {
        $script:FakeEndpoints.TCP = @([pscustomobject]@{ LocalAddress = $null; LocalPort = $null; OwningProcess = $null })
        $result = Invoke-TestProcessCollection
        $row = $result.Endpoints.Items[0]
        Assert-True ($result.Endpoints.Status -eq 'Partial' -and $result.Endpoints.Count -eq 1 -and $row.RecordStatus -eq 'Partial')
        Assert-True ($null -eq $row.LocalPort -and $null -eq $row.ProcessId -and $row.ServiceAssociationStatus -eq 'Unknown')
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Count -eq 1 -and $null -eq $result.Budget.AdditionalProcesses.CandidateCount)
    }
    Run-Test 'partial required metadata preserves PID and empty commands without copying service configuration' {
        $row = New-FakeProcessRecord 123; $row.CreationDate = $null; $row.ExecutablePath = $null; $row.CommandLine = ''
        $script:ProcessRows['123'] = $row
        $result = Invoke-TestProcessCollection
        $process = $result.Processes.Items[0]
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 1 -and $process.ProcessId -eq 123)
        Assert-True ($process.RawCommandLine -ceq '' -and $process.RawCommandLineState -eq 'Empty' -and $null -eq $process.CreatedAt)
        Assert-True ($result.Processes.TargetOutcomes[0].Outcome -eq 'PartialMetadata' -and $process.AssociationStatus -eq 'UnconfirmedPidMatch')
        Assert-True ($result.Budget.ServiceProcesses.CompletedCount -eq 1)
        Assert-ProcessReferences $result
    }
    Run-Test 'missing invalid and unreadable process metadata retain partial records and sanitized issues' {
        foreach ($mode in @('MissingName', 'InvalidDate', 'DeniedPath', 'DeniedCommand')) {
            $row = New-FakeProcessRecord 123
            switch ($mode) {
                'MissingName' { $row.PSObject.Properties.Remove('Name') }
                'InvalidDate' { $row.CreationDate = 'not-a-provider-date' }
                'DeniedPath' { $row | Add-Member ScriptProperty ExecutablePath { throw [UnauthorizedAccessException]::new('Synthetic process secret') } -Force }
                'DeniedCommand' { $row | Add-Member ScriptProperty CommandLine { throw [UnauthorizedAccessException]::new('Synthetic process secret') } -Force }
            }
            $script:ProcessRows['123'] = $row
            $before = $script:CollectionIssues.Count
            $result = Invoke-TestProcessCollection
            Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 1 -and $result.Processes.TargetOutcomes[0].Outcome -eq 'PartialMetadata')
            $issue = $script:CollectionIssues[$before]
            Assert-True ($issue.RecordId -eq 'process:123' -and -not $issue.Message.Contains('Synthetic process secret'))
            $expected = if ($mode -like 'Denied*') { 'AccessDenied' } else { 'RecordReadFailed' }
            Assert-True ($issue.Code -eq $expected)
            Assert-ProcessReferences $result
        }
    }
    Run-Test 'optional process metadata and query failures cannot downgrade required success' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        $row = New-FakeProcessRecord 900; $row.CommandLine = $null
        $script:ProcessRows['900'] = $row
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Coverage[1].Status -eq 'Partial')
        Assert-True ($result.Processes.TargetOutcomes[1].Outcome -eq 'PartialMetadata' -and $result.Processes.Items[1].RawCommandLineState -eq 'Unavailable')
        $script:ProcessRows.Clear(); $script:ProcessBatches.Clear(); $script:ProcessBatchModes[1] = 'Denied'
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Success' -and $result.Processes.Coverage[1].Status -eq 'Unavailable')
        Assert-True ($result.Processes.Count -eq 1 -and $result.Processes.TargetOutcomes[1].Outcome -eq 'Unavailable')
        Assert-ProcessReferences $result
    }
    Run-Test 'source timestamps flag PID reuse without claiming certain service ownership' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 123))
        $row = New-FakeProcessRecord 123; $row.CreationDate = [datetime]::Parse('2099-01-01T00:00:00Z').ToUniversalTime()
        $script:ProcessRows['123'] = $row
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Services.Items[0].ProcessAssociationStatus -eq 'PossiblePidReuse' -and $result.Endpoints.Items[0].ProcessAssociationStatus -eq 'PossiblePidReuse')
        Assert-True ($result.Processes.Items[0].AssociationStatus -eq 'PossiblePidReuse' -and $result.Processes.Items[0].CreatedAt.StartsWith('2099-01-01'))
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'PossiblePidReuse' }).Count -eq 1)
        Assert-ProcessReferences $result
        $end = '2020-01-01T00:00:01Z'
        Assert-True ((Get-ProcessAssociationStatus ([pscustomobject]@{ CreatedAt = $end }) Returned $end) -eq 'UnconfirmedPidMatch')
        Assert-True ((Get-ProcessAssociationStatus ([pscustomobject]@{ CreatedAt = '2020-01-01T00:00:00Z' }) Returned $end) -eq 'UnconfirmedPidMatch')
        Assert-True ((Get-ProcessAssociationStatus ([pscustomobject]@{ CreatedAt = $null }) Returned $end) -eq 'UnconfirmedPidMatch')
        $row.CreationDate = [datetimeoffset]::Parse('2000-01-01T02:00:00+02:00')
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Items[0].CreatedAt.StartsWith('2000-01-01T00:00:00') -and $result.Processes.Items[0].AssociationStatus -eq 'UnconfirmedPidMatch')
    }
    Run-Test 'unexpected and duplicate process identities never create invalid references' {
        $script:ProcessRows['123'] = New-FakeProcessRecord 999
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Failed' -and $null -eq $result.Processes.Count -and $result.Processes.TargetOutcomes[0].Outcome -eq 'Failed')
        $script:ProcessRows['123'] = @((New-FakeProcessRecord 123), (New-FakeProcessRecord 123))
        $result = Invoke-TestProcessCollection
        Assert-True ($result.Processes.Status -eq 'Partial' -and $result.Processes.Count -eq 1)
        Assert-ProcessReferences $result
    }
    Run-Test 'six reports round trip all endpoint and process records with JSON-only commands' {
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 123 443), (New-FakeEndpointRecord 900 8080))
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')) | ConvertFrom-Json
        foreach ($pair in @(@('Services', 'services.csv'), @('InstalledSoftware', 'software.csv'), @('NetworkEndpoints', 'network-endpoints.csv'), @('Processes', 'processes.csv'))) {
            $dataset = @($json.Collection.Datasets | Where-Object { $_.Id -eq $pair[0] })[0]
            $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory $pair[1]))
            Assert-True ($csv.Count -eq $dataset.Count -and $dataset.Items.Count -eq $dataset.Count)
        }
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'processes.csv'))
        $sourceKinds = ConvertFrom-Json -InputObject $csv[0].SourceKinds
        Assert-True (
            $csv[1].RelatedServiceIds -eq '[]' -and
            $sourceKinds.Count -eq 2 -and
            $sourceKinds -contains 'RunningService' -and
            $sourceKinds -contains 'TCPListener'
        )
        foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv')) {
            $text = [IO.File]::ReadAllText((Join-Path $location.Directory $name))
            Assert-True (-not $text.Contains('SYNTHETIC_PROCESS_SECRET') -and -not $text.Contains('SYNTHETIC_SECRET_MARKER'))
        }
        $canonical = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json'))
        Assert-True ($canonical.Contains('SYNTHETIC_PROCESS_SECRET') -and $canonical.Contains('SYNTHETIC_SECRET_MARKER'))
        $console = Get-ServiceSoftwareSummary $report
        Assert-True (-not $console.Contains('SYNTHETIC_PROCESS_SECRET') -and -not $console.Contains('SYNTHETIC_SECRET_MARKER'))
    }
    Run-Test 'process and issue preview caps do not truncate detailed reports' {
        $script:FakeServices[0].State = 'Stopped'; $script:FakeServices[0].ProcessId = 0
        $script:FakeEndpoints.TCP = @(foreach ($number in 1..25) { New-FakeEndpointRecord $number })
        $location = New-TestLocation; $report = New-TestReport $location
        $processes = @($report.Collection.Datasets | Where-Object { $_.Id -eq 'Processes' })[0]
        Assert-True ($processes.Status -eq 'Success' -and $processes.Count -eq 25)
        foreach ($number in 1..15) { Add-InventoryIssue Collection Processes Parse SyntheticIssue 'Synthetic issue.' }
        foreach ($number in 1..5) { Add-InventoryIssue Output $null Verify SyntheticIssue 'Synthetic issue.' }
        $report.Collection.Issues = @($script:CollectionIssues.ToArray()); $report.Output.Issues = @($script:OutputIssues.ToArray())
        $console = Get-ServiceSoftwareSummary $report
        $detailed = Get-ServiceSoftwareSummary $report -Detailed
        Assert-True ([regex]::Matches($console, '(?m)^[0-9]+ / SyntheticProcess_').Count -eq 10)
        Assert-True ([regex]::Matches($console, '(?m)^- SyntheticIssue:').Count -eq 10)
        Assert-True ([regex]::Matches($detailed, '(?m)^- PID:').Count -eq 25 -and [regex]::Matches($detailed, '(?m)^- SyntheticIssue:').Count -eq 20)
    }
    Run-Test 'saved required success exits zero even with unavailable optional endpoints and files' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); $script:LastLocation = New-TestLocation; $script:LastLocation }
        $script:EndpointModes.TCP = 'Missing'; $script:EndpointModes.UDP = 'Missing'
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 0 -and $script:ProcessBatches.Count -eq 1)
        $json = [IO.File]::ReadAllText((Join-Path $script:LastLocation.Directory 'service-software.json')) | ConvertFrom-Json
        Assert-True ($json.Collection.Status -eq 'Success' -and $json.Output.Status -eq 'Success' -and $json.Output.Files.Count -eq 7 -and -not $json.ReleaseReady)
        Assert-True (@($json.Collection.Issues | Where-Object { $_.DatasetId -eq 'ExecutableFiles' -and $_.Code -eq 'CapabilityMissing' }).Count -eq 1)
    }
    Run-Test 'configured paths use conservative quoted or explicit unquoted executable boundaries' {
        Assert-True ((Resolve-ConfiguredExecutablePath '"C:\Program Files\App\svc.exe" -k value') -eq 'C:\Program Files\App\svc.exe')
        Assert-True ((Resolve-ConfiguredExecutablePath 'C:\Fixture\svc.exe -k value') -eq 'C:\Fixture\svc.exe')
        foreach ($text in @('C:\Program Files\App\svc.exe -k x', '"C:\Fixture\svc.exe', '"C:\Fixture\svc.exe"tail', 'svc.exe -k x', 'C:\Fixture\extensionless -k x', '"C:\Fixture\svc.exe --argument value"', '"C:\Fixture\extensionless"')) {
            $token = Resolve-ConfiguredExecutablePath $text
            $path = ConvertTo-ExecutablePath $token
            Assert-True ($null -eq $path.Path)
        }
        Assert-True ($script:ContentCalls.Count -eq 0)
    }
    Run-Test 'only Windows system-root aliases expand and unsafe lexical paths never access content' {
        foreach ($path in @('%SystemRoot%\System32\svc.exe', '%windir%\System32\svc.exe', '\SystemRoot\System32\svc.exe')) {
            Assert-True ((ConvertTo-ExecutablePath $path).Path -eq 'C:\Windows\System32\svc.exe')
        }
        foreach ($path in @('%USERPROFILE%\svc.exe', 'C:relative.exe', '\\server\share\svc.exe', '\\?\C:\svc.exe', '\Device\Volume\svc.exe', 'C:\Fixture\svc.exe:stream', 'C:\Fixture\NUL.exe', 'C:\Fixture\svc.exe.', 'C:\Redirect\..\svc.exe')) {
            Assert-True ($null -eq (ConvertTo-ExecutablePath $path).Path)
        }
        Assert-True ($script:AttributeCalls.Count -eq 0 -and $script:ContentCalls.Count -eq 0)
    }
    Run-Test 'network drives and reparse components are excluded before any content reads' {
        $script:FakeServices[0].PathName = 'Z:\Svc.exe'
        $row = New-FakeProcessRecord 123; $row.ExecutablePath = 'C:\Redirect\Svc.exe'
        $script:ProcessRows['123'] = $row; $script:FileStates['C:\Redirect'] = 'Reparse'
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Status -eq 'Unavailable' -and $null -eq $result.Files.Count)
        Assert-True ($script:ContentCalls.Count -eq 0 -and -not ($script:AttributeCalls -contains 'Z:\'))
        Assert-True (-not ($script:AttributeCalls -contains 'C:\Redirect\Svc.exe'))
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'RemotePathSkipped' }).Count -eq 1)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'ReparsePointSkipped' }).Count -eq 1)
        Assert-FileReferences $result
    }
    Run-Test 'all service states resolve configured paths without replacing ambiguous configuration with process paths' {
        $stopped = $script:FakeServices[0].PSObject.Copy(); $stopped.Name = 'Stopped'; $stopped.State = 'Stopped'; $stopped.StartMode = 'Disabled'; $stopped.ProcessId = 0
        $stopped.PathName = '"C:\Other App\Stopped.exe" -x'
        $script:FakeServices[0].PathName = 'C:\Program Files\Ambiguous\Svc.exe -x'
        $script:FakeServices += $stopped
        $row = New-FakeProcessRecord 123; $row.ExecutablePath = 'C:\Observed\Process.exe'; $script:ProcessRows['123'] = $row
        $result = Invoke-TestFileCollection
        Assert-True ($result.Services.Status -eq 'Success' -and $result.Services.Count -eq 2)
        Assert-True ($result.Services.Items[0].PathResolution -eq 'Unresolved' -and $null -eq $result.Services.Items[0].ExecutablePath -and $null -eq $result.Services.Items[0].FileRecordId)
        Assert-True ($result.Services.Items[1].PathResolution -eq 'Resolved' -and $result.Services.Items[1].ExecutablePath -eq 'C:\Other App\Stopped.exe')
        Assert-True ($result.Processes.Items[0].ExecutablePath -eq 'C:\Observed\Process.exe' -and $result.Processes.Items[0].FileRecordId)
        Assert-True ($null -eq $result.Budget.Files.CandidateCount)
        Assert-FileReferences $result
    }
    Run-Test 'shared case-insensitive file candidates preserve every source reference and hash once' {
        $second = $script:FakeServices[0].PSObject.Copy(); $second.Name = 'Shared'; $second.PathName = 'c:\fixture\SERVICE.exe'
        $script:FakeServices += $second
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Count -eq 1 -and $result.Files.Items[0].SourceRefs.Count -eq 3)
        Assert-True ($result.Budget.Files.CandidateCount -eq 1 -and $result.Budget.Hashes.AttemptedCount -eq 1)
        Assert-True ($result.Files.Items[0].SHA256 -eq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD')
        Assert-True ($result.Files.Items[0].MetadataStatus -eq 'Collected' -and $null -eq $result.Files.Items[0].FileVersion)
        Assert-True ($script:ObservedReadBytes -eq 3 -and $script:DisposedStreams -eq 1)
        Assert-FileReferences $result
    }
    Run-Test 'zero-byte files produce the complete standard SHA256 without consuming read bytes' {
        $script:FileFacts['C:\Fixture\Service.exe'] = [pscustomobject]@{ LengthBytes = [long]0; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' }
        $script:FilePayloads['C:\Fixture\Service.exe'] = [byte[]]@()
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Items[0].SHA256 -eq 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855')
        Assert-True ($result.Files.Items[0].HashStatus -eq 'Collected' -and $result.Budget.HashBytesRead -eq 0)
        Assert-FileReferences $result
    }
    Run-Test 'known missing files are negative facts while denied and failed paths remain unavailable or failed' {
        $path = 'C:\Fixture\Service.exe'
        foreach ($state in @('Missing', 'Denied', 'Failed')) {
            $script:FileStates[$path] = $state
            $result = Invoke-TestFileCollection
            if ($state -eq 'Missing') {
                Assert-True ($result.Files.Count -eq 1 -and $result.Files.Items[0].FileState -eq 'Missing' -and $result.Files.Items[0].MetadataStatus -eq 'Collected')
                Assert-True ($result.Budget.Files.CompletedCount -eq 1 -and $result.Budget.Hashes.SkippedCount -eq 1)
                Assert-True ($null -eq $result.Files.Items[0].SHA256)
            }
            else {
                $expected = if ($state -eq 'Denied') { 'Unavailable' } else { 'Failed' }
                Assert-True ($result.Files.Status -eq $expected -and $null -eq $result.Files.Count -and $null -eq $result.Services.Items[0].FileRecordId)
            }
            Assert-FileReferences $result
        }
    }
    Run-Test 'available version-resource strings are preserved as unverified metadata' {
        function script:Get-ExecutableVersion {
            param($Path)
            [pscustomobject]@{ FileVersion = '1.2.3'; ProductVersion = '4.5'; CompanyName = 'Synthetic company'; ProductName = 'Synthetic product' }
        }
        $result = Invoke-TestFileCollection
        $row = $result.Files.Items[0]
        Assert-True ($row.MetadataStatus -eq 'Collected' -and $row.FileVersion -eq '1.2.3' -and $row.ProductVersion -eq '4.5')
        Assert-True ($row.CompanyName -eq 'Synthetic company' -and $row.ProductName -eq 'Synthetic product' -and $row.SignatureStatus -eq 'Skipped')
        Assert-FileReferences $result
    }
    Run-Test 'version-resource access failures retain usable file facts without inventing version or hash values' {
        $script:VersionFailures['C:\Fixture\Service.exe'] = $true
        $result = Invoke-TestFileCollection
        $row = $result.Files.Items[0]
        Assert-True ($result.Files.Status -eq 'Partial' -and $row.FileState -eq 'Present' -and $row.LengthBytes -eq 3)
        Assert-True ($row.MetadataStatus -eq 'Unavailable' -and $null -eq $row.FileVersion -and $null -eq $row.SHA256)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'AccessDenied' -and $_.DatasetId -eq 'ExecutableFiles' }).Count -ge 1)
        Assert-FileReferences $result
    }
    Run-Test 'metadata and hash snapshots detect changed files and discard all affected digests' {
        foreach ($threshold in @(2, 3, 4)) {
            $script:FactCalls.Clear(); $script:ChangedFacts['C:\Fixture\Service.exe'] = $threshold
            $result = Invoke-TestFileCollection
            Assert-True ($null -eq $result.Files.Items[0].SHA256 -and $result.Files.Items[0].HashStatus -ne 'Collected')
            Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -eq 'FileChanged' }).Count -gt 0)
            Assert-FileReferences $result
        }
    }
    Run-Test 'stream growth and failed reads never publish partial hashes and count consumed bytes' {
        $script:GrowAfterRead = $true
        $result = Invoke-TestFileCollection
        Assert-True ($null -eq $result.Files.Items[0].SHA256 -and $result.Budget.Hashes.UnusableCount -eq 1 -and $result.Budget.HashBytesRead -eq 3)
        $script:GrowAfterRead = $false; $script:ReadFailures['C:\Fixture\Service.exe'] = 2
        $script:FileFacts['C:\Fixture\Service.exe'] = [pscustomobject]@{ LengthBytes = [long]65537; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' }
        $script:FilePayloads['C:\Fixture\Service.exe'] = [byte[]]@()
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Items[0].HashStatus -eq 'Failed' -and $null -eq $result.Files.Items[0].SHA256)
        Assert-True ($result.Budget.HashBytesRead -eq 65536 -and $result.Budget.Hashes.UnusableCount -eq 1)
        Assert-FileReferences $result
    }
    Run-Test 'failed reads with position advances count consumed bytes and disposal failures remain isolated' {
        $script:ReadFailures['C:\Fixture\Service.exe'] = 1; $script:AdvanceBeforeReadFailure = 3
        $result = Invoke-TestFileCollection
        Assert-True ($result.Budget.HashBytesRead -eq 3 -and $result.Budget.Hashes.UnusableCount -eq 1 -and $null -eq $result.Files.Items[0].SHA256)
        $script:ReadFailures.Clear(); $script:AdvanceBeforeReadFailure = 0; $script:FailStreamDispose = $true
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Items[0].HashStatus -eq 'Failed' -and $null -eq $result.Files.Items[0].SHA256 -and $result.Budget.Hashes.UnusableCount -eq 1)
        Assert-True ($result.Services.Status -eq 'Success' -and $result.Processes.Status -eq 'Success')
        Assert-FileReferences $result
    }
    Run-Test 'denied stream opens leave metadata usable and publish no hash' {
        $script:OpenFailures['C:\Fixture\Service.exe'] = $true
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Items[0].MetadataStatus -eq 'Collected' -and $result.Files.Items[0].HashStatus -eq 'Unavailable')
        Assert-True ($result.Budget.Hashes.AttemptedCount -eq 1 -and $result.Budget.Hashes.UnusableCount -eq 1 -and $result.Budget.HashBytesRead -eq 0)
        Assert-FileReferences $result
    }
    Run-Test '64 MiB inclusive hash eligibility rejects one byte over without reading that file' {
        foreach ($size in @([long]67108864, [long]67108865)) {
            $script:FileFacts['C:\Fixture\Service.exe'] = [pscustomobject]@{ LengthBytes = $size; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' }
            $script:FilePayloads['C:\Fixture\Service.exe'] = [byte[]]@()
            $result = Invoke-TestFileCollection
            if ($size -eq 67108864) { Assert-True ($result.Files.Items[0].HashStatus -eq 'Collected' -and $result.Budget.HashBytesRead -eq 67108864) }
            else { Assert-True ($result.Files.Items[0].HashStatus -eq 'Skipped' -and $result.Budget.HashBytesRead -eq 0 -and $result.Budget.Hashes.SkippedCount -eq 1) }
            Assert-True ($script:MaxReadRequest -le 65536)
            Assert-FileReferences $result
        }
    }
    Run-Test 'aggregate reads stop at 512 MiB and smaller files continue after a larger file is skipped' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 0..9) {
            $row = $base.PSObject.Copy(); $row.Name = 'HashBudget_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
            $path = 'C:\Fixture\Budget' + $number + '.exe'; $row.PathName = $path
            $length = if ($number -eq 9) { [long]1 } elseif ($number -eq 7) { [long]67108863 } else { [long]67108864 }
            $script:FileFacts[$path] = [pscustomobject]@{ LengthBytes = $length; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' }
            $script:FilePayloads[$path] = [byte[]]@(); $row
        })
        $result = Invoke-TestFileCollection
        Assert-True ($result.Budget.HashBytesRead -eq 536870912 -and $result.Budget.Hashes.CompletedCount -eq 9 -and $result.Budget.Hashes.SkippedCount -eq 1)
        Assert-True ($result.Files.Items[8].HashStatus -eq 'Skipped' -and $result.Files.Items[9].LengthBytes -eq 1 -and $result.Files.Items[9].HashStatus -eq 'Collected')
        Assert-True ($script:MaxReadRequest -le 65536)
        Assert-FileReferences $result
    }
    Run-Test 'exactly 256 paths and one over have consistent selection and omission accounting' {
        $base = $script:FakeServices[0]
        foreach ($size in @(256, 257)) {
            $script:FakeServices = @(for ($number = 0; $number -lt $size; $number++) {
                $row = $base.PSObject.Copy(); $row.Name = 'Boundary_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
                $row.PathName = 'C:\Fixture\Boundary' + $number.ToString('D3') + '.exe'; $row
            })
            $result = Invoke-TestFileCollection
            Assert-True ($result.Files.Count -eq 256 -and $result.Budget.Files.CandidateCount -eq $size -and $result.Budget.Files.SkippedCount -eq $size - 256)
            Assert-True ($result.Budget.Files.AttemptedCount -eq 256 -and $result.Budget.Hashes.CandidateCount -eq 256)
            Assert-FileReferences $result
        }
    }
    Run-Test 'path selection boundaries preserve IDs and prefer required service paths over network paths' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 0..255) {
            $row = $base.PSObject.Copy(); $row.Name = 'Other_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
            $row.PathName = 'C:\Fixture\A' + $number.ToString('D3') + '.exe'; $row
        })
        $running = $base.PSObject.Copy(); $running.PathName = 'C:\Fixture\ZRunning.exe'; $script:FakeServices += $running
        $process = New-FakeProcessRecord 123; $process.ExecutablePath = 'C:\Fixture\ZRunning.exe'; $script:ProcessRows['123'] = $process
        $script:FakeEndpoints.TCP = @((New-FakeEndpointRecord 900))
        $network = New-FakeProcessRecord 900; $network.ExecutablePath = 'C:\Fixture\AAdditional.exe'; $script:ProcessRows['900'] = $network
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Count -eq 256 -and $result.Budget.Files.CandidateCount -eq 258 -and $result.Budget.Files.SkippedCount -eq 2)
        Assert-True ($result.Files.Items[0].Path -eq 'C:\Fixture\ZRunning.exe' -and $result.Files.Items[0].Id -eq 'file:258')
        Assert-True ($null -eq $result.Services.Items[255].FileRecordId -and $null -eq $result.Processes.Items[1].FileRecordId)
        $omitted = @($script:CollectionIssues | Where-Object { $_.Code -eq 'LimitReached' -and $_.Stage -eq 'Prerequisite' })
        Assert-True ($omitted.Count -eq 2 -and $omitted[0].SourceRefs.Count -gt 0)
        Assert-FileReferences $result
    }
    Run-Test 'expiration before first path verification counts the skipped path without claiming an empty scope' {
        $script:FakeServices[0].State = 'Stopped'; $script:FakeServices[0].ProcessId = 0
        $script:ExpireClockAt = 1
        $result = Invoke-TestFileCollection
        Assert-True ($result.Services.Status -eq 'Success' -and $result.Processes.Status -eq 'Success')
        Assert-True ($result.Files.Status -eq 'Unavailable' -and $null -eq $result.Files.Count -and $null -eq $result.Budget.Files.CandidateCount)
        Assert-True ($result.Budget.Files.SkippedCount -eq 1 -and $result.Budget.Files.AttemptedCount -eq 0)
        Assert-True ($script:AttributeCalls.Count -eq 0 -and $script:ContentCalls.Count -eq 0)
        $issues = @($script:CollectionIssues | Where-Object { $_.DatasetId -eq 'ExecutableFiles' -and $_.Code -eq 'LimitReached' })
        Assert-True ($issues.Count -eq 1 -and $issues[0].Stage -eq 'Prerequisite' -and $issues[0].SourceRefs.Count -eq 1)
        Assert-True ($issues[0].SourceRefs[0].RecordId -eq $result.Services.Items[0].Id -and $null -eq $result.Services.Items[0].FileRecordId)
        Assert-FileReferences $result
    }
    Run-Test 'multiple distinct unverified paths are counted separately from unresolved source references' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 0..3) {
            $row = $base.PSObject.Copy(); $row.Name = 'Preflight_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
            $row.PathName = if ($number -eq 3) { 'relative.exe' } else { 'C:\Fixture\Preflight' + $number + '.exe' }; $row
        })
        $script:ExpireClockAt = 1
        $result = Invoke-TestFileCollection
        Assert-True ($result.Budget.Files.SkippedCount -eq 3 -and $null -eq $result.Budget.Files.CandidateCount)
        Assert-True ($result.Budget.Files.AttemptedCount -eq 0 -and $script:AttributeCalls.Count -eq 0 -and $script:ContentCalls.Count -eq 0)
        $issues = @($script:CollectionIssues | Where-Object { $_.DatasetId -eq 'ExecutableFiles' -and $_.Code -eq 'LimitReached' })
        Assert-True ($issues.Count -eq 3 -and @($issues | ForEach-Object { $_.SourceRefs[0].RecordId } | Select-Object -Unique).Count -eq 3)
        $limits = $result.Files.Limitations -join ' '
        Assert-True ($limits.Contains('Observed safe distinct paths: 0; excluded/unresolved source references: 1'))
        Assert-True ($limits.Contains('scheduling-unverified distinct paths: 3 (source references: 3)'))
        Assert-FileReferences $result
    }
    Run-Test 'shared unverified paths count once while preserving all service and process references' {
        $second = $script:FakeServices[0].PSObject.Copy(); $second.Name = 'Shared'; $second.PathName = 'c:\fixture\SERVICE.exe'
        $script:FakeServices += $second
        $script:ExpireClockAt = 1
        $result = Invoke-TestFileCollection
        Assert-True ($result.Services.Count -eq 2 -and $result.Processes.Count -eq 1)
        Assert-True ($result.Budget.Files.SkippedCount -eq 1 -and $null -eq $result.Budget.Files.CandidateCount)
        Assert-True ($script:AttributeCalls.Count -eq 0 -and $script:ContentCalls.Count -eq 0)
        $issues = @($script:CollectionIssues | Where-Object { $_.DatasetId -eq 'ExecutableFiles' -and $_.Code -eq 'LimitReached' })
        Assert-True ($issues.Count -eq 1 -and $issues[0].SourceRefs.Count -eq 3)
        Assert-True (@($issues[0].SourceRefs | Where-Object { $_.DatasetId -eq 'Services' }).Count -eq 2)
        Assert-True (@($issues[0].SourceRefs | Where-Object { $_.DatasetId -eq 'Processes' }).Count -eq 1)
        Assert-True (($result.Files.Limitations -join ' ').Contains('scheduling-unverified distinct paths: 1 (source references: 3)'))
        Assert-FileReferences $result
    }
    Run-Test 'preflight selection-cap and metadata scheduling skips are disjoint without double counting' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 0..259) {
            $row = $base.PSObject.Copy(); $row.Name = 'MixedSkip_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
            $row.PathName = 'C:\Fixture\MixedSkip' + $number.ToString('D3') + '.exe'; $row
        })
        # 257 verified paths, then three unverified paths; one verified path
        # exceeds the cap, and all 256 selected metadata operations miss the deadline.
        $script:ExpireClockAt = 258
        $result = Invoke-TestFileCollection
        Assert-True ($null -eq $result.Budget.Files.CandidateCount -and $result.Budget.Files.SkippedCount -eq 260)
        Assert-True ($result.Budget.Files.AttemptedCount -eq 0 -and $script:ContentCalls.Count -eq 0)
        Assert-True (-not ($script:AttributeCalls -contains 'C:\Fixture\MixedSkip257.exe'))
        $preflight = @($script:CollectionIssues | Where-Object { $_.Code -eq 'LimitReached' -and $_.Stage -eq 'Prerequisite' })
        $metadata = @($script:CollectionIssues | Where-Object { $_.Code -eq 'LimitReached' -and $_.Stage -eq 'Collect' })
        Assert-True ($preflight.Count -eq 4 -and $metadata.Count -eq 256)
        $skippedIds = @(@($preflight) + @($metadata) | ForEach-Object { $_.SourceRefs[0].RecordId })
        Assert-True ($skippedIds.Count -eq 260 -and @($skippedIds | Select-Object -Unique).Count -eq 260)
        $limits = $result.Files.Limitations -join ' '
        Assert-True ($limits.Contains('Observed safe distinct paths: 257; excluded/unresolved source references: 0'))
        Assert-True ($limits.Contains('scheduling-unverified distinct paths: 3 (source references: 3)'))
        Assert-FileReferences $result
    }
    Run-Test 'fully verified candidate counts retain budget identities when metadata scheduling expires' {
        $base = $script:FakeServices[0]
        $script:FakeServices = @(foreach ($number in 0..2) {
            $row = $base.PSObject.Copy(); $row.Name = 'Verified_' + $number; $row.State = 'Stopped'; $row.ProcessId = 0
            $row.PathName = 'C:\Fixture\Verified' + $number + '.exe'; $row
        })
        $script:ExpireClockAt = 4
        $result = Invoke-TestFileCollection
        Assert-True ($result.Budget.Files.CandidateCount -eq 3 -and $result.Budget.Files.SkippedCount -eq 3 -and $result.Budget.Files.AttemptedCount -eq 0)
        Assert-True ($script:ContentCalls.Count -eq 0 -and ($script:AttributeCalls -contains 'C:\Fixture\Verified2.exe'))
        Assert-True (($result.Files.Limitations -join ' ').Contains('scheduling-unverified distinct paths: 0 (source references: 0)'))
        Assert-FileReferences $result
    }
    Run-Test 'incomplete upstream scope keeps candidate totals unknown even when all observed paths are verified' {
        $script:CimMode = 'AfterOne'
        $result = Invoke-TestFileCollection
        Assert-True ($result.Services.Status -eq 'Partial' -and $null -eq $result.Budget.Files.CandidateCount)
        Assert-True ($result.Files.Count -eq 1 -and $result.Budget.Files.AttemptedCount -eq 1 -and $result.Budget.Files.SkippedCount -eq 0)
        Assert-True (($result.Files.Limitations -join ' ').Contains('Observed safe distinct paths: 1; excluded/unresolved source references: 0'))
        Assert-True (($result.Files.Limitations -join ' ').Contains('scheduling-unverified distinct paths: 0 (source references: 0)'))
        Assert-FileReferences $result
    }
    Run-Test '60-second scheduling stops new operations and discards interrupted streaming hashes' {
        $script:ExpireClockAt = 2
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Status -eq 'Unavailable' -and $result.Budget.Files.AttemptedCount -eq 0 -and $result.Budget.Files.SkippedCount -eq 1)
        Assert-True ($script:ContentCalls.Count -eq 0)
        $script:ExpireClockAt = 0; $script:FileElapsed = 0; $script:ClockCalls = 0; $script:StopAfterRead = $true
        $script:FileFacts['C:\Fixture\Service.exe'] = [pscustomobject]@{ LengthBytes = [long]65537; LastWriteTimeUtc = '2000-01-01T00:00:00.0000000Z' }
        $script:FilePayloads['C:\Fixture\Service.exe'] = [byte[]]@()
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Items[0].HashStatus -eq 'Skipped' -and $null -eq $result.Files.Items[0].SHA256)
        Assert-True ($result.Budget.HashBytesRead -eq 65536 -and $result.Budget.Hashes.AttemptedCount -eq 1 -and $result.Budget.Hashes.UnusableCount -eq 1)
        Assert-FileReferences $result
    }
    Run-Test 'unsupported file host and unknown inputs preserve unavailable counts without touching files' {
        $result = Invoke-TestFileCollection $false
        Assert-True ($result.Files.Status -eq 'Unavailable' -and $null -eq $result.Files.Count -and $null -eq $result.Budget.Files.CandidateCount -and $script:AttributeCalls.Count -eq 0)
        $script:FileHostSupported = $true
        $row = New-FakeProcessRecord 123; $row.ExecutablePath = $null; $script:ProcessRows['123'] = $row
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Status -eq 'Partial' -and $null -eq $result.Budget.Files.CandidateCount -and $result.Files.Count -eq 1)
        Assert-True ($null -eq $result.Processes.Items[0].FileRecordId -and $result.Services.Items[0].FileRecordId)
        Assert-FileReferences $result
    }
    Run-Test 'complete empty file candidate scope is success zero and signatures are never invoked' {
        $script:FakeServices = @()
        $result = Invoke-TestFileCollection
        Assert-True ($result.Files.Status -eq 'Success' -and $result.Files.Count -eq 0 -and $result.Budget.Files.CandidateCount -eq 0)
        Assert-True ($result.Budget.Signatures.AttemptedCount -eq 0 -and $script:SignatureCalls -eq 0)
        Assert-FileReferences $result
    }
    Run-Test 'seven reports preserve file schemas references and JSON-only raw commands' {
        $script:FileHostSupported = $true
        $location = New-TestLocation; $report = New-TestReport $location -IncludeFiles
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')) | ConvertFrom-Json
        $files = @($json.Collection.Datasets | Where-Object { $_.Id -eq 'ExecutableFiles' })[0]
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'files.csv'))
        Assert-True ($files.Count -eq $csv.Count -and $csv.Count -eq 2 -and $json.Output.Files.Count -eq 7)
        $references = ConvertFrom-Json -InputObject $csv[0].SourceRefs
        Assert-True ($references.Count -eq 1 -and $references[0].RecordId)
        foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv')) {
            $text = [IO.File]::ReadAllText((Join-Path $location.Directory $name))
            Assert-True (-not $text.Contains('SYNTHETIC_SECRET_MARKER') -and -not $text.Contains('SYNTHETIC_PROCESS_SECRET'))
        }
        Assert-True ($json.Collection.Status -eq 'Success' -and $files.Status -eq 'Partial' -and $report.Output.Status -eq 'Success')
        Assert-True ($script:SignatureCalls -eq 0 -and $json.Collection.BudgetUsage.Signatures.AttemptedCount -eq 0)
    }
    Run-Test 'files.csv failure prevents canonical publication and supports safe cleanup' {
        function script:Write-ProtectedReportText {
            param($Path,$Text,$AllowedSids)
            if ([IO.Path]::GetFileName($Path) -eq 'files.csv.tmp') { throw 'Synthetic file CSV failure' }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed' -and -not [IO.File]::Exists((Join-Path $location.Directory 'service-software.json')))
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True (@(Get-ChildItem -LiteralPath $location.Directory -Force).Count -eq 0)
    }
    Run-Test 'native read helpers hash only an invocation-owned synthetic file' {
        $path = Join-Path $script:TestRoot 'SyntheticHash.exe'
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes('abc'))
        foreach ($name in @('Get-ExecutableDriveType', 'Get-ExecutableAttributes', 'Get-ExecutableFacts', 'Open-ExecutableStream')) {
            Set-Item -Path ('Function:script:' + $name) -Value $definitions[$name]
        }
        $facts = Get-ExecutableFacts $path
        $candidate = [pscustomobject]@{ Path = $path; Row = $facts }
        $budget = [ordered]@{ HashBytesRead = [long]0 }
        $clock = [Diagnostics.Stopwatch]::StartNew()
        try { $result = Get-ExecutableHash $candidate $clock $budget }
        finally { $clock.Stop() }
        Assert-True ($result.Status -eq 'Collected' -and $result.SHA256 -eq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD' -and $budget.HashBytesRead -eq 3)
    }
    Run-Test 'native location preparation resolves relative roots and avoids collisions' {
        $base = Join-Path $script:TestRoot 'RelativeRoot'
        [void][IO.Directory]::CreateDirectory($base)
        Push-Location -LiteralPath $base
        try {
            $first = New-ProtectedReportLocation '.' SYNTHETIC_HOST ([guid]::NewGuid().ToString()) $script:Allowed
            $second = New-ProtectedReportLocation '.' SYNTHETIC_HOST ([guid]::NewGuid().ToString()) $script:Allowed
            Assert-True ([IO.Path]::IsPathRooted($first.Directory) -and $first.Directory -ne $second.Directory)
            Assert-True ($first.TemporaryPaths.Count -eq 7 -and $second.TemporaryPaths.Count -eq 7)
        }
        finally { Pop-Location }
    }
}
finally {
    # Only the GUID-named test directory created above; no real reports or ACLs.
    if ($script:TestRoot -like (Join-Path ([IO.Path]::GetTempPath()) 'CCDC-ServiceSoftware-Tests-*')) {
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction Stop
    }
}
Write-Host ('Synthetic tests: ' + $script:Passed + ' passed; ' + $script:Failed + ' failed.')
if ($script:Failed -gt 0) { exit 1 }
