#requires -Version 5.1
<#
.SYNOPSIS
    Collects service, software, process, and file inventory (development Milestone 1.2C).
.DESCRIPTION
    Standalone, read-only Windows collector. Raw service commands are saved only in
    restricted JSON. Local endpoint tables provide optional process discovery.
    File enrichment is bounded; native signatures are not invoked. Development release.
.PARAMETER OutputDir
    Optional local output root. A verified private temporary location is the fallback.
#>
[CmdletBinding()]
param([string]$OutputDir)

function Add-InventoryIssue {
    param(
        [ValidateSet('Collection', 'Output')][string]$Kind,
        [AllowNull()][string]$DatasetId,
        [string]$Stage, [string]$Code, [string]$Message,
        [string]$RecordId, [object[]]$SourceRefs
    )
    $issue = [ordered]@{ DatasetId = $DatasetId; Stage = $Stage; Code = $Code; Message = $Message }
    if ([string]::IsNullOrEmpty($DatasetId)) { $issue.DatasetId = $null }
    if ($RecordId) { $issue.RecordId = $RecordId }
    if ($SourceRefs.Count -gt 0) { $issue.SourceRefs = @($SourceRefs) }
    if ($Kind -eq 'Collection') { $script:CollectionIssues.Add([pscustomobject]$issue) }
    else { $script:OutputIssues.Add([pscustomobject]$issue) }
    # Messages are fixed explanations, never native exception text or command lines.
    if ($script:WarningCount -lt 10) { Write-Warning ($Code + ': ' + $Message) }
    $script:WarningCount++
}

function Get-CollectionFailure {
    param([System.Management.Automation.ErrorRecord]$Record, [string]$DefaultCode = 'QueryFailed')
    $denied = $Record.CategoryInfo.Category -in @('PermissionDenied', 'SecurityError')
    $missing = $false
    $exception = $Record.Exception
    while ($null -ne $exception) {
        if ($exception -is [UnauthorizedAccessException] -or
            $exception -is [System.Security.SecurityException]) { $denied = $true }
        if ($exception -is [System.Management.Automation.CommandNotFoundException] -or
            $exception -is [PlatformNotSupportedException] -or $exception -is [TypeLoadException] -or
            $exception -is [DllNotFoundException]) { $missing = $true }
        if ($exception.PSObject.Properties['NativeErrorCode']) {
            $nativeCode = [string]$exception.NativeErrorCode
            if ($nativeCode -eq 'AccessDenied') { $denied = $true }
            if ($nativeCode -in @('InvalidClass', 'InvalidNamespace', 'NotSupported')) { $missing = $true }
        }
        $exception = $exception.InnerException
    }
    if ($denied) {
        return [pscustomobject]@{ Status = 'Unavailable'; Code = 'AccessDenied'; Message = 'Access to the requested collection data was denied.' }
    }
    if ($missing) {
        return [pscustomobject]@{ Status = 'Unavailable'; Code = 'CapabilityMissing'; Message = 'A required local collection capability is unavailable.' }
    }
    [pscustomobject]@{ Status = 'Failed'; Code = $DefaultCode; Message = 'The requested collection operation did not complete.' }
}

function Get-AggregateStatus {
    param([object[]]$Results)
    $required = @($Results | Where-Object { $_.Required })
    if ($required.Count -eq 0) { return 'Unavailable' }
    if (@($required | Where-Object { $_.Status -ne 'Success' }).Count -eq 0) { return 'Success' }
    if (@($required | Where-Object { $_.Status -in @('Success', 'Partial') }).Count -gt 0) { return 'Partial' }
    if (@($required | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) { return 'Failed' }
    return 'Unavailable'
}

function Get-InventoryExitCode {
    param([string]$CollectionStatus, [bool]$ReportsSaved)
    if (-not $ReportsSaved) { return 3 }
    switch ($CollectionStatus) {
        'Success' { return 0 }
        'Failed' { return 1 }
        default { return 2 }
    }
}

function New-InventoryDataset {
    param([string]$Id, [bool]$Required, [string]$Status, [object[]]$Items, [string[]]$Limitations)
    $retained = [object[]]@()
    if ($Status -notin @('Unavailable', 'Failed')) { $retained = [object[]]@($Items | Where-Object { $null -ne $_ }) }
    [pscustomobject][ordered]@{
        Id = $Id; Required = $Required; Status = $Status
        Count = if ($Status -in @('Unavailable', 'Failed')) { $null } else { $retained.Count }
        Items = $retained
        Limitations = @($Limitations); Coverage = @()
    }
}

function Convert-ServiceRecord {
    param($Source)
    # Invoke the getter as a .NET method so a failed read cannot masquerade as null.
    $valueProperty = [System.Management.Automation.PSPropertyInfo].GetProperty('Value')
    $nameProperty = $Source.PSObject.Properties['Name']
    if ($null -eq $nameProperty) { throw 'ServiceIdentityMissing' }
    $name = $valueProperty.GetValue($nameProperty, $null)
    if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) { throw 'ServiceIdentityMissing' }
    $item = [ordered]@{
        Id = 'service:' + $name; Name = $name; DisplayName = $null; State = $null
        StartMode = $null; ServiceAccount = $null; ProcessId = $null
        RawCommandLine = $null; RawCommandLineState = 'Unavailable'
        ExecutablePath = $null; PathResolution = 'Unavailable'
        ProcessRecordId = $null; ProcessAssociationStatus = 'Unavailable'
        FileRecordId = $null; RecordStatus = 'Success'
    }
    $mapping = [ordered]@{
        DisplayName = 'DisplayName'; State = 'State'; StartMode = 'StartMode'
        ServiceAccount = 'StartName'; ProcessId = 'ProcessId'; RawCommandLine = 'PathName'
    }
    foreach ($field in $mapping.Keys) {
        try {
            $property = $Source.PSObject.Properties[$mapping[$field]]
            if ($null -eq $property) { throw 'ServicePropertyMissing' }
            $value = $valueProperty.GetValue($property, $null)
            if ($null -eq $value) {
                # StartName is legitimately nullable; a missing or failed read is not.
                if ($field -eq 'ServiceAccount') { continue }
                throw 'ServiceFieldUnavailable'
            }
            if ($field -eq 'ProcessId') {
                if ($value.GetType() -notin @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])) {
                    throw 'ServiceFieldTypeInvalid'
                }
                $item[$field] = [uint32]$value
            }
            else {
                if ($value -isnot [string]) { throw 'ServiceFieldTypeInvalid' }
                $item[$field] = $value
            }
        }
        catch {
            $item.RecordStatus = 'Partial'
            $problem = Get-CollectionFailure $_ RecordReadFailed
            Add-InventoryIssue Collection Services Parse $problem.Code $problem.Message $item.Id
        }
    }
    if ($null -ne $item.RawCommandLine) {
        $item.RawCommandLineState = if ($item.RawCommandLine -ceq '') { 'Empty' } else { 'Collected' }
    }
    if (($null -ne $item.State -and $item.State -ne 'Running') -or $item.ProcessId -eq 0) {
        $item.ProcessAssociationStatus = 'NotApplicable'
    }
    [pscustomobject]$item
}

function Get-ServiceDataset {
    $started = [datetime]::UtcNow.ToString('o')
    $items = New-Object 'System.Collections.Generic.List[object]'
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $issueStart = $script:CollectionIssues.Count
    $failure = $null
    try {
        Get-CimInstance -ClassName Win32_Service -Property Name,DisplayName,State,StartMode,StartName,ProcessId,PathName -OperationTimeoutSec 30 -ErrorAction Stop |
            ForEach-Object {
                try {
                    $item = Convert-ServiceRecord $_
                    if (-not $names.Add($item.Name)) { throw 'DuplicateServiceIdentity' }
                    $items.Add($item)
                }
                catch {
                    $problem = Get-CollectionFailure $_ RecordReadFailed
                    Add-InventoryIssue Collection Services Parse $problem.Code $problem.Message
                }
            }
    }
    catch {
        $problem = Get-CollectionFailure $_
        $failure = $problem.Status
        Add-InventoryIssue Collection Services Collect $problem.Code $problem.Message
    }
    $status = if ($script:CollectionIssues.Count -eq $issueStart) { 'Success' }
        elseif ($items.Count -gt 0) { 'Partial' }
        elseif ($failure) { $failure } else { 'Failed' }
    $result = New-InventoryDataset Services $true $status $items.ToArray() @(
        'Configured paths are resolved conservatively; process paths never substitute for service configuration.'
    )
    $result.Coverage = @([pscustomobject]@{
        SourceId = 'Win32_Service'; Required = $true; Status = $status
        QueryStartedAt = $started; QueryCompletedAt = [datetime]::UtcNow.ToString('o')
    })
    $result
}

function Open-UninstallRoot {
    param([string]$View)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]$View)
    try {
        [pscustomobject]@{
            BaseKey = $base
            Key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $false)
        }
    }
    catch { $base.Dispose(); throw }
}

function Read-SoftwareRegistration {
    param([string]$View, [string]$SubkeyName, $Key, [System.Management.Automation.ErrorRecord]$OpenError)
    $item = [ordered]@{
        Id = 'software:' + $View + ':' + $SubkeyName
        Name = $null; Version = $null; Publisher = $null; RegistryHive = 'HKLM'
        RegistryView = $View
        RegistryKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + $SubkeyName
        SubkeyName = $SubkeyName; MissingValueNames = @(); RecordStatus = 'Success'
    }
    try {
        if ($null -ne $OpenError) { throw $OpenError }
        if ($null -eq $Key) { throw 'RegistrationUnavailable' }
        $valueNames = @($Key.GetValueNames())
    }
    catch {
        $item.RecordStatus = 'Partial'
        $problem = Get-CollectionFailure $_ RecordReadFailed
        Add-InventoryIssue Collection InstalledSoftware Collect $problem.Code $problem.Message $item.Id
        return [pscustomobject]$item
    }
    $mapping = [ordered]@{ Name = 'DisplayName'; Version = 'DisplayVersion'; Publisher = 'Publisher' }
    foreach ($field in $mapping.Keys) {
        $valueName = $mapping[$field]
        if ($valueNames -notcontains $valueName) { $item.MissingValueNames += $valueName; continue }
        try {
            $value = $Key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $value -and $value -isnot [string]) { throw 'RegistrationValueTypeUnsupported' }
            $item[$field] = $value
        }
        catch {
            $item.RecordStatus = 'Partial'
            $problem = Get-CollectionFailure $_ RecordReadFailed
            Add-InventoryIssue Collection InstalledSoftware Collect $problem.Code $problem.Message $item.Id
        }
    }
    [pscustomobject]$item
}

function Get-SoftwareDataset {
    $items = New-Object 'System.Collections.Generic.List[object]'
    $coverage = @()
    foreach ($view in @('Registry64', 'Registry32')) {
        $started = [datetime]::UtcNow.ToString('o')
        $root = $null; $viewCount = 0; $failure = $null
        $issueStart = $script:CollectionIssues.Count
        try {
            if ($view -eq 'Registry64' -and -not [Environment]::Is64BitOperatingSystem) {
                throw [PlatformNotSupportedException]::new('Registry64Unavailable')
            }
            $root = Open-UninstallRoot $view
            if ($null -ne $root.Key) {
                $subkeys = [string[]]$root.Key.GetSubKeyNames()
                [array]::Sort($subkeys, [StringComparer]::OrdinalIgnoreCase)
                foreach ($subkeyName in $subkeys) {
                    $key = $null; $openError = $null
                    try { $key = $root.Key.OpenSubKey($subkeyName, $false) }
                    catch {
                        # Retain the error identity for one sanitized issue in the reader.
                        $openError = $_
                    }
                    try {
                        $items.Add((Read-SoftwareRegistration $view $subkeyName $key $openError))
                        $viewCount++
                    }
                    finally { if ($null -ne $key) { $key.Dispose() } }
                }
            }
        }
        catch {
            $problem = Get-CollectionFailure $_
            $failure = $problem.Status
            Add-InventoryIssue Collection InstalledSoftware Collect $problem.Code $problem.Message $view
        }
        finally {
            if ($null -ne $root) {
                if ($null -ne $root.Key) { $root.Key.Dispose() }
                $root.BaseKey.Dispose()
            }
        }
        $status = if ($script:CollectionIssues.Count -eq $issueStart) { 'Success' }
            elseif ($viewCount -gt 0) { 'Partial' }
            elseif ($failure) { $failure } else { 'Failed' }
        $coverage += [pscustomobject]@{
            SourceId = $view; Required = $true; Status = $status
            QueryStartedAt = $started; QueryCompletedAt = [datetime]::UtcNow.ToString('o')
        }
    }
    $result = New-InventoryDataset InstalledSoftware $true (Get-AggregateStatus $coverage) $items.ToArray() @(
        'HKLM uninstall registrations only; no inferred service ownership or complete application coverage.'
    )
    $result.Coverage = @($coverage)
    $result
}

function Read-ObservedProperty {
    param($Source, [string]$Name)
    $property = $Source.PSObject.Properties[$Name]
    if ($null -eq $property) { throw 'ProviderPropertyMissing' }
    $getter = [System.Management.Automation.PSPropertyInfo].GetProperty('Value')
    $value = $getter.GetValue($property, $null)
    if ($null -eq $value) { return $null }
    # Every requested provider field is scalar. Reject collections before the
    # success stream could unwrap a one-element array into a plausible scalar.
    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { throw 'ProviderScalarExpected' }
    return $value
}

function Convert-ObservedUInt32 {
    param($Value)
    if ($null -eq $Value -or $Value.GetType() -notin @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])) {
        throw 'ProviderIntegerInvalid'
    }
    [uint32]$Value
}

function Convert-EndpointRecord {
    param($Source, [string]$Protocol)
    $item = [ordered]@{
        Id = ''; Protocol = $Protocol; EndpointType = if ($Protocol -eq 'TCP') { 'Listening' } else { 'Bound' }
        LocalAddress = $null; LocalPort = $null; ProcessId = $null
        RelatedServiceIds = @(); ServiceAssociationStatus = 'Unknown'; ProcessRecordId = $null
        ProcessAssociationStatus = 'Unavailable'; AssociationBasis = 'PID-only, non-atomic'; RecordStatus = 'Success'
    }
    foreach ($field in @('LocalAddress', 'LocalPort', 'OwningProcess')) {
        try {
            $value = Read-ObservedProperty $Source $field
            if ($field -eq 'LocalAddress') {
                if ($value -isnot [string] -or [string]::IsNullOrEmpty($value)) { throw 'EndpointAddressUnavailable' }
                $item.LocalAddress = $value
            }
            else {
                $number = Convert-ObservedUInt32 $value
                if ($field -eq 'LocalPort') {
                    if ($number -gt 65535) { throw 'EndpointPortInvalid' }
                    $item.LocalPort = $number
                }
                else { $item.ProcessId = $number }
            }
        }
        catch {
            $item.RecordStatus = 'Partial'
            $problem = Get-CollectionFailure $_ RecordReadFailed
            Add-InventoryIssue Collection NetworkEndpoints Parse $problem.Code $problem.Message
        }
    }
    [pscustomobject]$item
}

function Get-EndpointDataset {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $coverage = @()
    foreach ($source in @(
        @{ Id = 'TCPListeners'; Protocol = 'TCP'; Query = { Get-NetTCPConnection -State Listen -ErrorAction Stop } },
        @{ Id = 'UDPEndpoints'; Protocol = 'UDP'; Query = { Get-NetUDPEndpoint -ErrorAction Stop } }
    )) {
        $started = [datetime]::UtcNow.ToString('o')
        $before = $rows.Count; $issueStart = $script:CollectionIssues.Count; $failure = $null
        try {
            & ($source.Query) | ForEach-Object {
                if ($null -eq $_) {
                    Add-InventoryIssue Collection NetworkEndpoints Parse RecordReadFailed 'An endpoint source returned an unusable null record.'
                    return
                }
                $item = Convert-EndpointRecord $_ $source.Protocol
                $rows.Add([pscustomobject]@{ Item = $item; Ordinal = $rows.Count })
            }
        }
        catch {
            # A filtered CDXML query can report a known no-match error. Never
            # reinterpret other ObjectNotFound/provider failures as empty tables.
            $errorId = $_.FullyQualifiedErrorId.Split(',')[0]
            $knownNoMatch = $errorId -eq 'CmdletizationQuery_NotFound' -or
                ($source.Protocol -eq 'TCP' -and $errorId -eq 'CmdletizationQuery_NotFound_State')
            $noMatch = $knownNoMatch -and $rows.Count -eq $before -and
                $_.CategoryInfo.Category -eq 'ObjectNotFound'
            if (-not $noMatch) {
                $problem = Get-CollectionFailure $_
                $failure = $problem.Status
                Add-InventoryIssue Collection NetworkEndpoints Collect $problem.Code $problem.Message $source.Id
            }
        }
        $status = if ($script:CollectionIssues.Count -eq $issueStart) { 'Success' }
            elseif ($rows.Count -gt $before) { 'Partial' }
            elseif ($failure) { $failure } else { 'Failed' }
        $coverage += [pscustomobject]@{
            SourceId = $source.Id; Required = $true; Status = $status
            QueryStartedAt = $started; QueryCompletedAt = [datetime]::UtcNow.ToString('o')
        }
    }
    $items = @(foreach ($row in @($rows.ToArray() | Sort-Object { $_.Item.Protocol }, { $_.Item.LocalAddress }, { $_.Item.LocalPort }, { $_.Item.ProcessId }, Ordinal)) {
        $row.Item
    })
    for ($index = 0; $index -lt $items.Count; $index++) { $items[$index].Id = 'endpoint:' + ($index + 1) }
    $result = New-InventoryDataset NetworkEndpoints $false (Get-AggregateStatus $coverage) $items @(
        'All returned local TCP listeners and bound UDP endpoints; no remote connections or scans.'
        'NetTCPIP provider calls have no hard timeout here; incomplete discovery is optional and does not invalidate complete required process coverage.'
        'PID-only, non-atomic associations do not establish individual service endpoint ownership.'
    )
    $result.Coverage = @($coverage)
    $result
}

function Convert-ProcessRecord {
    param($Source, $Target)
    $item = [ordered]@{
        Id = 'process:' + $Target.ProcessId; ProcessId = $Target.ProcessId
        Name = $null; ExecutablePath = $null; RawCommandLine = $null; CreatedAt = $null
        RawCommandLineState = 'Unavailable'; RequiredForCollection = $Target.RequiredForCollection
        SourceKinds = @($Target.SourceKinds); RelatedServiceIds = @($Target.RelatedServiceIds); EndpointIds = @($Target.EndpointIds)
        AssociationStatus = 'UnconfirmedPidMatch'; FileRecordId = $null; RecordStatus = 'Success'
    }
    $mapping = [ordered]@{ Name = 'Name'; ExecutablePath = 'ExecutablePath'; RawCommandLine = 'CommandLine'; CreatedAt = 'CreationDate' }
    foreach ($field in $mapping.Keys) {
        try {
            $value = Read-ObservedProperty $Source $mapping[$field]
            if ($null -eq $value) { throw 'ProcessFieldUnavailable' }
            if ($field -eq 'CreatedAt') {
                if ($value -is [datetimeoffset]) { $item.CreatedAt = $value.UtcDateTime.ToString('o') }
                elseif ($value -is [datetime]) { $item.CreatedAt = $value.ToUniversalTime().ToString('o') }
                else { throw 'ProcessCreationTimeInvalid' }
            }
            else {
                if ($value -isnot [string] -or ($field -ne 'RawCommandLine' -and [string]::IsNullOrEmpty($value))) {
                    throw 'ProcessTextUnavailable'
                }
                $item[$field] = $value
            }
        }
        catch {
            $item.RecordStatus = 'Partial'
            $problem = Get-CollectionFailure $_ RecordReadFailed
            Add-InventoryIssue Collection Processes Parse $problem.Code $problem.Message $item.Id
        }
    }
    if ($null -ne $item.RawCommandLine) {
        $item.RawCommandLineState = if ($item.RawCommandLine -ceq '') { 'Empty' } else { 'Collected' }
    }
    [pscustomobject]$item
}

function Invoke-ProcessTargetQueries {
    param([object[]]$Targets)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $started = $null; $completed = $null; $usable = $false; $incomplete = $false; $failed = $false
    for ($offset = 0; $offset -lt $Targets.Count; $offset += 32) {
        $last = [Math]::Min($offset + 31, $Targets.Count - 1)
        $batch = @($Targets[$offset..$last])
        $batchMap = @{}
        foreach ($target in $batch) { $batchMap[[string]$target.ProcessId] = $target }
        $filter = ($batch | ForEach-Object { 'ProcessId = ' + $_.ProcessId }) -join ' OR '
        $state = @{ InvalidRecord = $false; Seen = @{} }
        $failure = $null
        if ($null -eq $started) { $started = [datetime]::UtcNow.ToString('o') }
        try {
            Get-CimInstance -ClassName Win32_Process -Property ProcessId,Name,CreationDate,ExecutablePath,CommandLine -Filter $filter -OperationTimeoutSec 30 -ErrorAction Stop |
                ForEach-Object {
                    $recordId = $null
                    try {
                        $number = Convert-ObservedUInt32 (Read-ObservedProperty $_ ProcessId)
                        $key = [string]$number
                        if ($number -eq 0 -or -not $batchMap.ContainsKey($key)) { throw 'UnexpectedProcessIdentity' }
                        $recordId = 'process:' + $number
                        if ($state.Seen.ContainsKey($key)) { throw 'DuplicateProcessIdentity' }
                        $target = $batchMap[$key]
                        $item = Convert-ProcessRecord $_ $target
                        $state.Seen[$key] = $true
                        $target.Result = $item
                        $target.Outcome.ProcessRecordId = $item.Id
                        $target.Outcome.Outcome = if ($item.RecordStatus -eq 'Success') { 'Returned' } else { 'PartialMetadata' }
                        $items.Add($item)
                    }
                    catch {
                        $state.InvalidRecord = $true
                        $problem = Get-CollectionFailure $_ RecordReadFailed
                        Add-InventoryIssue Collection Processes Parse $problem.Code $problem.Message $recordId
                    }
                }
        }
        catch { $failure = Get-CollectionFailure $_ }
        $completed = [datetime]::UtcNow.ToString('o')
        if ($null -eq $failure -and -not $state.InvalidRecord) { $usable = $true }
        if ($null -ne $failure -or $state.InvalidRecord) { $incomplete = $true }
        if ($state.InvalidRecord -or ($null -ne $failure -and $failure.Status -eq 'Failed')) { $failed = $true }
        foreach ($target in $batch) {
            if ($null -ne $target.Result) {
                $usable = $true
                if ($target.Result.RecordStatus -eq 'Partial') { $incomplete = $true }
            }
            else {
                $incomplete = $true
                if ($null -ne $failure) {
                    $target.Outcome.Outcome = $failure.Status
                    Add-InventoryIssue Collection Processes Collect $failure.Code $failure.Message $target.Outcome.TargetId
                }
                elseif ($state.InvalidRecord) {
                    $target.Outcome.Outcome = 'Failed'
                    Add-InventoryIssue Collection Processes Parse RecordReadFailed 'A requested process could not be represented reliably.' $target.Outcome.TargetId
                }
                else {
                    $target.Outcome.Outcome = 'NotReturned'
                    Add-InventoryIssue Collection Processes Collect ProcessNotReturned 'A requested PID was not returned; an exit is possible but not confirmed.' $target.Outcome.TargetId
                }
            }
        }
        if ($null -ne $failure -and @($batch | Where-Object { $null -eq $_.Result }).Count -eq 0) {
            Add-InventoryIssue Collection Processes Collect $failure.Code $failure.Message
        }
    }
    $status = if ($Targets.Count -eq 0 -or ($usable -and -not $incomplete)) { 'Success' }
        elseif ($usable) { 'Partial' } elseif ($failed) { 'Failed' } else { 'Unavailable' }
    [pscustomobject]@{ Status = $status; Items = $items.ToArray(); QueryStartedAt = $started; QueryCompletedAt = $completed }
}

function Get-ProcessAssociationStatus {
    param($Process, [string]$Outcome, [string]$SourceCompletedAt)
    if ($null -eq $Process) {
        if ($Outcome -in @('NotReturned', 'Skipped')) { return $Outcome }
        return 'Unavailable'
    }
    $created = [datetimeoffset]::MinValue; $sourceEnd = [datetimeoffset]::MinValue
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $styles = [Globalization.DateTimeStyles]::None
    if ($Process.CreatedAt -and $SourceCompletedAt -and
        [datetimeoffset]::TryParse($Process.CreatedAt, $culture, $styles, [ref]$created) -and
        [datetimeoffset]::TryParse($SourceCompletedAt, $culture, $styles, [ref]$sourceEnd) -and $created -gt $sourceEnd) {
        return 'PossiblePidReuse'
    }
    return 'UnconfirmedPidMatch'
}

function Get-ProcessDataset {
    param($Services, $NetworkEndpoints, [System.Collections.IDictionary]$Budget)
    $serviceGroups = @{}; $endpointGroups = @{}; $targets = @{}
    $known = $Services.Status -in @('Success', 'Partial')
    foreach ($name in @('ServiceProcesses', 'AdditionalProcesses')) {
        $Budget[$name] = [ordered]@{ CandidateCount = $null; AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0 }
    }
    foreach ($service in $Services.Items) {
        if ($service.State -ne 'Running' -or $null -eq $service.ProcessId -or $service.ProcessId -eq 0) { continue }
        $key = [string]$service.ProcessId
        if (-not $serviceGroups.ContainsKey($key)) { $serviceGroups[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $serviceGroups[$key].Add($service)
    }
    foreach ($endpoint in $NetworkEndpoints.Items) {
        if ($null -eq $endpoint.ProcessId) { continue }
        $key = [string]$endpoint.ProcessId
        if ($serviceGroups.ContainsKey($key)) {
            $endpoint.RelatedServiceIds = @($serviceGroups[$key].ToArray() | Sort-Object Id | ForEach-Object { $_.Id })
            $endpoint.ServiceAssociationStatus = 'UnconfirmedPidMatch'
        }
        else { $endpoint.ServiceAssociationStatus = if ($Services.Status -eq 'Success') { 'NoObservedMatch' } else { 'Unknown' } }
        if ($null -eq $endpoint.ProcessId -or $endpoint.ProcessId -eq 0) { continue }
        if (-not $endpointGroups.ContainsKey($key)) { $endpointGroups[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $endpointGroups[$key].Add($endpoint)
    }
    $requiredTargets = @(); $additionalTargets = @()
    if ($known) {
        $requiredKeys = @($serviceGroups.Keys | Sort-Object { [uint32]$_ })
        $additionalKeys = @($endpointGroups.Keys | Where-Object { -not $serviceGroups.ContainsKey($_) } | Sort-Object { [uint32]$_ })
        foreach ($key in @($requiredKeys) + @($additionalKeys)) {
            $required = $serviceGroups.ContainsKey($key)
            $related = [string[]]@(); $endpoints = [object[]]@()
            if ($required) { $related = [string[]]@($serviceGroups[$key].ToArray() | Sort-Object Id | ForEach-Object { $_.Id }) }
            if ($endpointGroups.ContainsKey($key)) { $endpoints = $endpointGroups[$key].ToArray() }
            $kinds = @()
            if ($required) { $kinds += 'RunningService' }
            if (@($endpoints | Where-Object { $_.Protocol -eq 'TCP' }).Count -gt 0) { $kinds += 'TCPListener' }
            if (@($endpoints | Where-Object { $_.Protocol -eq 'UDP' }).Count -gt 0) { $kinds += 'UDPEndpoint' }
            $targets[$key] = [pscustomobject]@{
                ProcessId = [uint32]$key; RequiredForCollection = $required; RelatedServiceIds = [string[]]@($related)
                EndpointIds = [string[]]@($endpoints | ForEach-Object { $_.Id }); SourceKinds = [string[]]@($kinds); Result = $null
                Outcome = [pscustomobject]@{
                    TargetId = 'process:' + $key; ProcessId = [uint32]$key; RequiredForCollection = $required
                    ProcessRecordId = $null; Outcome = 'Skipped'
                }
            }
        }
        $requiredTargets = @($requiredKeys | ForEach-Object { $targets[$_] })
        $additionalTargets = @($additionalKeys | ForEach-Object { $targets[$_] })
    }
    $core = Invoke-ProcessTargetQueries $requiredTargets
    $extra = Invoke-ProcessTargetQueries @()
    if (-not $known) {
        $core.Status = $Services.Status; $extra.Status = 'Unavailable'
        Add-InventoryIssue Collection Processes Prerequisite PrerequisiteUnavailable 'Required service PID selection is unavailable; process enrichment was not attempted.'
    }
    else {
        if ($Services.Status -eq 'Partial' -and $core.Status -eq 'Success') { $core.Status = 'Partial' }
        if ($Services.Status -eq 'Success') { $Budget.ServiceProcesses.CandidateCount = $requiredTargets.Count }
        if ($NetworkEndpoints.Status -eq 'Success') { $Budget.AdditionalProcesses.CandidateCount = $additionalTargets.Count }
        if ($core.Status -in @('Success', 'Partial')) {
            $selected = @($additionalTargets | Select-Object -First 128)
            $extra = Invoke-ProcessTargetQueries $selected
            foreach ($target in @($additionalTargets | Select-Object -Skip 128)) {
                Add-InventoryIssue Collection Processes Collect LimitReached 'Additional endpoint-derived PID was skipped by the 128-PID enrichment limit.' $target.Outcome.TargetId
            }
            $Budget.AdditionalProcesses.AttemptedCount = $selected.Count
            if ($extra.Status -eq 'Success' -and ($additionalTargets.Count -gt 128 -or $NetworkEndpoints.Status -ne 'Success')) {
                $extra.Status = if ($additionalTargets.Count -eq 0 -and $NetworkEndpoints.Status -in @('Unavailable', 'Failed')) { $NetworkEndpoints.Status } else { 'Partial' }
            }
        }
        else {
            $extra.Status = 'Unavailable'
            foreach ($target in $additionalTargets) {
                Add-InventoryIssue Collection Processes Prerequisite PrerequisiteUnavailable 'Optional process enrichment was skipped because required process coverage is unavailable or failed.' $target.Outcome.TargetId
            }
        }
        $Budget.ServiceProcesses.AttemptedCount = $requiredTargets.Count
        $Budget.ServiceProcesses.CompletedCount = @($core.Items).Count
        $Budget.ServiceProcesses.UnusableCount = $requiredTargets.Count - @($core.Items).Count
        $Budget.AdditionalProcesses.CompletedCount = @($extra.Items).Count
        $Budget.AdditionalProcesses.UnusableCount = $Budget.AdditionalProcesses.AttemptedCount - @($extra.Items).Count
        $Budget.AdditionalProcesses.SkippedCount = $additionalTargets.Count - $Budget.AdditionalProcesses.AttemptedCount
    }
    $serviceEnd = @($Services.Coverage | Where-Object { $_.SourceId -eq 'Win32_Service' } | ForEach-Object { $_.QueryCompletedAt } | Select-Object -First 1)
    $possibleReuse = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($target in @($requiredTargets) + @($additionalTargets)) {
        $process = $target.Result
        $matchingServices = [object[]]@()
        if ($serviceGroups.ContainsKey([string]$target.ProcessId)) { $matchingServices = $serviceGroups[[string]$target.ProcessId].ToArray() }
        foreach ($service in $matchingServices) {
            $service.ProcessRecordId = $target.Outcome.ProcessRecordId
            $service.ProcessAssociationStatus = Get-ProcessAssociationStatus $process $target.Outcome.Outcome ($serviceEnd -join '')
            if ($service.ProcessAssociationStatus -eq 'PossiblePidReuse') { [void]$possibleReuse.Add($process.Id) }
        }
    }
    $sourceEnds = @{}
    foreach ($coverage in $NetworkEndpoints.Coverage) { $sourceEnds[$coverage.SourceId] = $coverage.QueryCompletedAt }
    foreach ($endpoint in $NetworkEndpoints.Items) {
        if ($null -eq $endpoint.ProcessId) { continue }
        $target = $targets[[string]$endpoint.ProcessId]
        if ($null -eq $target) { $endpoint.ProcessAssociationStatus = 'Skipped'; continue }
        $sourceId = if ($endpoint.Protocol -eq 'TCP') { 'TCPListeners' } else { 'UDPEndpoints' }
        $endpoint.ProcessRecordId = $target.Outcome.ProcessRecordId
        $endpoint.ProcessAssociationStatus = Get-ProcessAssociationStatus $target.Result $target.Outcome.Outcome $sourceEnds[$sourceId]
        if ($endpoint.ProcessAssociationStatus -eq 'PossiblePidReuse') { [void]$possibleReuse.Add($target.Result.Id) }
    }
    $items = @($core.Items) + @($extra.Items)
    foreach ($process in $items) {
        if ($possibleReuse.Contains($process.Id)) {
            $process.AssociationStatus = 'PossiblePidReuse'
            Add-InventoryIssue Collection Processes Correlate PossiblePidReuse 'Process creation is later than a contributing source snapshot; PID reuse or non-atomic observation is possible.' $process.Id
        }
    }
    $result = New-InventoryDataset Processes $true $core.Status $items @(
        'All observed positive running-service PIDs are required; no service-PID count cap.'
        'Additional endpoint-derived PIDs: ascending numeric order, at most 128; both scopes use batches of at most 32 PIDs and OperationTimeoutSec 30, without retries.'
        'PID-only, non-atomic associations are uncertain; missing or overlapping creation timestamps cannot exclude PID reuse. Zero PIDs are not enrichment targets.'
    )
    $result.Coverage = @(
        [pscustomobject]@{ SourceId = 'ServiceProcessTargets'; Required = $true; Status = $core.Status; QueryStartedAt = $core.QueryStartedAt; QueryCompletedAt = $core.QueryCompletedAt },
        [pscustomobject]@{ SourceId = 'AdditionalEndpointTargets'; Required = $false; Status = $extra.Status; QueryStartedAt = $extra.QueryStartedAt; QueryCompletedAt = $extra.QueryCompletedAt }
    )
    $result | Add-Member -NotePropertyName InputStatus -NotePropertyValue ([ordered]@{ Services = $Services.Status; NetworkEndpoints = $NetworkEndpoints.Status })
    $outcomes = [object[]]@(@($requiredTargets) + @($additionalTargets) | ForEach-Object { $_.Outcome })
    $result | Add-Member -NotePropertyName TargetOutcomes -NotePropertyValue $outcomes
    $result
}

function Test-FileEnrichmentHost {
    [Environment]::Is64BitOperatingSystem -and [Environment]::Is64BitProcess
}

function Get-WindowsDirectory {
    [Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
}

function Resolve-ConfiguredExecutablePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine -match '[\x00-\x1F]') { return $null }
    $text = $CommandLine.TrimStart()
    if ($text.StartsWith('"')) {
        $match = [regex]::Match($text, '^"([^"]+\.(?i:exe|com))"(?=\s|$)')
    }
    else {
        # An explicit executable suffix avoids interpreting C:\Program Files as
        # C:\Program. Never probe for existing prefixes or search PATH.
        $match = [regex]::Match($text, '^(\S+\.(?i:exe|com))(?=\s|$)')
    }
    if (-not $match.Success) { return $null }
    $match.Groups[1].Value
}

function ConvertTo-ExecutablePath {
    param([string]$Path)
    $result = [pscustomobject]@{ Path = $null; Code = 'PathUnresolved' }
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1F"*?<>|]') { return $result }
    $pathText = $Path.Replace('/', '\')
    if ($pathText -match '(?i)^(?:%SystemRoot%|%windir%|\\SystemRoot)\\') {
        $prefixLength = $Matches[0].Length
        $windows = Get-WindowsDirectory
        if ([string]::IsNullOrEmpty($windows)) { return $result }
        $pathText = $windows.TrimEnd('\') + '\' + $pathText.Substring($prefixLength)
    }
    if ($pathText -notmatch '^[A-Za-z]:\\') {
        if ($pathText.StartsWith('\')) { $result.Code = 'RemotePathSkipped' }
        return $result
    }
    if ($pathText.Substring(2).Contains(':') -or $pathText.Contains('%') -or $pathText.EndsWith('\')) { return $result }
    foreach ($part in $pathText.Substring(3).Split('\')) {
        # Collapsing dot segments before checking reparse components could inspect
        # a different file than Windows would resolve from the original path.
        if ($part -in @('.', '..')) { return $result }
        if ($part -match '[. ]$' -or $part -match '(?i)^(CON(?:IN\$|OUT\$)?|PRN|AUX|NUL|(?:COM|LPT)[0-9\u00B9\u00B2\u00B3])(?:\.|$)') { return $result }
    }
    try {
        $result.Path = [IO.Path]::GetFullPath($pathText)
        $result.Code = $null
    }
    catch { $result.Path = $null }
    $result
}

function Get-ExecutableDriveType {
    param([string]$Root)
    ([IO.DriveInfo]::new($Root)).DriveType
}

function Get-ExecutableAttributes {
    param([string]$Path)
    [IO.File]::GetAttributes($Path)
}

function Get-ExecutablePathState {
    param([string]$Path)
    # Call only with an already normalized drive-qualified path. No content API
    # runs until locality and every existing path component have been checked.
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')) { return 'RemotePathSkipped' }
    $root = [IO.Path]::GetPathRoot($Path)
    $driveType = Get-ExecutableDriveType $root
    if ($driveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { return 'RemotePathSkipped' }
    $cursor = $root
    foreach ($part in @('') + @($Path.Substring($root.Length).Split('\') | Where-Object { $_ -ne '' })) {
        if ($part) { $cursor = [IO.Path]::Combine($cursor, $part) }
        try { $attributes = Get-ExecutableAttributes $cursor }
        catch [IO.FileNotFoundException] { return 'Missing' }
        catch [IO.DirectoryNotFoundException] { return 'Missing' }
        if (([int]$attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { return 'ReparsePointSkipped' }
        $directory = ([int]$attributes -band [int][IO.FileAttributes]::Directory) -ne 0
        if ($cursor -ne $Path -and -not $directory) { return 'Missing' }
        if ($cursor -eq $Path -and $directory) { return 'NotFile' }
    }
    'Present'
}

function Get-ExecutableFacts {
    param([string]$Path)
    $info = [IO.FileInfo]::new($Path)
    $info.Refresh()
    # Length throws for a missing/denied file; FileInfo.Exists would hide errors.
    [pscustomobject]@{ LengthBytes = [long]$info.Length; LastWriteTimeUtc = $info.LastWriteTimeUtc.ToString('o') }
}

function Get-ExecutableVersion {
    param([string]$Path)
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $values = [ordered]@{}
    foreach ($field in @('FileVersion', 'ProductVersion', 'CompanyName', 'ProductName')) {
        $values[$field] = if ([string]::IsNullOrEmpty($version.$field)) { $null } else { $version.$field }
    }
    [pscustomobject]$values
}

function Open-ExecutableStream {
    param([string]$Path)
    $share = [IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    # The caller owns the 64 KiB buffer. A one-byte internal buffer avoids
    # additional managed read-ahead beyond the caller's bounded read request.
    [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share, 1, [IO.FileOptions]::SequentialScan)
}

function Get-FilePhaseElapsedSeconds {
    param($Clock)
    $Clock.Elapsed.TotalSeconds
}

function Add-ExecutableIssue {
    param($Candidate, [string]$Stage, [string]$Code, [string]$Message)
    Add-InventoryIssue -Kind Collection -DatasetId ExecutableFiles -Stage $Stage -Code $Code -Message $Message -RecordId $Candidate.Id -SourceRefs @($Candidate.SourceRefs)
}

function Get-ExecutableCandidates {
    param($Services, $Processes, $Clock)
    $paths = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $complete = $Services.Status -eq 'Success' -and $Processes.Status -eq 'Success' -and
        @($Processes.Coverage | Where-Object { $_.Status -ne 'Success' }).Count -eq 0
    $excluded = 0; $preflightSkipped = 0; $unverifiedSources = 0; $unexpected = $false
    foreach ($source in @($Services.Items) + @($Processes.Items)) {
        $service = $source.Id.StartsWith('service:')
        $source.FileRecordId = $null
        $datasetId = if ($service) { 'Services' } else { 'Processes' }
        $reference = [pscustomobject]@{ DatasetId = $datasetId; RecordId = $source.Id }
        $diagnostic = [pscustomobject]@{ Id = $null; SourceRefs = @($reference) }
        if ($service) {
            $source.ExecutablePath = $null
            $source.PathResolution = if ($source.RawCommandLineState -eq 'Unavailable') { 'Unavailable' } else { 'Unresolved' }
            $token = Resolve-ConfiguredExecutablePath $source.RawCommandLine
        }
        else { $token = $source.ExecutablePath }
        $normalized = ConvertTo-ExecutablePath $token
        if ($null -eq $normalized.Path) {
            $complete = $false; $excluded++
            Add-ExecutableIssue $diagnostic Resolve $normalized.Code 'A source executable path could not be resolved safely; no file content was inspected.'
            continue
        }
        if ($service) { $source.ExecutablePath = $normalized.Path; $source.PathResolution = 'Resolved' }
        $priority = if (($service -and $source.State -eq 'Running') -or (-not $service -and $source.RequiredForCollection)) { 0 }
            elseif ($service) { 1 } else { 2 }
        if (-not $paths.ContainsKey($normalized.Path)) {
            $paths[$normalized.Path] = [pscustomobject]@{
                Id = $null; Path = $normalized.Path; Priority = $priority; SourceRefs = @(); Owners = @(); Row = $null; HashBlockedReason = $null
            }
        }
        $candidate = $paths[$normalized.Path]
        if ([StringComparer]::Ordinal.Compare($normalized.Path, $candidate.Path) -lt 0) { $candidate.Path = $normalized.Path }
        $candidate.Priority = [Math]::Min($candidate.Priority, $priority)
        $candidate.SourceRefs += $reference
        $candidate.Owners += $source
    }
    $orderedPaths = [string[]]@($paths.Keys)
    [array]::Sort($orderedPaths, [StringComparer]::OrdinalIgnoreCase)
    $safe = New-Object 'System.Collections.Generic.List[object]'
    foreach ($path in $orderedPaths) {
        $candidate = $paths[$path]
        $candidate.SourceRefs = @($candidate.SourceRefs | Sort-Object DatasetId,RecordId)
        if ((Get-FilePhaseElapsedSeconds $Clock) -ge 60) {
            $complete = $false
            # This deduplicated path has not been tested for eligibility. It is
            # disjoint from the verified paths later omitted by the selection cap.
            $preflightSkipped++
            $unverifiedSources += $candidate.SourceRefs.Count
            Add-ExecutableIssue $candidate Prerequisite LimitReached 'Path verification was not started because the file-phase scheduling budget was exhausted.'
            continue
        }
        try {
            $state = Get-ExecutablePathState $candidate.Path
            if ($state -notin @('Present', 'Missing')) {
                $complete = $false; $excluded += $candidate.SourceRefs.Count
                $code = if ($state -eq 'NotFile') { 'PathUnresolved' } else { $state }
                Add-ExecutableIssue $candidate Prerequisite $code 'A source path is remote, redirected, unsupported, or not a regular file; no content was inspected.'
                continue
            }
            $safe.Add($candidate)
        }
        catch {
            $complete = $false; $excluded += $candidate.SourceRefs.Count
            $problem = Get-CollectionFailure $_ RecordReadFailed
            if ($problem.Status -eq 'Failed') { $unexpected = $true }
            Add-ExecutableIssue $candidate Prerequisite $problem.Code $problem.Message
        }
    }
    # Stable IDs use the entire safe path-sorted list, before priority/cap selection.
    for ($index = 0; $index -lt $safe.Count; $index++) { $safe[$index].Id = 'file:' + ($index + 1) }
    $selectedOrder = @(foreach ($priority in 0..2) { foreach ($candidate in $safe.ToArray()) { if ($candidate.Priority -eq $priority) { $candidate } } })
    [pscustomobject]@{
        Candidates = $selectedOrder; Complete = $complete; ExcludedSourceCount = $excluded
        PreflightSkippedCount = $preflightSkipped; UnverifiedSourceCount = $unverifiedSources; UnexpectedFailure = $unexpected
    }
}

function Read-ExecutableMetadata {
    param($Candidate, $Clock)
    $state = Get-ExecutablePathState $Candidate.Path
    if ($state -notin @('Present', 'Missing')) { throw 'ExecutablePathChanged' }
    $row = [pscustomobject][ordered]@{
        Id = $Candidate.Id; Path = $Candidate.Path; SourceRefs = @($Candidate.SourceRefs); FileState = $state
        LengthBytes = $null; LastWriteTimeUtc = $null
        FileVersion = $null; ProductVersion = $null; CompanyName = $null; ProductName = $null
        MetadataStatus = 'Collected'; HashStatus = 'Skipped'; SHA256 = $null
        SignatureMode = 'NotInvoked'; SignatureStatus = 'Skipped'; NativeSignatureStatus = $null; NativeSignatureType = $null
        SignerSubject = $null; SignerThumbprint = $null; RecordStatus = 'Partial'
    }
    if ($state -eq 'Missing') {
        Add-ExecutableIssue $Candidate Collect FileMissing 'The verified local path did not identify an existing file at collection time.'
        return $row
    }
    try {
        $facts = Get-ExecutableFacts $Candidate.Path
        if ($facts.LengthBytes -lt 0) { throw 'ExecutableLengthInvalid' }
        $row.LengthBytes = $facts.LengthBytes; $row.LastWriteTimeUtc = $facts.LastWriteTimeUtc
        if ((Get-FilePhaseElapsedSeconds $Clock) -ge 60) {
            $row.MetadataStatus = 'Skipped'; $Candidate.HashBlockedReason = 'LimitReached'
            Add-ExecutableIssue $Candidate Collect LimitReached 'Version-resource collection was not started after the file-phase scheduling budget was exhausted.'
            return $row
        }
        if ((Get-ExecutablePathState $Candidate.Path) -ne 'Present') {
            $row.MetadataStatus = 'Failed'; $Candidate.HashBlockedReason = 'FileChanged'
            Add-ExecutableIssue $Candidate Collect FileChanged 'The file path changed during metadata collection; no hash will be published.'
            return $row
        }
        $version = Get-ExecutableVersion $Candidate.Path
        foreach ($field in @('FileVersion', 'ProductVersion', 'CompanyName', 'ProductName')) { $row.$field = $version.$field }
        if ((Get-ExecutablePathState $Candidate.Path) -ne 'Present') {
            $row.MetadataStatus = 'Failed'; $Candidate.HashBlockedReason = 'FileChanged'
            Add-ExecutableIssue $Candidate Collect FileChanged 'The file path changed during metadata collection; no hash will be published.'
            return $row
        }
        $after = Get-ExecutableFacts $Candidate.Path
        if ($after.LengthBytes -ne $row.LengthBytes -or $after.LastWriteTimeUtc -ne $row.LastWriteTimeUtc) {
            $row.MetadataStatus = 'Failed'; $Candidate.HashBlockedReason = 'FileChanged'
            Add-ExecutableIssue $Candidate Collect FileChanged 'The file changed during metadata collection; its hash will not be published.'
        }
    }
    catch {
        $problem = Get-CollectionFailure $_ RecordReadFailed
        $row.MetadataStatus = if ($problem.Status -eq 'Unavailable') { 'Unavailable' } else { 'Failed' }
        $Candidate.HashBlockedReason = $problem.Code
        Add-ExecutableIssue $Candidate Collect $problem.Code $problem.Message
    }
    $row
}

function Get-ExecutableHash {
    param($Candidate, $Clock, [System.Collections.IDictionary]$Budget)
    $stream = $null; $algorithm = $null
    $result = [pscustomobject]@{ Status = 'Failed'; SHA256 = $null; Code = 'FileChanged' }
    try {
        if ((Get-ExecutablePathState $Candidate.Path) -ne 'Present') { return $result }
        $before = Get-ExecutableFacts $Candidate.Path
        if ($before.LengthBytes -ne $Candidate.Row.LengthBytes -or $before.LastWriteTimeUtc -ne $Candidate.Row.LastWriteTimeUtc) { return $result }
        if ((Get-FilePhaseElapsedSeconds $Clock) -ge 60) { $result.Status = 'Skipped'; $result.Code = 'LimitReached'; return $result }
        $stream = Open-ExecutableStream $Candidate.Path
        if ($stream.Length -ne $before.LengthBytes) { return $result }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $buffer = New-Object byte[] 65536
        $readTotal = [long]0
        while ($readTotal -lt $before.LengthBytes) {
            $remaining = [long]536870912 - $Budget.HashBytesRead
            if ((Get-FilePhaseElapsedSeconds $Clock) -ge 60 -or $remaining -le 0) {
                $result.Status = 'Skipped'; $result.Code = 'LimitReached'; return $result
            }
            $requested = [int][Math]::Min([long]$buffer.Length, [Math]::Min($remaining, $before.LengthBytes - $readTotal))
            $position = $stream.Position
            try { $count = $stream.Read($buffer, 0, $requested) }
            catch {
                # Include any position advance reported by a failed read as well
                # as all successful reads. No partial digest is retained.
                $advance = $stream.Position - $position
                if ($advance -gt 0 -and $advance -le $requested) { $Budget.HashBytesRead += $advance }
                throw
            }
            $Budget.HashBytesRead += $count
            $readTotal += $count
            if ($count -le 0) { return $result }
            [void]$algorithm.TransformBlock($buffer, 0, $count, $buffer, 0)
        }
        if ($stream.Length -ne $before.LengthBytes -or (Get-ExecutablePathState $Candidate.Path) -ne 'Present') { return $result }
        $after = Get-ExecutableFacts $Candidate.Path
        if ($after.LengthBytes -ne $before.LengthBytes -or $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc) { return $result }
        if ((Get-FilePhaseElapsedSeconds $Clock) -ge 60) { $result.Status = 'Skipped'; $result.Code = 'LimitReached'; return $result }
        [void]$algorithm.TransformFinalBlock([byte[]]@(), 0, 0)
        $result.SHA256 = [BitConverter]::ToString($algorithm.Hash).Replace('-', '')
        $result.Status = 'Collected'; $result.Code = $null
    }
    catch {
        $problem = Get-CollectionFailure $_ RecordReadFailed
        $result.Status = if ($problem.Status -eq 'Unavailable') { 'Unavailable' } else { 'Failed' }
        $result.Code = $problem.Code
    }
    finally {
        try { if ($null -ne $algorithm) { $algorithm.Dispose() } }
        finally { if ($null -ne $stream) { $stream.Dispose() } }
    }
    $result
}

function Get-ExecutableDataset {
    param($Services, $Processes, [System.Collections.IDictionary]$Budget)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $metadataStarted = $null; $metadataCompleted = $null; $hashStarted = $null; $hashCompleted = $null
    foreach ($name in @('Files', 'Hashes', 'Signatures')) {
        $Budget[$name] = [ordered]@{ CandidateCount = $null; AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0 }
    }
    $Budget.HashBytesRead = [long]0; $Budget.FilePhaseElapsedSeconds = 0
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $bundle = $null; $selected = @(); $unexpected = $false; $metadataStatus = 'Unavailable'; $hashStatus = 'Unavailable'
    $status = 'Unavailable'; $definitiveEmpty = $false; $hashFailed = $false
    try {
        if (-not (Test-FileEnrichmentHost)) {
            Add-InventoryIssue Collection ExecutableFiles Prerequisite CapabilityMissing 'File enrichment requires a 64-bit PowerShell process on a 64-bit Windows host; no relaunch was attempted.'
        }
        else {
            $bundle = Get-ExecutableCandidates $Services $Processes $clock
            $unexpected = $bundle.UnexpectedFailure
            $all = @($bundle.Candidates)
            $selected = @($all | Select-Object -First 256)
            # A safe observed subset is not a complete candidate total when
            # upstream coverage, resolution, or eligibility remains unknown.
            if ($bundle.Complete) { $Budget.Files.CandidateCount = $all.Count }
            $Budget.Files.SkippedCount = $bundle.PreflightSkippedCount + $all.Count - $selected.Count
            $Budget.Hashes.CandidateCount = $selected.Count; $Budget.Signatures.CandidateCount = $selected.Count
            $Budget.Signatures.SkippedCount = $selected.Count
            foreach ($candidate in @($all | Select-Object -Skip 256)) {
                Add-ExecutableIssue $candidate Prerequisite LimitReached 'Executable metadata was skipped by the 256-path selection limit.'
            }
            foreach ($candidate in $selected) {
                Add-ExecutableIssue $candidate Signature SignatureNetworkPolicy 'Native signature verification was not invoked because Windows trust evaluation may initiate network requests.'
                if ((Get-FilePhaseElapsedSeconds $clock) -ge 60) {
                    $Budget.Files.SkippedCount++
                    $candidate.HashBlockedReason = 'LimitReached'
                    Add-ExecutableIssue $candidate Collect LimitReached 'Metadata collection was not started after the file-phase scheduling budget was exhausted.'
                    continue
                }
                $Budget.Files.AttemptedCount++
                if ($null -eq $metadataStarted) { $metadataStarted = [datetime]::UtcNow.ToString('o') }
                try {
                    $candidate.Row = Read-ExecutableMetadata $candidate $clock
                    $rows.Add($candidate.Row)
                    $Budget.Files.CompletedCount++
                    foreach ($owner in $candidate.Owners) { $owner.FileRecordId = $candidate.Id }
                }
                catch {
                    $Budget.Files.UnusableCount++
                    $problem = Get-CollectionFailure $_ RecordReadFailed
                    $candidate.HashBlockedReason = $problem.Code
                    if ($problem.Status -eq 'Failed') { $unexpected = $true }
                    Add-ExecutableIssue $candidate Collect $problem.Code $problem.Message
                }
                $metadataCompleted = [datetime]::UtcNow.ToString('o')
            }
            # Metadata is completed/scheduled first; hashes follow in the same order.
            foreach ($candidate in $selected) {
                $row = $candidate.Row
                $reason = $null
                if ($candidate.HashBlockedReason) { $reason = $candidate.HashBlockedReason }
                elseif ($null -eq $row) { $reason = 'PrerequisiteUnavailable' }
                elseif ($row.FileState -eq 'Missing') { $reason = 'FileMissing' }
                elseif ($null -eq $row.LengthBytes) { $reason = 'PrerequisiteUnavailable' }
                elseif ($row.LengthBytes -gt 67108864) { $reason = 'HashFileTooLarge' }
                elseif ($row.LengthBytes -gt ([long]536870912 - $Budget.HashBytesRead)) { $reason = 'LimitReached' }
                elseif ((Get-FilePhaseElapsedSeconds $clock) -ge 60) { $reason = 'LimitReached' }
                if ($reason) {
                    $Budget.Hashes.SkippedCount++
                    Add-ExecutableIssue $candidate Hash $reason 'Hashing was skipped because file eligibility, prerequisites, or a reviewed budget did not permit a complete hash.'
                    continue
                }
                $Budget.Hashes.AttemptedCount++
                if ($null -eq $hashStarted) { $hashStarted = [datetime]::UtcNow.ToString('o') }
                try { $hash = Get-ExecutableHash $candidate $clock $Budget }
                catch {
                    $problem = Get-CollectionFailure $_ RecordReadFailed
                    $hash = [pscustomobject]@{ Status = if ($problem.Status -eq 'Unavailable') { 'Unavailable' } else { 'Failed' }; SHA256 = $null; Code = $problem.Code }
                }
                $row.HashStatus = $hash.Status; $row.SHA256 = $hash.SHA256
                if ($hash.Status -eq 'Collected') { $Budget.Hashes.CompletedCount++ }
                else {
                    $Budget.Hashes.UnusableCount++
                    if ($hash.Status -eq 'Failed') { $hashFailed = $true }
                    Add-ExecutableIssue $candidate Hash $hash.Code 'A complete, unchanged-file SHA256 result could not be confirmed; no hash was published.'
                }
                $hashCompleted = [datetime]::UtcNow.ToString('o')
            }
            $definitiveEmpty = $bundle.Complete -and $all.Count -eq 0
            if ($definitiveEmpty) { $status = 'Success'; $metadataStatus = 'Success'; $hashStatus = 'Success' }
            elseif ($rows.Count -gt 0) {
                $status = 'Partial' # Signatures are deliberately unavailable under no-network policy.
                $metadataStatus = if ($bundle.Complete -and $Budget.Files.SkippedCount -eq 0 -and $Budget.Files.UnusableCount -eq 0 -and @($rows.ToArray() | Where-Object { $_.MetadataStatus -ne 'Collected' }).Count -eq 0) { 'Success' } else { 'Partial' }
                $hashStatus = if ($Budget.Hashes.CompletedCount -gt 0) { 'Partial' } elseif ($hashFailed) { 'Failed' } else { 'Unavailable' }
                if ($bundle.Complete -and $Budget.Files.SkippedCount -eq 0 -and $Budget.Hashes.CompletedCount -eq $selected.Count) { $hashStatus = 'Success' }
            }
            elseif ($unexpected) { $status = 'Failed'; $metadataStatus = 'Failed' }
        }
    }
    catch {
        $problem = Get-CollectionFailure $_ RecordReadFailed
        Add-InventoryIssue Collection ExecutableFiles Collect $problem.Code $problem.Message
        $status = if ($rows.Count -gt 0) { 'Partial' } else { $problem.Status }
        $metadataStatus = $status
    }
    finally { $Budget.FilePhaseElapsedSeconds = Get-FilePhaseElapsedSeconds $clock; $clock.Stop() }
    $limits = @(
        'At most 256 paths; running-service paths first, other configured-service paths next, additional-network process paths last; ordinal case-insensitive path order within each tier.'
        'Hash limits: 64 MiB per file, 512 MiB actual aggregate reads, 64 KiB streaming buffer. Metadata precedes hashes. File-phase scheduling budget: 60 seconds; blocking calls may exceed it.'
        'Signatures: NotInvoked/Skipped (SignatureNetworkPolicy). The 16-native-invocation allowance is reserved and unused.'
        'Path/reparse and size/time checks are point-in-time safeguards, not proof of atomic identity or of bytes loaded in memory. No service DLL or software-ownership inference.'
    )
    if ($null -ne $bundle) {
        $limits += 'Observed safe distinct paths: ' + @($bundle.Candidates).Count + '; excluded/unresolved source references: ' + $bundle.ExcludedSourceCount +
            '; scheduling-unverified distinct paths: ' + $bundle.PreflightSkippedCount + ' (source references: ' + $bundle.UnverifiedSourceCount + '). Unknown full candidate coverage is reported as null.'
    }
    $result = New-InventoryDataset ExecutableFiles $false $status $rows.ToArray() $limits
    $result.Coverage = @(
        [pscustomobject]@{ SourceId = 'FileMetadata'; Required = $true; Status = $metadataStatus; QueryStartedAt = $metadataStarted; QueryCompletedAt = $metadataCompleted },
        [pscustomobject]@{ SourceId = 'SHA256'; Required = $true; Status = $hashStatus; QueryStartedAt = $hashStarted; QueryCompletedAt = $hashCompleted },
        [pscustomobject]@{ SourceId = 'WindowsNativeSignatures'; Required = $true; Status = if ($definitiveEmpty) { 'Success' } else { 'Unavailable' }; QueryStartedAt = $null; QueryCompletedAt = $null }
    )
    $result | Add-Member -NotePropertyName SignaturePolicy -NotePropertyValue ([ordered]@{ Status = 'Skipped'; ReasonCode = 'SignatureNetworkPolicy' })
    $result
}

function Test-LocalNonReparsePath {
    param([string]$Path, [bool]$MustExist = $true)
    try {
        if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')) { return $false }
        $root = [IO.Path]::GetPathRoot($Path)
        $drive = [IO.DriveInfo]::new($root)
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { return $false }
        $cursor = $root
        $parts = @('') + @($Path.Substring($root.Length).Split('\') | Where-Object { $_ -ne '' })
        foreach ($part in $parts) {
            if ($part) { $cursor = [IO.Path]::Combine($cursor, $part) }
            try { $attributes = [IO.File]::GetAttributes($cursor) }
            catch [IO.FileNotFoundException] { return (-not $MustExist) }
            catch [IO.DirectoryNotFoundException] { return (-not $MustExist) }
            if (([int]$attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            if ($cursor -ne $Path -and ([int]$attributes -band [int][IO.FileAttributes]::Directory) -eq 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-RestrictedDescriptor {
    param([System.Security.AccessControl.RawSecurityDescriptor]$Descriptor, [string[]]$AllowedSids, [switch]$Ancestor)
    $trustedSids = @($AllowedSids)
    if ($Ancestor) {
        # Windows servicing may own/control ordinary ancestors, but is not added
        # to the stricter allowlist for report directories or report contents.
        $trustedSids += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
    }
    if ($null -eq $Descriptor.Owner -or $trustedSids -notcontains $Descriptor.Owner.Value) { return $false }
    if (([int]$Descriptor.ControlFlags -band [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        $null -eq $Descriptor.DiscretionaryAcl) { return $false }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        # Unknown/callback ACEs are not interpreted as safe; no effective-access engine.
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.IsCallback) { return $false }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($trustedSids -contains $ace.SecurityIdentifier.Value) { continue }
            $inheritOnly = (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0)
            if ($Ancestor) {
                # Other users may read/traverse or create siblings, but not replace
                # this directory or its protected children, or rewrite its DACL/owner.
                if ($inheritOnly) { continue }
                # DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL/WRITE.
                if (($ace.AccessMask -band 0x500D0040) -ne 0) { return $false }
            }
            elseif (-not ($inheritOnly -and $ace.SecurityIdentifier.Value -eq 'S-1-3-0')) {
                return $false
            }
        }
        elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) { return $false }
    }
    return $true
}

function Assert-ReportAncestors {
    param([string]$Path, [string[]]$AllowedSids)
    # Ancestors permit Windows servicing ownership and ordinary read/traverse;
    # untrusted replacement/control rights still fail closed, without ACL edits.
    $cursor = [IO.Directory]::GetParent($Path)
    while ($null -ne $cursor) {
        try { $attributes = [IO.File]::GetAttributes($cursor.FullName) }
        catch [IO.DirectoryNotFoundException] { $cursor = $cursor.Parent; continue }
        catch [IO.FileNotFoundException] { $cursor = $cursor.Parent; continue }
        if (([int]$attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ([int]$attributes -band [int][IO.FileAttributes]::Directory) -eq 0) { throw 'ReportAncestorUnverified' }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if (-not (Test-RestrictedDescriptor $descriptor $AllowedSids -Ancestor)) { throw 'ReportAncestorUnverified' }
        $cursor = $cursor.Parent
    }
}

function Assert-ProtectedReportPath {
    param([string]$Path, [string[]]$AllowedSids)
    if (-not (Test-LocalNonReparsePath $Path)) { throw 'ReportPathUnverified' }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if (-not (Test-RestrictedDescriptor $descriptor $AllowedSids)) { throw 'ReportProtectionUnverified' }
    Assert-ReportAncestors $Path $AllowedSids
}

function Remove-IncompleteReportFiles {
    param($Location, [string[]]$AllowedSids)
    if ($null -eq $Location) { return }
    $paths = $Location.CreatedPaths.ToArray()
    # Published JSON is added last: remove it first if final verification fails.
    [array]::Reverse($paths)
    foreach ($path in $paths) {
        try {
            if (-not [IO.File]::Exists($path)) { continue }
            Assert-ProtectedReportPath $Location.Directory $AllowedSids
            Assert-ProtectedReportPath $path $AllowedSids
            [IO.File]::Delete($path)
        }
        catch {
            Add-InventoryIssue Output $null Cleanup CleanupFailed 'An invocation-owned incomplete file could not be safely removed.'
        }
    }
}

function New-ProtectedReportLocation {
    param([string]$Root, [string]$HostFolder, [string]$RunId, [string[]]$AllowedSids)
    $location = $null
    try {
        if ($Root -match '^(\\\\|//)' -or $Root.Contains('::')) { throw 'RemoteOrProviderReportRootRejected' }
        $fullRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Root)
        $fullRoot = [IO.Path]::GetFullPath($fullRoot)
        if (-not (Test-LocalNonReparsePath $fullRoot $false)) { throw 'ReportRootUnverified' }
        $hostRoot = [IO.Path]::Combine($fullRoot, $HostFolder)
        Assert-ReportAncestors $hostRoot $AllowedSids
        [void][IO.Directory]::CreateDirectory($hostRoot)
        if (-not (Test-LocalNonReparsePath $hostRoot)) { throw 'ReportHostPathUnverified' }
        $stamp = 'ServiceSoftwareInventory_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
        $directory = [IO.Path]::Combine($hostRoot, $stamp)
        $suffix = 0
        while (Test-Path -LiteralPath $directory -ErrorAction Stop) {
            $suffix++
            $directory = [IO.Path]::Combine($hostRoot, ($stamp + '-' + $suffix))
        }
        # No -Force: a concurrent creator is not an invocation-owned directory.
        $created = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
        $location = [pscustomobject]@{
            Directory = $created.FullName; TemporaryPaths = [ordered]@{}
            CreatedPaths = (New-Object 'System.Collections.Generic.List[string]')
        }
        Assert-ProtectedReportPath $location.Directory $AllowedSids
        foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv', 'service-software.json')) {
            $path = [IO.Path]::Combine($location.Directory, ('.' + $name + '.' + $RunId + '.tmp'))
            $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $location.CreatedPaths.Add($path)
            $stream.Dispose()
            Assert-ProtectedReportPath $path $AllowedSids
            $location.TemporaryPaths[$name] = $path
        }
        return $location
    }
    catch { Remove-IncompleteReportFiles $location $AllowedSids; throw }
}

function Get-ServiceSoftwareSummary {
    param($Report, [switch]$Detailed)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Get-ServiceSoftwareInventory.ps1 0.1.0 - DEVELOPMENT Milestone 1.2C')
    $lines.Add('Development release: bounded file metadata/SHA256; signatures are not invoked under no-network policy.')
    $lines.Add('Hostname: ' + $Report.Hostname + '; RunId: ' + $Report.RunId)
    $lines.Add('Collection: ' + $Report.Collection.Status)
    foreach ($dataset in $Report.Collection.Datasets) {
        $count = if ($null -eq $dataset.Count) { '<unknown>' } else { [string]$dataset.Count }
        $lines.Add($dataset.Id + ': ' + $dataset.Status + '; retained records: ' + $count)
        if ($Detailed) { foreach ($note in $dataset.Limitations) { $lines.Add('  ' + $note) } }
    }
    $services = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'Services' })[0]
    if ($services.Status -in @('Success', 'Partial')) {
        $running = @($services.Items | Where-Object { $_.State -eq 'Running' }).Count
        $stopped = @($services.Items | Where-Object { $_.State -eq 'Stopped' }).Count
        $disabled = @($services.Items | Where-Object { $_.StartMode -eq 'Disabled' }).Count
        $lines.Add('Within retained services: running=' + $running + '; stopped=' + $stopped + '; disabled startup=' + $disabled)
    }
    else { $lines.Add('Service state/startup totals: <unknown>') }
    $processes = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'Processes' })[0]
    $endpoints = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'NetworkEndpoints' })[0]
    foreach ($coverage in $endpoints.Coverage) {
        $protocol = if ($coverage.SourceId -eq 'TCPListeners') { 'TCP' } else { 'UDP' }
        $count = if ($coverage.Status -in @('Success', 'Partial')) { [string]@($endpoints.Items | Where-Object { $_.Protocol -eq $protocol }).Count } else { '<unknown>' }
        $lines.Add($coverage.SourceId + ': ' + $coverage.Status + '; retained endpoints: ' + $count)
    }
    foreach ($coverage in $processes.Coverage) {
        $scope = if ($coverage.Required) { 'required' } else { 'optional' }
        $lines.Add($coverage.SourceId + ' (' + $scope + '): ' + $coverage.Status)
    }
    foreach ($name in @('ServiceProcesses', 'AdditionalProcesses', 'Files', 'Hashes', 'Signatures')) {
        $usage = $Report.Collection.BudgetUsage[$name]
        $candidates = if ($null -eq $usage.CandidateCount) { '<unknown>' } else { [string]$usage.CandidateCount }
        $lines.Add($name + ': candidates=' + $candidates + '; attempted=' + $usage.AttemptedCount + '; completed=' + $usage.CompletedCount + '; unusable=' + $usage.UnusableCount + '; skipped=' + $usage.SkippedCount)
    }
    $lines.Add('File-phase seconds: ' + $Report.Collection.BudgetUsage.FilePhaseElapsedSeconds + '; actual hash bytes read: ' + $Report.Collection.BudgetUsage.HashBytesRead)
    $lines.Add('File limits: 256 paths, 64 MiB per hash, 512 MiB actual reads, 60-second scheduling budget. Signature invocations: 0 (reserved limit 16).')
    $files = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'ExecutableFiles' })[0]
    foreach ($coverage in $files.Coverage) { $lines.Add($coverage.SourceId + ': ' + $coverage.Status) }
    $lines.Add('Process queries: all observed running-service PIDs; at most 128 additional PIDs, 32 per batch, CIM timeout request 30 seconds.')
    $lines.Add('PID-only, non-atomic: matching PIDs do not establish individual service endpoint ownership; missing/overlapping creation times cannot exclude reuse.')
    $orderedProcesses = @($processes.Items | Sort-Object @{ Expression = { $_.RequiredForCollection }; Descending = $true }, ProcessId)
    if (-not $Detailed) {
        $lines.Add('PROCESS PREVIEW (PID / name; at most 10 rows)')
        foreach ($process in @($orderedProcesses | Select-Object -First 10)) {
            $name = if ($null -eq $process.Name) { '<unavailable>' } else { $process.Name }
            $lines.Add([string]$process.ProcessId + ' / ' + $name)
        }
        if ($orderedProcesses.Count -gt 10) { $lines.Add([string]($orderedProcesses.Count - 10) + ' additional process records are saved in the reports.') }
    }
    if ($Detailed) {
        $software = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'InstalledSoftware' })[0]
        $lines.Add(''); $lines.Add('ALL COLLECTED SERVICES (commands/arguments are JSON-only)')
        foreach ($item in @($services.Items | Sort-Object Name)) {
            $lines.Add('- ' + $item.Name + '; state=' + $item.State + '; startup=' + $item.StartMode)
            $lines.Add('  Account: ' + $item.ServiceAccount + '; PID: ' + $item.ProcessId)
            $lines.Add('  Process reference: ' + $item.ProcessRecordId + '; association: ' + $item.ProcessAssociationStatus)
        }
        $lines.Add(''); $lines.Add('ALL COLLECTED SOFTWARE REGISTRATIONS')
        foreach ($item in $software.Items) {
            $lines.Add('- ' + $item.Id + '; name=' + $item.Name + '; version=' + $item.Version + '; publisher=' + $item.Publisher)
        }
        $lines.Add(''); $lines.Add('ALL COLLECTED PROCESSES (commands/arguments are JSON-only)')
        foreach ($process in $orderedProcesses) {
            $name = if ($null -eq $process.Name) { '<unavailable>' } else { $process.Name }
            $created = if ($null -eq $process.CreatedAt) { '<unavailable>' } else { $process.CreatedAt }
            $path = if ($null -eq $process.ExecutablePath) { '<unavailable>' } else { $process.ExecutablePath }
            $lines.Add('- PID: ' + $process.ProcessId + '; name: ' + $name + '; required: ' + $process.RequiredForCollection + '; metadata: ' + $process.RecordStatus)
            $lines.Add('  Created UTC: ' + $created + '; executable: ' + $path)
            $lines.Add('  Sources: ' + ($process.SourceKinds -join ', ') + '; services: ' + ($process.RelatedServiceIds -join ', '))
            $lines.Add('  Endpoints: ' + ($process.EndpointIds -join ', ') + '; association: ' + $process.AssociationStatus)
        }
        $lines.Add(''); $lines.Add('PROCESS TARGET OUTCOMES (not additional process records)')
        foreach ($target in $processes.TargetOutcomes) {
            $lines.Add('- ' + $target.TargetId + '; required: ' + $target.RequiredForCollection + '; outcome: ' + $target.Outcome + '; process reference: ' + $target.ProcessRecordId)
        }
        $lines.Add(''); $lines.Add('ALL COLLECTED EXECUTABLE FILES (disk observations, not loaded-memory identity)')
        foreach ($file in $files.Items) {
            $length = if ($null -eq $file.LengthBytes) { '<unavailable>' } else { [string]$file.LengthBytes }
            $modified = if ($null -eq $file.LastWriteTimeUtc) { '<unavailable>' } else { $file.LastWriteTimeUtc }
            $hash = if ($null -eq $file.SHA256) { '<not collected>' } else { $file.SHA256 }
            $lines.Add('- ' + $file.Id + ': ' + $file.Path + '; state: ' + $file.FileState)
            $lines.Add('  Bytes: ' + $length + '; modified UTC: ' + $modified + '; metadata: ' + $file.MetadataStatus)
            $lines.Add('  File version: ' + $file.FileVersion + '; product version: ' + $file.ProductVersion + '; company: ' + $file.CompanyName + '; product: ' + $file.ProductName)
            $lines.Add('  SHA256 (' + $file.HashStatus + '): ' + $hash + '; signature: ' + $file.SignatureStatus + ' (SignatureNetworkPolicy)')
            $lines.Add('  Sources: ' + (($file.SourceRefs | ForEach-Object { $_.DatasetId + '/' + $_.RecordId }) -join ', '))
        }
        $lines.Add('Endpoint details are preserved completely in network-endpoints.csv and service-software.json.')
    }
    $remaining = 10
    foreach ($kind in @('Collection', 'Output')) {
        $issues = @($Report[$kind].Issues | Sort-Object DatasetId,Stage,Code,RecordId)
        $lines.Add($kind + ' issues: ' + $issues.Count)
        $shown = if ($Detailed) { $issues } else { @($issues | Select-Object -First $remaining) }
        foreach ($issue in $shown) { $lines.Add('- ' + $issue.Code + ': ' + $issue.Message) }
        if ($shown.Count -lt $issues.Count) { $lines.Add('Additional issues are recorded in the reports.') }
        if (-not $Detailed) { $remaining -= $shown.Count }
    }
    if ($Detailed) {
        # TXT is published before JSON and cannot certify the later publication.
        $lines.Add('Report-save status: not certified by this supporting report.')
        $lines.Add('Verify process completion, the matching RunId in service-software.json, and all declared readable reports.')
        $lines.Add('Surviving TXT/CSV or temporary files alone do not confirm a complete report set.')
    }
    else { $lines.Add('Report-save status: ' + $Report.Output.Status) }
    $lines.Add('Output directory: ' + $Report.Output.Directory)
    $lines.Add('Raw command lines are restricted JSON only. Native signature verification is skipped by no-network policy.')
    return ($lines.ToArray() -join [Environment]::NewLine)
}

function Convert-InventoryCsv {
    param([object[]]$Items, [string[]]$Columns)
    if ($Items.Count -eq 0) { return (($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',') }
    $rows = foreach ($item in $Items) {
        $row = [ordered]@{}
        foreach ($column in $Columns) {
            if ($column -in @('MissingValueNames', 'SourceKinds', 'RelatedServiceIds', 'EndpointIds', 'SourceRefs')) { $row[$column] = ConvertTo-Json -InputObject @($item.$column) -Compress }
            else { $row[$column] = $item.$column }
        }
        [pscustomobject]$row
    }
    return (($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine)
}

function Write-ProtectedReportText {
    param([string]$Path, [string]$Text, [string[]]$AllowedSids)
    Assert-ProtectedReportPath ([IO.Path]::GetDirectoryName($Path)) $AllowedSids
    Assert-ProtectedReportPath $Path $AllowedSids
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.SetLength(0)
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($true))
        try { $writer.Write($Text); $writer.Flush() }
        finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Publish-InventoryReports {
    param($Report, $Location, [string[]]$AllowedSids)
    $serviceColumns = 'Id,Name,DisplayName,State,StartMode,ServiceAccount,ProcessId,RawCommandLineState,ExecutablePath,PathResolution,ProcessRecordId,ProcessAssociationStatus,FileRecordId,RecordStatus'.Split(',')
    $softwareColumns = 'Id,Name,Version,Publisher,RegistryHive,RegistryView,RegistryKey,SubkeyName,MissingValueNames,RecordStatus'.Split(',')
    $endpointColumns = 'Id,Protocol,EndpointType,LocalAddress,LocalPort,ProcessId,RelatedServiceIds,ServiceAssociationStatus,ProcessRecordId,ProcessAssociationStatus,AssociationBasis,RecordStatus'.Split(',')
    $processColumns = 'Id,ProcessId,Name,ExecutablePath,RawCommandLineState,CreatedAt,RequiredForCollection,SourceKinds,RelatedServiceIds,EndpointIds,AssociationStatus,FileRecordId,RecordStatus'.Split(',')
    $fileColumns = 'Id,Path,SourceRefs,FileState,LengthBytes,LastWriteTimeUtc,FileVersion,ProductVersion,CompanyName,ProductName,MetadataStatus,HashStatus,SHA256,SignatureMode,SignatureStatus,NativeSignatureStatus,NativeSignatureType,SignerSubject,SignerThumbprint,RecordStatus'.Split(',')
    $services = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'Services' })[0]
    $software = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'InstalledSoftware' })[0]
    $endpoints = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'NetworkEndpoints' })[0]
    $processes = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'Processes' })[0]
    $files = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'ExecutableFiles' })[0]
    $Report.Output.Directory = $Location.Directory
    $Report.Output.ProtectionStatus = 'VerifiedRestricted'
    $Report.Output.Issues = @($script:OutputIssues.ToArray())
    # Keep live status failed until all publication/verification steps complete.
    $Report.Output.Status = 'Failed'
    $contents = [ordered]@{
        'summary.txt' = Get-ServiceSoftwareSummary $Report -Detailed
        'services.csv' = Convert-InventoryCsv @($services.Items) $serviceColumns
        'software.csv' = Convert-InventoryCsv @($software.Items) $softwareColumns
        'network-endpoints.csv' = Convert-InventoryCsv @($endpoints.Items) $endpointColumns
        'processes.csv' = Convert-InventoryCsv @($processes.Items) $processColumns
        'files.csv' = Convert-InventoryCsv @($files.Items) $fileColumns
    }
    foreach ($name in @($contents.Keys) + @('service-software.json')) {
        $temporaryPath = $Location.TemporaryPaths[$name]
        if ($name -eq 'service-software.json') {
            # JSON cannot attest to its own creation. Serialize candidate success
            # only after supporting files pass checks, without changing live status.
            $candidate = [ordered]@{}
            foreach ($key in $Report.Keys) { $candidate[$key] = $Report[$key] }
            $candidate.Output = [ordered]@{}
            foreach ($key in $Report.Output.Keys) { $candidate.Output[$key] = $Report.Output[$key] }
            $candidate.Output.Status = 'Success'
            $text = $candidate | ConvertTo-Json -Depth 12
        }
        else { $text = $contents[$name] }
        Write-ProtectedReportText $temporaryPath $text $AllowedSids
        if ($name -eq 'service-software.json') {
            $null = [IO.File]::ReadAllText($temporaryPath) | ConvertFrom-Json -ErrorAction Stop
        }
        Assert-ProtectedReportPath $Location.Directory $AllowedSids
        Assert-ProtectedReportPath $temporaryPath $AllowedSids
        $stream = [IO.File]::OpenRead($temporaryPath)
        try { if ($stream.Length -eq 0) { throw 'EmptyRequiredReport' } }
        finally { $stream.Dispose() }
        $finalPath = [IO.Path]::Combine($Location.Directory, $name)
        [IO.File]::Move($temporaryPath, $finalPath)
        $Location.CreatedPaths.Add($finalPath)
        Assert-ProtectedReportPath $finalPath $AllowedSids
        $stream = [IO.File]::OpenRead($finalPath)
        try { if ($stream.Length -eq 0) { throw 'EmptyRequiredReport' } }
        finally { $stream.Dispose() }
    }
    foreach ($name in $Report.Output.Files) {
        $path = [IO.Path]::Combine($Location.Directory, $name)
        Assert-ProtectedReportPath $Location.Directory $AllowedSids
        Assert-ProtectedReportPath $path $AllowedSids
        $stream = [IO.File]::OpenRead($path)
        try { if ($stream.Length -eq 0) { throw 'EmptyRequiredReport' } }
        finally { $stream.Dispose() }
    }
    $published = [IO.File]::ReadAllText([IO.Path]::Combine($Location.Directory, 'service-software.json')) | ConvertFrom-Json -ErrorAction Stop
    if ($published.RunId -ne $Report.RunId -or $published.ModuleId -ne $Report.ModuleId -or
        $published.Version -ne $Report.Version -or $published.SchemaVersion -ne '0.1.0' -or
        $published.Output.ProtectionStatus -ne 'VerifiedRestricted' -or $published.Output.Status -ne 'Success' -or
        $published.Output.Directory -ne $Location.Directory -or
        (@($published.Output.Files) -join '|') -ne (@($Report.Output.Files) -join '|')) { throw 'ReportIdentityMismatch' }
    $Report.Output.Status = 'Success'
}

function Invoke-ServiceSoftwareInventory {
    param([string]$OutputRoot)
    $script:CollectionIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:OutputIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:WarningCount = 0
    $runId = [guid]::NewGuid().ToString()
    $location = $null; $fallbackUsed = $false
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'WindowsRequired' }
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
        $hostname = $env:COMPUTERNAME
        $hostFolder = if ($hostname) { $hostname -replace '[\\/:*?"<>|]', '_' } else { 'UnknownHost' }
        if (-not $hostname) {
            Add-InventoryIssue Collection $null Collect HostnameUnavailable 'Hostname was unavailable; the output folder uses UnknownHost.'
        }
        $fallbackRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'CCDC-ServiceSoftwareInventory')
        if (-not $OutputRoot) {
            $parent = Split-Path -Parent $PSScriptRoot
            $standardLayout = (Split-Path -Leaf $PSScriptRoot) -eq 'Inventory' -and
                (Test-Path -LiteralPath (Join-Path $parent 'AGENTS.md')) -and
                (Test-Path -LiteralPath (Join-Path $parent 'README.md'))
            $OutputRoot = if ($standardLayout) { Join-Path $parent 'Output' } else { Join-Path $PSScriptRoot 'Output' }
        }
    }
    catch { Write-Warning 'A Windows report environment could not be established. No reports saved.'; return 3 }
    try { $location = New-ProtectedReportLocation $OutputRoot $hostFolder $runId $allowedSids }
    catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Requested report location could not be created or verified as restricted.' }
    if ($null -eq $location) {
        $fallbackUsed = $true
        try { $location = New-ProtectedReportLocation $fallbackRoot $hostFolder $runId $allowedSids }
        catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Temporary report fallback could not be created or verified as restricted.' }
    }
    if ($null -eq $location) { Write-Output ('Reports not saved; no collection started. RunId: ' + $runId); return 3 }

    $started = [datetime]::UtcNow.ToString('o')
    $budget = [ordered]@{}
    foreach ($name in @('ServiceProcesses', 'AdditionalProcesses', 'Files', 'Hashes', 'Signatures')) {
        $budget[$name] = [ordered]@{ CandidateCount = $null; AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0 }
    }
    $budget.HashBytesRead = 0; $budget.FilePhaseElapsedSeconds = 0
    $services = Get-ServiceDataset
    $software = Get-SoftwareDataset
    $endpoints = Get-EndpointDataset
    $processes = Get-ProcessDataset $services $endpoints $budget
    $files = Get-ExecutableDataset $services $processes $budget
    $datasets = @($services, $software, $endpoints, $processes, $files)
    $report = [ordered]@{
        SchemaVersion = '0.1.0'; ModuleId = 'service-software-inventory'; Version = '0.1.0'
        DevelopmentStage = 'Milestone 1.2C'; ReleaseReady = $false
        RunId = $runId; Hostname = $hostname; StartedAt = $started; CompletedAt = [datetime]::UtcNow.ToString('o')
        Collection = [ordered]@{ Status = Get-AggregateStatus $datasets; Datasets = @($datasets); Issues = @($script:CollectionIssues.ToArray()); BudgetUsage = $budget }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{
            Status = 'Failed'; Directory = $location.Directory; FallbackUsed = $fallbackUsed
            ProtectionStatus = 'VerifiedRestricted'
            Files = @('summary.txt', 'services.csv', 'software.csv', 'network-endpoints.csv', 'processes.csv', 'files.csv', 'service-software.json')
            Issues = @($script:OutputIssues.ToArray())
        }
    }
    $saved = $false
    while ($null -ne $location -and -not $saved) {
        try { Publish-InventoryReports $report $location $allowedSids; $saved = $true }
        catch {
            Add-InventoryIssue Output $null Publish ReportWriteFailed 'Required report publication or verification failed; no complete report set is confirmed at that location.'
            Remove-IncompleteReportFiles $location $allowedSids
            $report.Output.Status = 'Failed'
            $location = $null
            if (-not $report.Output.FallbackUsed) {
                $report.Output.FallbackUsed = $true
                try { $location = New-ProtectedReportLocation $fallbackRoot $hostFolder $runId $allowedSids }
                catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Temporary report fallback could not be verified as restricted.' }
            }
        }
    }
    $report.Output.Issues = @($script:OutputIssues.ToArray())
    if (-not $saved) { $report.Output.Directory = $null; $report.Output.ProtectionStatus = $null }
    Write-Output (Get-ServiceSoftwareSummary $report)
    Get-InventoryExitCode $report.Collection.Status $saved
}

try { $result = @(Invoke-ServiceSoftwareInventory $OutputDir) }
catch { Write-Warning 'The development collector stopped unexpectedly; no complete report set is confirmed.'; exit 3 }
if ($result.Count -gt 1) { $result[0..($result.Count - 2)] | Write-Output }
exit ([int]$result[-1])
