#requires -Version 5.1
<#
.SYNOPSIS
    Read-only local TCP relationship snapshot (development Milestone 1.3).
.DESCRIPTION
    Observations are not dependencies or proof of service socket ownership.
    No probes, lookups, remote connections, command lines, or configuration changes.
    Reports require verified private local storage. Windows validation is pending.
.PARAMETER OutputDir
    Optional output root; a restricted temporary fallback is attempted if necessary.
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
    $timeout = $Record.CategoryInfo.Category -eq 'OperationTimeout'
    $exception = $Record.Exception
    while ($null -ne $exception) {
        if ($exception -is [TimeoutException]) { $timeout = $true }
        if ($exception -is [UnauthorizedAccessException] -or
            $exception -is [System.Security.SecurityException]) { $denied = $true }
        if ($exception -is [System.Management.Automation.CommandNotFoundException] -or
            $exception -is [PlatformNotSupportedException] -or $exception -is [TypeLoadException] -or
            $exception -is [DllNotFoundException]) { $missing = $true }
        if ($exception.PSObject.Properties['NativeErrorCode']) {
            $nativeCode = [string]$exception.NativeErrorCode
            if ($nativeCode -in @('OperationTimeout', 'TimedOut')) { $timeout = $true }
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
    if ($timeout) { return [pscustomobject]@{ Status = 'Failed'; Code = 'QueryTimeout'; Message = 'The local collection operation timed out.' } }
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

function Read-NetworkField {
    param($Source, [string]$Name, [string]$Type, [string]$DatasetId, $Item, [switch]$Optional)
    try {
        if ($Optional -and $null -eq $Source.PSObject.Properties[$Name]) { return $null }
        $value = Read-ObservedProperty $Source $Name
        if ($Optional -and $null -eq $value) { return $null }
        switch ($Type) {
            EnumText {
                if ($value -is [Enum]) { return $value.ToString() }
                if ($value -isnot [string] -or [string]::IsNullOrEmpty($value)) { throw 'EnumFieldUnavailable' }
                return $value
            }
            Text {
                if ($value -isnot [string] -or [string]::IsNullOrEmpty($value)) { throw 'TextFieldUnavailable' }
                return $value
            }
            UInt32 { return (Convert-ObservedUInt32 $value) }
            Date {
                if ($value -isnot [datetime]) { throw 'DateFieldUnavailable' }
                return $value.ToUniversalTime().ToString('o')
            }
        }
        throw 'UnsupportedFieldType'
    }
    catch {
        $Item.RecordStatus = 'Partial'
        $problem = Get-CollectionFailure $_ RecordReadFailed
        Add-InventoryIssue Collection $DatasetId Parse $problem.Code $problem.Message
        return $null
    }
}

function ConvertTo-NumericAddress {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $Text -ne $Text.Trim() -or $Text -match '[\[\]]') { return $null }
    $scope = $null
    if ($Text.Contains('%')) {
        # Reject named zones before parsing; never ask Windows to resolve a name.
        if ($Text -notmatch '^[^%]+%([0-9]+)$') { return $null }
        $zone = [uint32]0
        if (-not [uint32]::TryParse($Matches[1], [ref]$zone)) { return $null }
        $scope = [long]$zone
    }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Text, [ref]$ip)) { return $null }
    $family = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    if ($family -eq 'IPv4' -and $null -ne $scope) { return $null }
    # Provider IPv4 literals are dotted decimal; reject legacy shorthand/octal forms.
    if ($family -eq 'IPv4' -and $Text -cne $ip.ToString()) { return $null }
    $comparison = if ($ip.IsIPv4MappedToIPv6) { $ip.MapToIPv4() } else { $ip }
    $bytes = $comparison.GetAddressBytes()
    $normalized = [Net.IPAddress]::new($bytes).ToString()
    $needsScope = $comparison.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $comparison.IsIPv6LinkLocal
    $unsupported = $normalized -in @('0.0.0.0', '::') -or
        ($bytes.Length -eq 4 -and $bytes[0] -ge 224) -or
        ($bytes.Length -eq 16 -and ($bytes[0] -eq 255 -or $comparison.IsIPv6SiteLocal)) -or
        ($null -ne $scope -and $scope -gt 0 -and -not $needsScope)
    [pscustomobject]@{
        Normalized = $normalized; Family = $family; ScopeId = $scope
        ComparisonFamily = if ($bytes.Length -eq 4) { 'IPv4' } else { 'IPv6' }
        NeedsScope = $needsScope; Loopback = [Net.IPAddress]::IsLoopback($comparison); Unsupported = $unsupported
    }
}

function Get-RecordFailureStatus {
    param([int]$IssueStart)
    $issues = @($script:CollectionIssues | Select-Object -Skip $IssueStart)
    if ($issues.Count -gt 0 -and @($issues | Where-Object { $_.Code -notin @('AccessDenied', 'CapabilityMissing') }).Count -eq 0) {
        return 'Unavailable'
    }
    'Failed'
}

function Convert-NetworkRecord {
    param($Source, [string]$DatasetId, [string]$Family)
    $item = [ordered]@{ Id = ''; RecordStatus = 'Success' }
    if ($DatasetId -eq 'TCPConnections') {
        $item.ObservedAt = [datetime]::UtcNow.ToString('o')
        $item.Protocol = 'TCP'
        foreach ($field in @('LocalAddress', 'RemoteAddress')) {
            $item[$field] = Read-NetworkField $Source $field Text $DatasetId $item
        }
        $item.State = Read-NetworkField $Source State EnumText $DatasetId $item
        foreach ($field in @('LocalPort', 'RemotePort')) {
            $item[$field] = Read-NetworkField $Source $field UInt32 $DatasetId $item
            if ($null -ne $item[$field] -and $item[$field] -gt 65535) {
                $item[$field] = $null; $item.RecordStatus = 'Partial'
                Add-InventoryIssue Collection $DatasetId Parse RecordReadFailed 'A TCP port was outside the supported numeric range.'
            }
        }
        $item.ProcessId = Read-NetworkField $Source OwningProcess UInt32 $DatasetId $item
        $item.ConnectionCreatedAt = Read-NetworkField $Source CreationTime Date $DatasetId $item -Optional
        $item.AddressFamily = 'Unknown'
        $item.LocalAddressNormalized = $null; $item.RemoteAddressNormalized = $null
        $item.LocalScopeId = $null; $item.RemoteScopeId = $null
        $item.Relationship = 'Unknown'; $item.RelationshipReason = 'InvalidEndpoint'; $item.Initiator = 'Unknown'
        $item.LocalAddressIds = @(); $item.LocalInterfaceIds = @(); $item.ProcessRecordId = $null
        $item.ProcessAssociationStatus = 'Unavailable'; $item.RelatedServiceIds = @(); $item.ServiceAssociationStatus = 'Unknown'
        $item.AssociationBasis = 'PID-only, non-atomic'
        foreach ($side in @('Local', 'Remote')) {
            if ($null -eq $item[($side + 'Address')]) { continue } # The failed field read already has its own issue.
            $parsed = ConvertTo-NumericAddress $item[($side + 'Address')]
            if ($null -eq $parsed) {
                $item.RecordStatus = 'Partial'
                Add-InventoryIssue Collection $DatasetId Parse InvalidAddress 'A TCP endpoint address could not be interpreted as a supported numeric literal.'
            }
            else {
                $item[($side + 'AddressNormalized')] = $parsed.Normalized
                $item[($side + 'ScopeId')] = $parsed.ScopeId
                if ($side -eq 'Local') { $item.AddressFamily = $parsed.Family }
            }
        }
        if ($null -eq $item.LocalAddress -or $null -eq $item.RemoteAddress) { return $null }
        return [pscustomobject]$item
    }
    $item.AddressFamily = $Family
    $item.InterfaceIndex = Read-NetworkField $Source InterfaceIndex UInt32 $DatasetId $item
    if ($DatasetId -ne 'Routes') { $item.InterfaceAlias = Read-NetworkField $Source InterfaceAlias Text $DatasetId $item }
    if ($DatasetId -eq 'LocalAddresses') {
        $item.IPAddress = Read-NetworkField $Source IPAddress Text $DatasetId $item
        $item.AddressNormalized = $null; $item.ScopeId = $null
        $parsed = ConvertTo-NumericAddress $item.IPAddress
        if ($null -ne $item.IPAddress -and ($null -eq $parsed -or $parsed.Unsupported -or $parsed.Family -ne $Family -or
            ($parsed.NeedsScope -and $parsed.ScopeId -gt 0 -and $null -ne $item.InterfaceIndex -and $parsed.ScopeId -ne $item.InterfaceIndex))) {
            $item.RecordStatus = 'Partial'
            Add-InventoryIssue Collection $DatasetId Parse InvalidAddress 'A local address or its interface scope could not be interpreted consistently.'
        }
        elseif ($null -ne $parsed) { $item.AddressNormalized = $parsed.Normalized; $item.ScopeId = $parsed.ScopeId }
        $item.PrefixLength = Read-NetworkField $Source PrefixLength UInt32 $DatasetId $item
        if ($null -ne $item.PrefixLength -and $item.PrefixLength -gt $(if ($Family -eq 'IPv4') { 32 } else { 128 })) {
            $item.PrefixLength = $null; $item.RecordStatus = 'Partial'
            Add-InventoryIssue Collection $DatasetId Parse RecordReadFailed 'An address prefix length was outside its family range.'
        }
        $item.AddressState = Read-NetworkField $Source AddressState EnumText $DatasetId $item
        $item.InterfaceIds = @()
        if ($null -eq $item.IPAddress -or $null -eq $item.InterfaceIndex) { return $null }
    }
    elseif ($DatasetId -eq 'Interfaces') {
        $item.ConnectionState = Read-NetworkField $Source ConnectionState EnumText $DatasetId $item
        $item.InterfaceMetric = Read-NetworkField $Source InterfaceMetric UInt32 $DatasetId $item
        if ($null -eq $item.InterfaceIndex) { return $null }
    }
    elseif ($DatasetId -eq 'DnsServers') {
        $item.ServerAddresses = @(); $item.ServerAddressesState = 'Collected'; $item.InterfaceIds = @()
        try {
            $property = $Source.PSObject.Properties['ServerAddresses']
            if ($null -eq $property) { throw 'DnsListMissing' }
            $value = [System.Management.Automation.PSPropertyInfo].GetProperty('Value').GetValue($property, $null)
            foreach ($address in @($value)) {
                if ($null -eq $address) { continue } # A present null provider list is genuinely empty.
                $parsed = if ($address -is [string]) { ConvertTo-NumericAddress $address } else { $null }
                if ($null -eq $parsed -or $parsed.Family -ne $Family) {
                    $item.RecordStatus = 'Partial'; $item.ServerAddressesState = 'Unavailable'
                    Add-InventoryIssue Collection $DatasetId Parse InvalidAddress 'A configured DNS address was invalid; other available addresses were retained.'
                }
                else { $item.ServerAddresses += $address }
            }
        }
        catch {
            $item.RecordStatus = 'Partial'; $item.ServerAddressesState = 'Unavailable'
            $problem = Get-CollectionFailure $_ RecordReadFailed
            Add-InventoryIssue Collection $DatasetId Parse $problem.Code $problem.Message
        }
        if ($null -eq $item.InterfaceIndex) { return $null }
    }
    elseif ($DatasetId -eq 'Routes') {
        $item.DestinationPrefix = Read-NetworkField $Source DestinationPrefix Text $DatasetId $item
        $item.NextHop = Read-NetworkField $Source NextHop Text $DatasetId $item
        $item.RouteMetric = Read-NetworkField $Source RouteMetric UInt32 $DatasetId $item
        $item.InterfaceIds = @(); $item.PolicyStore = 'ActiveStore'
        if ($null -eq $item.DestinationPrefix) { return $null }
    }
    [pscustomobject]$item
}

function Sort-NetworkRecords {
    param([object[]]$Rows, [string[]]$Fields)
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $Rows) { $list.Add($row) }
    $list.Sort([Comparison[object]]{
        param($left, $right)
        foreach ($field in $Fields) {
            $a = $left.Item.$field; $b = $right.Item.$field
            $result = if ($null -eq $a) { if ($null -eq $b) { 0 } else { -1 } }
                elseif ($null -eq $b) { 1 }
                elseif ($a -is [ValueType] -and $b -is [ValueType]) { ([decimal]$a).CompareTo([decimal]$b) }
                else { [StringComparer]::Ordinal.Compare([string]$a, [string]$b) }
            if ($result -ne 0) { return $result }
        }
        return $left.Ordinal.CompareTo($right.Ordinal)
    })
    foreach ($row in $list) { $row.Item }
}

function Get-NetworkDataset {
    param([string]$Id)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $coverage = @()
    $sources = if ($Id -eq 'TCPConnections') { @('EstablishedTCP') } else { @('IPv4', 'IPv6') }
    foreach ($sourceId in $sources) {
        $started = [datetime]::UtcNow.ToString('o')
        $before = $rows.Count; $issueStart = $script:CollectionIssues.Count; $failure = $null
        try {
            $query = {
                switch ($Id) {
                    TCPConnections { Get-NetTCPConnection -State Established -ErrorAction Stop }
                    LocalAddresses { Get-NetIPAddress -AddressFamily $sourceId -ErrorAction Stop }
                    Interfaces { Get-NetIPInterface -AddressFamily $sourceId -ErrorAction Stop }
                    DnsServers { Get-DnsClientServerAddress -AddressFamily $sourceId -ErrorAction Stop }
                    Routes { Get-NetRoute -AddressFamily $sourceId -PolicyStore ActiveStore -ErrorAction Stop }
                }
            }
            & $query | ForEach-Object {
                try {
                    if ($null -eq $_) { throw 'NullProviderRecord' }
                    $item = Convert-NetworkRecord $_ $Id $sourceId
                    if ($null -ne $item) { $rows.Add([pscustomobject]@{ Item = $item; Ordinal = $rows.Count }) }
                }
                catch {
                    $problem = Get-CollectionFailure $_ RecordReadFailed
                    Add-InventoryIssue Collection $Id Parse $problem.Code $problem.Message
                }
            }
        }
        catch {
            $errorId = $_.FullyQualifiedErrorId.Split(',')[0]
            $emptyIds = @('CmdletizationQuery_NotFound')
            if ($Id -eq 'TCPConnections') { $emptyIds += 'CmdletizationQuery_NotFound_State' }
            else { $emptyIds += 'CmdletizationQuery_NotFound_AddressFamily' }
            $empty = $errorId -in $emptyIds -and $_.CategoryInfo.Category -eq 'ObjectNotFound' -and
                $rows.Count -eq $before -and $script:CollectionIssues.Count -eq $issueStart
            if (-not $empty) {
                $problem = Get-CollectionFailure $_
                $failure = $problem.Status
                Add-InventoryIssue Collection $Id Collect $problem.Code $problem.Message $sourceId
            }
        }
        $status = if ($script:CollectionIssues.Count -eq $issueStart) { 'Success' }
            elseif ($rows.Count -gt $before) { 'Partial' }
            elseif ($failure) { $failure } else { Get-RecordFailureStatus $issueStart }
        $coverage += [pscustomobject]@{
            SourceId = $sourceId; Required = $true; Status = $status
            QueryStartedAt = $started; QueryCompletedAt = [datetime]::UtcNow.ToString('o')
        }
    }
    $fields = switch ($Id) {
        TCPConnections { @('AddressFamily', 'LocalAddressNormalized', 'LocalPort', 'RemoteAddressNormalized', 'RemotePort', 'ProcessId') }
        Routes { @('AddressFamily', 'InterfaceIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric') }
        LocalAddresses { @('AddressFamily', 'InterfaceIndex', 'AddressNormalized') }
        default { @('AddressFamily', 'InterfaceIndex') }
    }
    $items = @(Sort-NetworkRecords $rows.ToArray() $fields)
    $prefix = @{ TCPConnections = 'connection'; LocalAddresses = 'address'; Interfaces = 'interface'; DnsServers = 'dns'; Routes = 'route' }[$Id]
    for ($index = 0; $index -lt $items.Count; $index++) { $items[$index].Id = $prefix + ':' + ($index + 1) }
    $dataset = New-InventoryDataset $Id ($Id -in @('TCPConnections', 'LocalAddresses')) (Get-AggregateStatus $coverage) $items @(
        'One local provider observation per source; no polling or probes. Configuration is default-compartment only; TCP compartment identity is not supplied.'
        'Counts are retained observations, not a machine/dependency count. Missing traffic is not evidence of no dependency.'
    )
    $dataset.Coverage = $coverage
    $dataset
}

function Set-InterfaceReferences {
    param($Interfaces, [object[]]$Datasets)
    $map = @{}
    foreach ($item in $Interfaces.Items) {
        $key = $item.AddressFamily + ':' + $item.InterfaceIndex
        if (-not $map.ContainsKey($key)) { $map[$key] = @() }
        $map[$key] += $item.Id
    }
    foreach ($dataset in $Datasets) {
        foreach ($item in $dataset.Items) {
            $key = $item.AddressFamily + ':' + $item.InterfaceIndex
            $item.InterfaceIds = @(if ($map.ContainsKey($key)) { $map[$key] })
        }
    }
}

function Set-ConnectionRelationships {
    param($Connections, $Addresses)
    $map = @{}; $broadcasts = @{}
    foreach ($address in $Addresses.Items) {
        if ($null -eq $address.AddressNormalized) { continue }
        $key = $address.AddressNormalized
        if (-not $map.ContainsKey($key)) { $map[$key] = @() }
        $map[$key] += $address
        if ($address.AddressFamily -eq 'IPv4' -and $null -ne $address.PrefixLength -and $address.PrefixLength -lt 31) {
            $bytes = [Net.IPAddress]::Parse($key).GetAddressBytes()
            for ($part = 0; $part -lt 4; $part++) {
                $bits = [Math]::Max(0, [Math]::Min(8, [int]$address.PrefixLength - 8 * $part))
                $bytes[$part] = [byte]([int]$bytes[$part] -bor ([int][Math]::Pow(2, 8 - $bits) - 1))
            }
            $broadcasts[[Net.IPAddress]::new($bytes).ToString()] = $true
        }
    }
    foreach ($item in $Connections.Items) {
        $local = ConvertTo-NumericAddress $item.LocalAddress
        $remote = ConvertTo-NumericAddress $item.RemoteAddress
        $item.Relationship = 'Unknown'; $item.RelationshipReason = 'InvalidEndpoint'
        if ($null -eq $local -or $null -eq $remote -or $local.ComparisonFamily -ne $remote.ComparisonFamily) { continue }
        $localMatches = @(if ($map.ContainsKey($local.Normalized)) { $map[$local.Normalized] })
        if ($local.NeedsScope -and $local.ScopeId -gt 0) { $localMatches = @($localMatches | Where-Object { $_.InterfaceIndex -eq $local.ScopeId }) }
        $item.LocalAddressIds = @($localMatches | ForEach-Object { $_.Id })
        $item.LocalInterfaceIds = @($localMatches | ForEach-Object { $_.InterfaceIds } | Select-Object -Unique)
        if ($local.Unsupported -or $remote.Unsupported -or $broadcasts.ContainsKey($remote.Normalized)) { $item.RelationshipReason = 'UnsupportedEndpoint'; continue }
        if ($remote.Loopback) { $item.Relationship = 'SameHostObserved'; $item.RelationshipReason = 'LoopbackRemote'; continue }
        $indices = @($localMatches | ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
        $localZone = $local.ScopeId; $remoteZone = $remote.ScopeId
        if ($local.NeedsScope -and -not ($localZone -gt 0) -and $indices.Count -eq 1) { $localZone = $indices[0] }
        if ($remote.NeedsScope -and -not ($remoteZone -gt 0)) {
            if ($localZone -gt 0) { $remoteZone = $localZone }
            elseif ($indices.Count -eq 1) { $remoteZone = $indices[0] }
        }
        if (($local.NeedsScope -and -not ($localZone -gt 0)) -or
            ($remote.NeedsScope -and -not ($remoteZone -gt 0)) -or
            ($local.NeedsScope -and $remote.NeedsScope -and $localZone -ne $remoteZone)) {
            $item.RelationshipReason = 'AmbiguousScope'; continue
        }
        if ($local.Normalized -eq $remote.Normalized) {
            $item.Relationship = 'SameHostObserved'; $item.RelationshipReason = 'EqualEndpointAddresses'; continue
        }
        $remoteMatches = @(if ($map.ContainsKey($remote.Normalized)) { $map[$remote.Normalized] })
        if ($remote.NeedsScope) { $remoteMatches = @($remoteMatches | Where-Object { $_.InterfaceIndex -eq $remoteZone }) }
        if ($remoteMatches.Count -gt 0) { $item.Relationship = 'SameHostObserved'; $item.RelationshipReason = 'RemoteMatchesLocalAddress'; continue }
        if ($Addresses.Status -ne 'Success') { $item.RelationshipReason = 'LocalCoverageIncomplete'; continue }
        if ($indices.Count -ne 1 -or $local.Loopback) { $item.RelationshipReason = 'LocalContextUnknown'; continue }
        if ($remote.NeedsScope -and $remoteZone -ne $indices[0]) { $item.RelationshipReason = 'AmbiguousScope'; continue }
        $item.Relationship = 'CrossMachineObserved'; $item.RelationshipReason = 'RemoteOutsideObservedLocalSet'
    }
}

function Get-ContextTargets {
    param($Connections)
    $map = @{}
    foreach ($connection in $Connections.Items) {
        if ($null -eq $connection.ProcessId -or $connection.ProcessId -eq 0) { continue }
        $key = [string]$connection.ProcessId
        $priority = switch ($connection.Relationship) { CrossMachineObserved { 0 } Unknown { 1 } default { 2 } }
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [pscustomobject]@{
                ProcessId = $connection.ProcessId; Priority = $priority; Connections = @()
                Process = $null; Services = (New-Object 'System.Collections.Generic.List[object]')
                ProcessOutcome = [pscustomobject]@{
                    TargetId = 'process:' + $key; ProcessId = $connection.ProcessId; ProcessRecordId = $null
                    Outcome = 'Skipped'; QueryStartedAt = $null; QueryCompletedAt = $null
                }
                ServiceOutcome = [pscustomobject]@{
                    ProcessId = $connection.ProcessId; Outcome = 'Skipped'; QueryStartedAt = $null; QueryCompletedAt = $null
                }
            }
        }
        $map[$key].Priority = [Math]::Min($map[$key].Priority, $priority)
        $map[$key].Connections += $connection
    }
    # Deduplicate first, then apply the highest applicable relationship tier.
    @($map.Values | Sort-Object Priority, { [uint32]$_.ProcessId })
}

function Get-ContextElapsedSeconds {
    param($Clock)
    $Clock.Elapsed.TotalSeconds
}

function Invoke-ContextBatch {
    param([object[]]$Targets, [string]$DatasetId, $Usage)
    $map = @{}
    foreach ($target in $Targets) { $map[[string]$target.ProcessId] = $target }
    $filter = ($Targets | ForEach-Object { 'ProcessId = ' + $_.ProcessId }) -join ' OR '
    $started = [datetime]::UtcNow.ToString('o')
    $failure = $null; $state = [pscustomobject]@{ Invalid = $false; Partial = $false; Records = 0 }
    $issueStart = $script:CollectionIssues.Count
    try {
        $query = {
            if ($DatasetId -eq 'Processes') {
                Get-CimInstance -ClassName Win32_Process -Property ProcessId,Name,CreationDate -Filter $filter -OperationTimeoutSec 30 -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_Service -Property Name,DisplayName,State,ProcessId -Filter ("State = 'Running' AND (" + $filter + ')') -OperationTimeoutSec 30 -ErrorAction Stop
            }
        }
        & $query | ForEach-Object {
            try {
                $number = Convert-ObservedUInt32 (Read-ObservedProperty $_ ProcessId)
                $key = [string]$number
                if ($number -eq 0 -or -not $map.ContainsKey($key)) { throw 'UnexpectedProcessIdentity' }
                $target = $map[$key]
                $item = [ordered]@{ Id = ''; ProcessId = $number; RecordStatus = 'Success' }
                $item.Name = Read-NetworkField $_ Name Text $DatasetId $item
                $item.ConnectionIds = @($target.Connections | ForEach-Object { $_.Id })
                if ($DatasetId -eq 'Processes') {
                    if ($null -ne $target.Process) { throw 'DuplicateProcessIdentity' }
                    $item.Id = 'process:' + $key
                    $item.CreatedAt = Read-NetworkField $_ CreationDate Date $DatasetId $item
                    $item.RelatedServiceIds = @()
                    $target.Process = [pscustomobject]$item
                }
                else {
                    $item.DisplayName = Read-NetworkField $_ DisplayName Text $DatasetId $item
                    $item.State = Read-NetworkField $_ State Text $DatasetId $item
                    $item.ProcessRecordId = $null; $item.ProcessAssociationStatus = 'Unavailable'
                    if ($null -eq $item.Name) { throw 'ServiceIdentityMissing' }
                    $target.Services.Add([pscustomobject]$item)
                }
                if ($item.RecordStatus -eq 'Partial') { $state.Partial = $true }
                $state.Records++
            }
            catch {
                $state.Invalid = $true
                $problem = Get-CollectionFailure $_ RecordReadFailed
                Add-InventoryIssue Collection $DatasetId Parse $problem.Code $problem.Message
            }
        }
    }
    catch {
        $failure = Get-CollectionFailure $_
        Add-InventoryIssue Collection $DatasetId Collect $failure.Code $failure.Message
    }
    $completed = [datetime]::UtcNow.ToString('o')
    $parseStatus = if ($state.Invalid) { Get-RecordFailureStatus $issueStart } else { $null }
    foreach ($target in $Targets) {
        $Usage.AttemptedCount++
        $outcome = if ($DatasetId -eq 'Processes') { $target.ProcessOutcome } else { $target.ServiceOutcome }
        $outcome.QueryStartedAt = $started; $outcome.QueryCompletedAt = $completed
        if ($DatasetId -eq 'Processes' -and $null -ne $target.Process) {
            $Usage.CompletedCount++
            $outcome.ProcessRecordId = $target.Process.Id
            $outcome.Outcome = if ($target.Process.RecordStatus -eq 'Success') { 'Returned' } else { 'PartialMetadata' }
        }
        elseif ($DatasetId -eq 'Services' -and $target.Services.Count -gt 0) {
            $Usage.CompletedCount++
            $outcome.Outcome = if ($null -ne $failure -or $state.Invalid -or $state.Partial) { 'Partial' } else { 'MatchesReturned' }
        }
        elseif ($null -ne $failure -or $state.Invalid) {
            $Usage.UnusableCount++
            $outcome.Outcome = if ($null -ne $failure) { $failure.Status } else { $parseStatus }
        }
        elseif ($DatasetId -eq 'Services') { $Usage.CompletedCount++; $outcome.Outcome = 'NoObservedMatch' }
        else {
            $Usage.UnusableCount++; $outcome.Outcome = 'NotReturned'
            Add-InventoryIssue Collection Processes Collect ProcessNotReturned 'A requested PID was not returned; an exit is possible but not confirmed.' $outcome.TargetId
        }
    }
    [pscustomobject]@{
        Usable = ($null -eq $failure -and -not $state.Invalid) -or $state.Records -gt 0
        Incomplete = $script:CollectionIssues.Count -gt $issueStart
        Failed = $parseStatus -eq 'Failed' -or ($null -ne $failure -and $failure.Status -eq 'Failed')
        QueryStartedAt = $started; QueryCompletedAt = $completed
    }
}

function Get-PidAssociation {
    param($Process, [string]$Outcome, [string]$SourceCompletedAt)
    if ($null -eq $Process) {
        if ($Outcome -in @('NotReturned', 'Skipped')) { return $Outcome }
        return 'Unavailable'
    }
    if ($Process.CreatedAt -and $SourceCompletedAt -and
        [datetimeoffset]::Parse($Process.CreatedAt) -gt [datetimeoffset]::Parse($SourceCompletedAt)) { return 'PossiblePidReuse' }
    'UnconfirmedPidMatch'
}

function Get-ConnectionContext {
    param($Connections, [System.Collections.IDictionary]$Budget)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $targets = @(Get-ContextTargets $Connections)
    $states = @{}
    foreach ($name in @('Processes', 'Services')) {
        $Budget[$name] = [ordered]@{
            CandidateCount = if ($Connections.Status -eq 'Success') { $targets.Count } else { $null }
            AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0
        }
        $states[$name] = [pscustomobject]@{ Usable = $false; Incomplete = $Connections.Status -ne 'Success'; Failed = $false; Started = $null; Completed = $null }
        if ($Connections.Status -in @('Unavailable', 'Failed')) {
            Add-InventoryIssue Collection $name Prerequisite PrerequisiteUnavailable 'Connection coverage is unavailable; no PID context query was started.'
        }
    }
    try {
        for ($offset = 0; $offset -lt $targets.Count; $offset += 32) {
            $batch = @($targets | Select-Object -Skip $offset -First 32)
            foreach ($name in @('Processes', 'Services')) {
                $state = $states[$name]
                if ($offset -ge 128 -or (Get-ContextElapsedSeconds $clock) -ge 60) {
                    $Budget[$name].SkippedCount += $batch.Count
                    $state.Incomplete = $true
                    foreach ($target in $batch) {
                        Add-InventoryIssue Collection $name Prerequisite LimitReached 'PID context was not queried because its selection or scheduling budget was exhausted.' ('process:' + $target.ProcessId)
                    }
                    continue
                }
                $result = Invoke-ContextBatch $batch $name $Budget[$name]
                $state.Usable = $state.Usable -or $result.Usable
                $state.Incomplete = $state.Incomplete -or $result.Incomplete
                $state.Failed = $state.Failed -or $result.Failed
                if ($null -eq $state.Started) { $state.Started = $result.QueryStartedAt }
                $state.Completed = $result.QueryCompletedAt
            }
        }
    }
    finally { $Budget.ContextElapsedSeconds = Get-ContextElapsedSeconds $clock; $clock.Stop() }
    $processes = @($targets | Where-Object { $null -ne $_.Process } | ForEach-Object { $_.Process })
    $serviceRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($target in $targets) {
        foreach ($service in $target.Services) { $serviceRows.Add([pscustomobject]@{ Item = $service; Ordinal = $serviceRows.Count }) }
    }
    $services = @(Sort-NetworkRecords $serviceRows.ToArray() @('Name', 'ProcessId'))
    for ($index = 0; $index -lt $services.Count; $index++) { $services[$index].Id = 'service:' + ($index + 1) }
    $datasets = @{}
    foreach ($name in @('Processes', 'Services')) {
        $state = $states[$name]
        $status = if ($Connections.Status -in @('Unavailable', 'Failed')) { $Connections.Status }
            elseif ($targets.Count -eq 0) { if ($Connections.Status -eq 'Success') { 'Success' } else { 'Partial' } }
            elseif ($state.Usable) { if ($state.Incomplete) { 'Partial' } else { 'Success' } }
            elseif ($state.Failed) { 'Failed' } else { 'Unavailable' }
        $items = if ($name -eq 'Processes') { $processes } else { $services }
        $dataset = New-InventoryDataset $name $false $status @($items) @(
            'PID-only, non-atomic. At most 128 distinct PIDs, CrossMachineObserved then Unknown then SameHostObserved, numeric within tiers; batches of 32, 30-second CIM timeout request, 60-second shared scheduling budget.'
            'No raw commands, executable inspection, full process scan, service ownership claim, or remote lookup.'
        )
        $dataset.Coverage = @([pscustomobject]@{
            SourceId = 'ConnectionPidTargets'; Required = $true; Status = $status
            QueryStartedAt = $state.Started; QueryCompletedAt = $state.Completed
        })
        $outcomes = @(foreach ($target in $targets) { if ($name -eq 'Processes') { $target.ProcessOutcome } else { $target.ServiceOutcome } })
        $dataset | Add-Member -NotePropertyName TargetOutcomes -NotePropertyValue $outcomes
        $datasets[$name] = $dataset
    }
    $sourceEnd = @($Connections.Coverage | ForEach-Object { $_.QueryCompletedAt }) -join ''
    foreach ($target in $targets) {
        $serviceIds = @($target.Services | ForEach-Object { $_.Id })
        if ($null -ne $target.Process) { $target.Process.RelatedServiceIds = $serviceIds }
        foreach ($service in $target.Services) {
            if ($null -ne $target.Process) { $service.ProcessRecordId = $target.Process.Id }
            $service.ProcessAssociationStatus = Get-PidAssociation $target.Process $target.ProcessOutcome.Outcome $target.ServiceOutcome.QueryCompletedAt
        }
        foreach ($connection in $target.Connections) {
            if ($null -ne $target.Process) { $connection.ProcessRecordId = $target.Process.Id }
            $connection.ProcessAssociationStatus = Get-PidAssociation $target.Process $target.ProcessOutcome.Outcome $sourceEnd
            $connection.RelatedServiceIds = $serviceIds
            $connection.ServiceAssociationStatus = if ($target.ServiceOutcome.Outcome -eq 'Skipped') { 'Skipped' }
                elseif ($serviceIds.Count -gt 0) { if ($connection.ProcessAssociationStatus -eq 'PossiblePidReuse') { 'PossiblePidReuse' } else { 'UnconfirmedPidMatch' } }
                elseif ($datasets.Services.Status -eq 'Success') { 'NoObservedMatch' } else { 'Unknown' }
            if ($connection.ProcessAssociationStatus -eq 'PossiblePidReuse') {
                Add-InventoryIssue Collection Processes Parse PossiblePidReuse 'A process was created after the connection observation window; the PID association is uncertain.' $target.ProcessOutcome.TargetId
            }
        }
    }
    foreach ($connection in $Connections.Items) {
        if ($null -ne $connection.ProcessId -and $connection.ProcessId -eq 0) {
            $connection.ProcessAssociationStatus = 'NotApplicable'; $connection.ServiceAssociationStatus = 'NotApplicable'
        }
    }
    [pscustomobject]@{ Processes = $datasets.Processes; Services = $datasets.Services }
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
        $stamp = 'NetworkRelationships_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
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
        foreach ($name in (Get-RelationshipReportNames)) {
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

function Convert-InventoryCsv {
    param([object[]]$Items, [string[]]$Columns)
    if ($Items.Count -eq 0) { return (($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',') }
    $rows = foreach ($item in $Items) {
        $row = [ordered]@{}
        foreach ($column in $Columns) {
            if ($column -in @('RelatedServiceIds', 'ConnectionIds', 'InterfaceIds', 'LocalAddressIds', 'LocalInterfaceIds', 'ServerAddresses')) { $row[$column] = ConvertTo-Json -InputObject @($item.$column) -Compress }
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
    $Report.Output.Directory = $Location.Directory
    $Report.Output.ProtectionStatus = 'VerifiedRestricted'
    $Report.Output.Issues = @($script:OutputIssues.ToArray())
    $Report.Output.Status = 'Failed'
    $contents = [ordered]@{ 'summary.txt' = Get-NetworkRelationshipSummary $Report -Detailed }
    $layout = Get-RelationshipReportLayout
    foreach ($id in $layout.Keys) {
        $dataset = @($Report.Collection.Datasets | Where-Object { $_.Id -eq $id })[0]
        $contents[$layout[$id].File] = Convert-InventoryCsv @($dataset.Items) $layout[$id].Columns
    }
    foreach ($name in @($contents.Keys) + @('network-relationships.json')) {
        $temporaryPath = $Location.TemporaryPaths[$name]
        if ($name -eq 'network-relationships.json') {
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
        if ($name -eq 'network-relationships.json') {
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
    $published = [IO.File]::ReadAllText([IO.Path]::Combine($Location.Directory, 'network-relationships.json')) | ConvertFrom-Json -ErrorAction Stop
    if ($published.RunId -ne $Report.RunId -or $published.ModuleId -ne $Report.ModuleId -or
        $published.Version -ne $Report.Version -or $published.SchemaVersion -ne '0.1.0' -or
        $published.Output.ProtectionStatus -ne 'VerifiedRestricted' -or $published.Output.Status -ne 'Success' -or
        $published.Output.Directory -ne $Location.Directory -or
        (@($published.Output.Files) -join '|') -ne (@($Report.Output.Files) -join '|')) { throw 'ReportIdentityMismatch' }
    $Report.Output.Status = 'Success'
}

function Get-RelationshipReportLayout {
    [ordered]@{
        TCPConnections = @{ File = 'connections.csv'; Columns = 'Id,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ObservedAt,ConnectionCreatedAt,AddressFamily,LocalAddressNormalized,RemoteAddressNormalized,LocalScopeId,RemoteScopeId,Relationship,RelationshipReason,Initiator,LocalAddressIds,LocalInterfaceIds,ProcessRecordId,ProcessAssociationStatus,RelatedServiceIds,ServiceAssociationStatus,AssociationBasis,RecordStatus'.Split(',') }
        LocalAddresses = @{ File = 'addresses.csv'; Columns = 'Id,InterfaceIndex,InterfaceAlias,AddressFamily,IPAddress,AddressNormalized,ScopeId,PrefixLength,AddressState,InterfaceIds,RecordStatus'.Split(',') }
        Interfaces = @{ File = 'interfaces.csv'; Columns = 'Id,InterfaceIndex,InterfaceAlias,AddressFamily,ConnectionState,InterfaceMetric,RecordStatus'.Split(',') }
        DnsServers = @{ File = 'dns-servers.csv'; Columns = 'Id,InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses,ServerAddressesState,InterfaceIds,RecordStatus'.Split(',') }
        Routes = @{ File = 'routes.csv'; Columns = 'Id,AddressFamily,DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,InterfaceIds,PolicyStore,RecordStatus'.Split(',') }
        Processes = @{ File = 'processes.csv'; Columns = 'Id,ProcessId,Name,CreatedAt,ConnectionIds,RelatedServiceIds,RecordStatus'.Split(',') }
        Services = @{ File = 'services.csv'; Columns = 'Id,Name,DisplayName,State,ProcessId,ConnectionIds,ProcessRecordId,ProcessAssociationStatus,RecordStatus'.Split(',') }
    }
}

function Get-RelationshipReportNames {
    'summary.txt'
    $layout = Get-RelationshipReportLayout
    foreach ($id in $layout.Keys) { $layout[$id].File }
    'network-relationships.json'
}

function Get-NetworkRelationshipSummary {
    param($Report, [switch]$Detailed)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('NETWORK RELATIONSHIPS / development 0.1.0')
    $lines.Add('Host: ' + $Report.Hostname + '; RunId: ' + $Report.RunId)
    $lines.Add('UTC observation window: ' + $Report.StartedAt + ' to ' + $Report.CompletedAt)
    $lines.Add('AT A GLANCE / required collection: ' + $Report.Collection.Status)
    foreach ($dataset in $Report.Collection.Datasets) {
        $count = if ($null -eq $dataset.Count) { 'unknown' } else { [string]$dataset.Count }
        $lines.Add($dataset.Id + ': ' + $dataset.Status + '; retained records: ' + $count)
        if ($Detailed) {
            foreach ($source in $dataset.Coverage) {
                $lines.Add('  ' + $source.SourceId + ': ' + $source.Status + '; UTC ' + $source.QueryStartedAt + ' to ' + $source.QueryCompletedAt)
            }
            foreach ($note in $dataset.Limitations) { $lines.Add('  ' + $note) }
        }
    }
    $connections = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'TCPConnections' })[0]
    foreach ($relationship in @('CrossMachineObserved', 'SameHostObserved', 'Unknown')) {
        $count = if ($null -eq $connections.Count) { 'unavailable' } else { [string]@($connections.Items | Where-Object { $_.Relationship -eq $relationship }).Count }
        $lines.Add($relationship + ': ' + $count)
    }
    foreach ($name in @('Processes', 'Services')) {
        $usage = $Report.Collection.BudgetUsage[$name]
        $candidate = if ($null -eq $usage.CandidateCount) { 'unknown' } else { [string]$usage.CandidateCount }
        $lines.Add($name + ' targets: ' + $candidate + '; attempted/completed/unusable/skipped: ' + $usage.AttemptedCount + '/' + $usage.CompletedCount + '/' + $usage.UnusableCount + '/' + $usage.SkippedCount)
    }
    $lines.Add('Context scheduling seconds: ' + $Report.Collection.BudgetUsage.ContextElapsedSeconds)
    $limit = if ($Detailed) { 50 } else { 20 }
    $preview = @(foreach ($kind in @('CrossMachineObserved', 'Unknown', 'SameHostObserved')) {
        $connections.Items | Where-Object { $_.Relationship -eq $kind }
    })
    $lines.Add('OBSERVED TCP CONNECTIONS / preview limit ' + $limit)
    $processes = @{}; $services = @{}
    foreach ($dataset in $Report.Collection.Datasets) {
        if ($dataset.Id -eq 'Processes') { foreach ($item in $dataset.Items) { $processes[$item.Id] = $item } }
        if ($dataset.Id -eq 'Services') { foreach ($item in $dataset.Items) { $services[$item.Id] = $item } }
    }
    foreach ($connection in @($preview | Select-Object -First $limit)) {
        $processName = if ($connection.ProcessRecordId -and $processes.ContainsKey($connection.ProcessRecordId)) { $processes[$connection.ProcessRecordId].Name } else { '<unavailable>' }
        $serviceNames = @(foreach ($id in $connection.RelatedServiceIds) { if ($services.ContainsKey($id)) { $services[$id].Name } })
        $serviceText = if ($serviceNames.Count -gt 0) { $serviceNames -join ', ' } else { '<none/unknown; ' + $connection.ServiceAssociationStatus + '>' }
        $lines.Add($connection.Id + ': [' + $connection.LocalAddress + ']:' + $connection.LocalPort + ' <-> [' + $connection.RemoteAddress + ']:' + $connection.RemotePort + '; ' + $connection.State)
        $lines.Add('  ' + $connection.Relationship + '/' + $connection.RelationshipReason + '; PID ' + $connection.ProcessId + '; process ' + $processName + ' (' + $connection.ProcessAssociationStatus + '); PID-associated services: ' + $serviceText)
    }
    $lines.Add('Displayed ' + [Math]::Min($limit, $preview.Count) + ' of ' + $preview.Count + ' retained connections; complete inventory: connections.csv and network-relationships.json.')
    if ($Detailed) {
        $lines.Add('NETWORK CONFIGURATION / default compartment')
        foreach ($dataset in $Report.Collection.Datasets) {
            if ($dataset.Id -eq 'Interfaces') {
                foreach ($item in $dataset.Items) { $lines.Add('Interface ' + $item.InterfaceIndex + ' / ' + $item.AddressFamily + ' / ' + $item.InterfaceAlias + ': ' + $item.ConnectionState + '; metric ' + $item.InterfaceMetric) }
            }
            if ($dataset.Id -eq 'LocalAddresses') {
                foreach ($item in $dataset.Items) { $lines.Add('Address ' + $item.IPAddress + '/' + $item.PrefixLength + '; interface ' + $item.InterfaceIndex + '; ' + $item.AddressState) }
            }
            if ($dataset.Id -eq 'DnsServers') {
                foreach ($item in $dataset.Items) { $lines.Add('DNS / interface ' + $item.InterfaceIndex + ' / ' + $item.AddressFamily + ': ' + ($item.ServerAddresses -join ', ') + '; ' + $item.ServerAddressesState) }
            }
            if ($dataset.Id -eq 'Routes') {
                foreach ($item in @($dataset.Items | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })) { $lines.Add('Default route ' + $item.DestinationPrefix + ' via ' + $item.NextHop + '; interface ' + $item.InterfaceIndex + '; route metric ' + $item.RouteMetric) }
                $lines.Add('Complete routing configuration: routes.csv / JSON. No actual path selection is asserted.')
            }
        }
    }
    $lines.Add('LIMITATIONS: snapshot evidence only, not dependencies. Initiator unknown. PID associations are non-atomic and do not prove service socket ownership. No observed traffic does not prove absence.')
    $remainingIssues = 10
    foreach ($kind in @('Collection', 'Output')) {
        $issues = @($Report.$kind.Issues)
        $lines.Add($kind + ' issues: ' + $issues.Count)
        $shown = if ($Detailed) { $issues } else { @($issues | Select-Object -First $remainingIssues) }
        foreach ($issue in $shown) { $lines.Add('  ' + $issue.DatasetId + '/' + $issue.Stage + '/' + $issue.Code + ': ' + $issue.Message) }
        if (-not $Detailed) { $remainingIssues -= @($shown).Count }
    }
    if ($Detailed) { $lines.Add('Report publication: pending final verification; this TXT file alone does not confirm a complete saved set.') }
    else { $lines.Add('Report-save status: ' + $Report.Output.Status + '; protection: ' + $Report.Output.ProtectionStatus) }
    $lines.Add('Actual output directory: ' + $Report.Output.Directory)
    $lines -join [Environment]::NewLine
}

function Invoke-NetworkRelationships {
    param([string]$OutputRoot)
    $script:CollectionIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:OutputIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:WarningCount = 0
    $runId = [guid]::NewGuid().ToString()
    $location = $null; $fallbackUsed = $false
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'WindowsRequired' }
        $allowedSids = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
        $hostname = $env:COMPUTERNAME
        $hostFolder = if ($hostname) { $hostname -replace '[\\/:*?"<>|]', '_' } else { 'UnknownHost' }
        if (-not $hostname) { Add-InventoryIssue Collection $null Collect HostnameUnavailable 'Hostname was unavailable; the folder uses UnknownHost.' }
        $fallbackRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'CCDC-NetworkRelationships')
        if (-not $OutputRoot) {
            $parent = Split-Path -Parent $PSScriptRoot
            $standardLayout = (Split-Path -Leaf $PSScriptRoot) -eq 'Inventory' -and
                (Test-Path -LiteralPath (Join-Path $parent 'AGENTS.md')) -and (Test-Path -LiteralPath (Join-Path $parent 'README.md'))
            $OutputRoot = if ($standardLayout) { Join-Path $parent 'Output' } else { Join-Path $PSScriptRoot 'Output' }
        }
    }
    catch { Write-Warning 'A Windows report environment could not be established; no reports saved.'; return 3 }
    try { $location = New-ProtectedReportLocation $OutputRoot $hostFolder $runId $allowedSids }
    catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Requested report storage could not be verified as restricted.' }
    if ($null -eq $location) {
        $fallbackUsed = $true
        try { $location = New-ProtectedReportLocation $fallbackRoot $hostFolder $runId $allowedSids }
        catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Temporary report storage could not be verified as restricted.' }
    }
    if ($null -eq $location) { Write-Output ('Reports not saved; no collection started. RunId: ' + $runId); return 3 }
    $started = [datetime]::UtcNow.ToString('o')
    $connections = Get-NetworkDataset TCPConnections
    $addresses = Get-NetworkDataset LocalAddresses
    $interfaces = Get-NetworkDataset Interfaces
    $dns = Get-NetworkDataset DnsServers
    $routes = Get-NetworkDataset Routes
    Set-InterfaceReferences $interfaces @($addresses, $dns, $routes)
    Set-ConnectionRelationships $connections $addresses
    $budget = [ordered]@{}
    $context = Get-ConnectionContext $connections $budget
    $datasets = @($connections, $addresses, $interfaces, $dns, $routes, $context.Processes, $context.Services)
    $report = [ordered]@{
        SchemaVersion = '0.1.0'; ModuleId = 'network-relationships'; Version = '0.1.0'
        DevelopmentStage = 'Milestone 1.3'; ReleaseReady = $false
        RunId = $runId; Hostname = $hostname; StartedAt = $started; CompletedAt = [datetime]::UtcNow.ToString('o')
        Collection = [ordered]@{ Status = Get-AggregateStatus $datasets; Datasets = @($datasets); Issues = @($script:CollectionIssues.ToArray()); BudgetUsage = $budget }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{
            Status = 'Failed'; Directory = $location.Directory; FallbackUsed = $fallbackUsed; ProtectionStatus = 'VerifiedRestricted'
            Files = @(Get-RelationshipReportNames); Issues = @($script:OutputIssues.ToArray())
        }
    }
    $saved = $false
    while ($null -ne $location) {
        try { Publish-InventoryReports $report $location $allowedSids; $saved = $true; break }
        catch {
            Add-InventoryIssue Output $null Publish ReportWriteFailed 'Required report publication or verification failed; no complete report set is confirmed.'
            Remove-IncompleteReportFiles $location $allowedSids
            $report.Output.Status = 'Failed'; $location = $null
            if (-not $report.Output.FallbackUsed) {
                $report.Output.FallbackUsed = $true
                try { $location = New-ProtectedReportLocation $fallbackRoot $hostFolder $runId $allowedSids }
                catch { Add-InventoryIssue Output $null Prerequisite OutputProtectionUnverified 'Temporary fallback could not be verified as restricted.' }
            }
        }
    }
    $report.Output.Issues = @($script:OutputIssues.ToArray())
    if (-not $saved) { $report.Output.Directory = $null; $report.Output.ProtectionStatus = $null }
    Write-Output (Get-NetworkRelationshipSummary $report)
    Get-InventoryExitCode $report.Collection.Status $saved
}

try { $result = @(Invoke-NetworkRelationships $OutputDir) }
catch { Write-Warning 'The development collector stopped unexpectedly; no complete report set is confirmed.'; exit 3 }
if ($result.Count -gt 1) { $result[0..($result.Count - 2)] | Write-Output }
exit ([int]$result[-1])
