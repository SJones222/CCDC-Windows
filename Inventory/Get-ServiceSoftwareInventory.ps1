#requires -Version 5.1
<#
.SYNOPSIS
    Collects service and machine-wide software inventory (development Milestone 1.2A).
.DESCRIPTION
    Standalone, read-only Windows collector. Raw service commands are saved only in
    restricted JSON. Process, endpoint, and file enrichment are not implemented.
    A saved report normally exits 2 because required process collection is incomplete.
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
        [string]$RecordId
    )
    $issue = [ordered]@{ DatasetId = $DatasetId; Stage = $Stage; Code = $Code; Message = $Message }
    if ([string]::IsNullOrEmpty($DatasetId)) { $issue.DatasetId = $null }
    if ($RecordId) { $issue.RecordId = $RecordId }
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
    $name = [string]$Source.Name
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'ServiceIdentityMissing' }
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
            $value = $Source.($mapping[$field])
            if ($null -eq $value) { throw 'ServiceFieldUnavailable' }
            if ($field -eq 'ProcessId') { $item[$field] = [uint32]$value }
            else { $item[$field] = [string]$value }
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
        'Milestone 1.2A: configured executable-path resolution and process/file associations are not implemented.'
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
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            if ($cursor -ne $Path -and ($attributes -band [IO.FileAttributes]::Directory) -eq 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-RestrictedDescriptor {
    param([System.Security.AccessControl.RawSecurityDescriptor]$Descriptor, [string[]]$AllowedSids, [switch]$Ancestor)
    if ($null -eq $Descriptor.Owner -or $AllowedSids -notcontains $Descriptor.Owner.Value) { return $false }
    if (($Descriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        $null -eq $Descriptor.DiscretionaryAcl) { return $false }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        # Unknown/callback ACEs are not interpreted as safe; no effective-access engine.
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.IsCallback) { return $false }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($AllowedSids -contains $ace.SecurityIdentifier.Value) { continue }
            $inheritOnly = ($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0
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
    # Check existing ancestors even before creating a missing output root. The same
    # owner allowlist applies; unfamiliar owners/ACEs fail closed, without ACL edits.
    $cursor = [IO.Directory]::GetParent($Path)
    while ($null -ne $cursor) {
        try { $attributes = [IO.File]::GetAttributes($cursor.FullName) }
        catch [IO.DirectoryNotFoundException] { $cursor = $cursor.Parent; continue }
        catch [IO.FileNotFoundException] { $cursor = $cursor.Parent; continue }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'ReportAncestorUnverified' }
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
        foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'service-software.json')) {
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
    $lines.Add('Get-ServiceSoftwareInventory.ps1 0.1.0 - DEVELOPMENT Milestone 1.2A')
    $lines.Add('Not a completed release: process, endpoint, and file enrichment are not implemented.')
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
    if ($Detailed) {
        $software = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'InstalledSoftware' })[0]
        $lines.Add(''); $lines.Add('ALL COLLECTED SERVICES (commands/arguments are JSON-only)')
        foreach ($item in @($services.Items | Sort-Object Name)) {
            $lines.Add('- ' + $item.Name + '; state=' + $item.State + '; startup=' + $item.StartMode)
            $lines.Add('  Account: ' + $item.ServiceAccount + '; PID: ' + $item.ProcessId)
        }
        $lines.Add(''); $lines.Add('ALL COLLECTED SOFTWARE REGISTRATIONS')
        foreach ($item in $software.Items) {
            $lines.Add('- ' + $item.Id + '; name=' + $item.Name + '; version=' + $item.Version + '; publisher=' + $item.Publisher)
        }
    }
    foreach ($kind in @('Collection', 'Output')) {
        $issues = @($Report[$kind].Issues)
        $lines.Add($kind + ' issues: ' + $issues.Count)
        $shown = if ($Detailed) { $issues } else { @($issues | Select-Object -First 10) }
        foreach ($issue in $shown) { $lines.Add('- ' + $issue.Code + ': ' + $issue.Message) }
        if ($shown.Count -lt $issues.Count) { $lines.Add('Additional issues are recorded in the reports.') }
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
            if ($column -eq 'MissingValueNames') { $row[$column] = ConvertTo-Json -InputObject @($item.$column) -Compress }
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
    $services = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'Services' })[0]
    $software = @($Report.Collection.Datasets | Where-Object { $_.Id -eq 'InstalledSoftware' })[0]
    $Report.Output.Directory = $Location.Directory
    $Report.Output.ProtectionStatus = 'VerifiedRestricted'
    $Report.Output.Issues = @($script:OutputIssues.ToArray())
    # Keep live status failed until all publication/verification steps complete.
    $Report.Output.Status = 'Failed'
    $contents = [ordered]@{
        'summary.txt' = Get-ServiceSoftwareSummary $Report -Detailed
        'services.csv' = Convert-InventoryCsv @($services.Items) $serviceColumns
        'software.csv' = Convert-InventoryCsv @($software.Items) $softwareColumns
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
    $datasets = @((Get-ServiceDataset), (Get-SoftwareDataset))
    foreach ($entry in @(
        @{ Id = 'Processes'; Required = $true },
        @{ Id = 'NetworkEndpoints'; Required = $false },
        @{ Id = 'ExecutableFiles'; Required = $false }
    )) {
        $datasets += New-InventoryDataset $entry.Id $entry.Required Unavailable @() @('NotImplemented: intentionally absent from Milestone 1.2A.')
        Add-InventoryIssue Collection $entry.Id Prerequisite NotImplemented 'Dataset collection is intentionally not implemented in Milestone 1.2A.'
    }
    $files = @($datasets | Where-Object { $_.Id -eq 'ExecutableFiles' })[0]
    $files | Add-Member -NotePropertyName SignaturePolicy -NotePropertyValue ([ordered]@{ Status = 'Skipped'; ReasonCode = 'SignatureNetworkPolicy' })
    $processes = @($datasets | Where-Object { $_.Id -eq 'Processes' })[0]
    $processes | Add-Member -NotePropertyName InputStatus -NotePropertyValue ([ordered]@{ Services = $datasets[0].Status; NetworkEndpoints = 'Unavailable' })
    $processes | Add-Member -NotePropertyName TargetOutcomes -NotePropertyValue @()
    $budget = [ordered]@{}
    foreach ($name in @('ServiceProcesses', 'AdditionalProcesses', 'Files', 'Hashes', 'Signatures')) {
        $budget[$name] = [ordered]@{ CandidateCount = $null; AttemptedCount = 0; CompletedCount = 0; UnusableCount = 0; SkippedCount = 0 }
    }
    $budget.HashBytesRead = 0; $budget.FilePhaseElapsedSeconds = 0
    $report = [ordered]@{
        SchemaVersion = '0.1.0'; ModuleId = 'service-software-inventory'; Version = '0.1.0'
        DevelopmentStage = 'Milestone 1.2A'; ReleaseReady = $false
        RunId = $runId; Hostname = $hostname; StartedAt = $started; CompletedAt = [datetime]::UtcNow.ToString('o')
        Collection = [ordered]@{ Status = Get-AggregateStatus $datasets; Datasets = @($datasets); Issues = @($script:CollectionIssues.ToArray()); BudgetUsage = $budget }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{
            Status = 'Failed'; Directory = $location.Directory; FallbackUsed = $fallbackUsed
            ProtectionStatus = 'VerifiedRestricted'
            Files = @('summary.txt', 'services.csv', 'software.csv', 'service-software.json')
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
