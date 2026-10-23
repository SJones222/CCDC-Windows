<#
.SYNOPSIS
    Performs bounded, read-only Windows security event triage for CCDC use.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Deep,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 720)]
    [int]$Hours = 24,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

$CollectionIssues = @()
$OutputIssues = @()
$outputSaved = $false

function Add-CollectionIssue {
    param([string]$Message)
    $script:CollectionIssues += $Message
    Write-Warning $Message
}

function Add-OutputIssue {
    param([string]$Message)
    $script:OutputIssues += $Message
    Write-Warning $Message
}

function New-UniqueOutputDirectory {
    param(
        [string]$Root,
        [string]$HostFolder
    )

    $stamp = 'SecurityEventTriage_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
    $hostRoot = Join-Path $Root $HostFolder
    $candidate = Join-Path $hostRoot $stamp
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = Join-Path $hostRoot ($stamp + '-' + $suffix)
        $suffix++
    }
    New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop | Out-Null
    return $candidate
}

function Format-Value {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return '<unavailable>'
    }
    return [string]$Value
}

function Get-EventDefinition {
    param([int]$EventId)

    switch ($EventId) {
        4624 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Successful logon' } }
        4625 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Failed logon' } }
        4648 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Explicit credentials used' } }
        4672 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Special privileges assigned at logon' } }
        4740 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Account locked out' } }
        4768 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Kerberos ticket-granting ticket request' } }
        4769 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Kerberos service ticket request' } }
        4771 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'Kerberos pre-authentication failure' } }
        4776 { return [pscustomobject]@{ Category = 'Authentication'; Description = 'NTLM credential validation' } }
        4720 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Account created' } }
        4722 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Account enabled' } }
        4724 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Password reset attempted' } }
        4725 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Account disabled' } }
        4726 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Account deleted' } }
        4738 { return [pscustomobject]@{ Category = 'AccountManagement'; Description = 'Account modified' } }
        4728 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member added to global security group' } }
        4729 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member removed from global security group' } }
        4732 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member added to local security group' } }
        4733 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member removed from local security group' } }
        4756 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member added to universal security group' } }
        4757 { return [pscustomobject]@{ Category = 'GroupMembership'; Description = 'Member removed from universal security group' } }
        4698 { return [pscustomobject]@{ Category = 'ScheduledTasks'; Description = 'Scheduled task created' } }
        4699 { return [pscustomobject]@{ Category = 'ScheduledTasks'; Description = 'Scheduled task deleted' } }
        4702 { return [pscustomobject]@{ Category = 'ScheduledTasks'; Description = 'Scheduled task modified' } }
        4719 { return [pscustomobject]@{ Category = 'SecurityConfiguration'; Description = 'System audit policy changed' } }
        1102 { return [pscustomobject]@{ Category = 'SecurityConfiguration'; Description = 'Security audit log cleared' } }
        7045 { return [pscustomobject]@{ Category = 'ServiceInstallation'; Description = 'Service installed' } }
        1116 { return [pscustomobject]@{ Category = 'Defender'; Description = 'Defender detection' } }
        1117 { return [pscustomobject]@{ Category = 'Defender'; Description = 'Defender action performed' } }
        5007 { return [pscustomobject]@{ Category = 'Defender'; Description = 'Defender configuration changed' } }
        4688 { return [pscustomobject]@{ Category = 'ProcessCreation'; Description = 'Process created' } }
        4104 { return [pscustomobject]@{ Category = 'PowerShell'; Description = 'PowerShell script block logged' } }
        default { return [pscustomobject]@{ Category = 'Other'; Description = 'Windows event ' + $EventId } }
    }
}

function Get-EventField {
    param(
        [System.Collections.IDictionary]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Data.Contains($name)) {
            $value = [string]$Data[$name]
            if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '-') {
                return $value
            }
        }
    }
    return $null
}

function Convert-EventRecord {
    param(
        $Record,
        [string]$QueryName
    )

    $eventId = [int]$Record.Id
    $definition = Get-EventDefinition $eventId
    $data = [ordered]@{}
    $parseError = $null
    $xmlText = $null
    try {
        $xmlText = $Record.ToXml()
        $xml = [xml]$xmlText
        $fieldNumber = 0
        foreach ($field in @($xml.Event.EventData.Data)) {
            $fieldName = [string]$field.Name
            if ([string]::IsNullOrWhiteSpace($fieldName)) {
                $fieldName = 'Data' + $fieldNumber
            }
            while ($data.Contains($fieldName)) {
                $fieldName = $fieldName + '_' + $fieldNumber
                $fieldNumber++
            }
            $fieldValue = $field.InnerText
            if ($null -eq $fieldValue) {
                $fieldValue = $field.'#text'
            }
            $data[$fieldName] = [string]$fieldValue
            $fieldNumber++
        }
    }
    catch {
        $parseError = $_.Exception.Message
    }

    $message = $null
    try {
        $message = $Record.Message
    }
    catch {
        $message = $null
    }

    $groupName = $null
    if ($definition.Category -eq 'GroupMembership') {
        $groupName = Get-EventField $data @('GroupName', 'TargetUserName')
    }
    $event = [pscustomobject][ordered]@{
        QueryName = $QueryName
        EventId = $eventId
        Description = $definition.Description
        Category = $definition.Category
        Timestamp = if ($Record.TimeCreated) { $Record.TimeCreated.ToString('o') } else { $null }
        LogName = [string]$Record.LogName
        Channel = [string]$Record.LogName
        ComputerName = [string]$Record.MachineName
        Provider = [string]$Record.ProviderName
        EventRecordId = $Record.RecordId
        Actor = Get-EventField $data @('SubjectUserName', 'CallerUserName', 'UserName', 'AccountName')
        Target = Get-EventField $data @('TargetUserName', 'TargetAccountName', 'MemberName', 'AccountName', 'TaskName', 'ObjectName')
        SourceIpAddress = Get-EventField $data @('IpAddress', 'SourceNetworkAddress', 'ClientAddress', 'SourceAddress')
        LogonType = Get-EventField $data @('LogonType')
        GroupName = $groupName
        ServiceName = Get-EventField $data @('ServiceName')
        ExecutablePath = Get-EventField $data @('ImagePath', 'NewProcessName', 'ProcessName', 'ExecutablePath', 'ServiceFileName', 'ImageFileName')
        ProcessName = Get-EventField $data @('NewProcessName', 'ProcessName', 'ApplicationName', 'ImageFileName')
        CommandLine = Get-EventField $data @('CommandLine', 'ProcessCommandLine', 'TaskContent')
        FailureCode = Get-EventField $data @('Status', 'SubStatus', 'FailureReason', 'ErrorCode', 'FailureCode', 'ResultCode', 'ReturnCode')
        ScriptBlockId = Get-EventField $data @('ScriptBlockId')
        ScriptBlockMessageNumber = Get-EventField $data @('MessageNumber')
        ScriptBlockTotalMessages = Get-EventField $data @('MessageTotal')
        Message = [string]$message
        EventData = $data
        ParseError = $parseError
    }
    return $event
}

function Get-EventQuery {
    param(
        $Query,
        [datetime]$StartTime
    )

    $events = @()
    $parseFailures = 0
    $queryLimit = $Query.ReportingLimit + 1
    $capped = $false
    $queryError = $null
    try {
        $rawEvents = @(Get-WinEvent -FilterHashtable @{
                LogName = $Query.LogName
                Id = $Query.EventIds
                StartTime = $StartTime
            } -MaxEvents $queryLimit -ErrorAction Stop)
        if ($rawEvents.Count -gt $Query.ReportingLimit) {
            $capped = $true
            $rawEvents = @($rawEvents | Select-Object -First $Query.ReportingLimit)
        }
        foreach ($rawEvent in $rawEvents) {
            $converted = Convert-EventRecord $rawEvent $Query.Name
            if ($converted.ParseError) {
                $parseFailures++
                Add-CollectionIssue ('Event parsing limitation: ' + $Query.Name + ': ' + $converted.ParseError)
            }
            $events += $converted
        }
    }
    catch {
        $errorRecord = $_
        $errorId = ([string]$errorRecord.FullyQualifiedErrorId).Split(',')[0]
        $isNoMatchingEvents = $errorId -eq 'NoMatchingEventsFound' -and
            $errorRecord.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound

        if (-not $isNoMatchingEvents) {
            $queryError = $errorRecord.Exception.Message
            Add-CollectionIssue ('Collection failure: ' + $Query.Name + ' [' + $Query.LogName + ']: ' + $queryError)
        }
    }

    $status = if ($queryError) {
        'Unavailable'
    }
    elseif ($capped -or $parseFailures -gt 0) {
        'Partial'
    }
    elseif ($events.Count -eq 0) {
        'Empty'
    }
    else {
        'Success'
    }
    return [pscustomobject][ordered]@{
        Name = $Query.Name
        LogName = $Query.LogName
        EventIds = @($Query.EventIds)
        ReportingLimit = $Query.ReportingLimit
        QueryLimit = $queryLimit
        Status = $status
        ObservedCount = $events.Count
        Capped = $capped
        Events = @($events)
        Error = $queryError
    }
}

function Get-LogStatus {
    param([string[]]$LogNames)

    $results = @()
    foreach ($logName in @($LogNames | Sort-Object -Unique)) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $results += [pscustomobject][ordered]@{
                LogName = $logName
                Status = 'Available'
                IsEnabled = $log.IsEnabled
                RecordCount = $log.RecordCount
                LogMode = [string]$log.LogMode
                MaximumSizeInBytes = $log.MaximumSizeInBytes
                Error = $null
            }
        }
        catch {
            $results += [pscustomobject][ordered]@{
                LogName = $logName
                Status = 'Unknown'
                IsEnabled = $null
                RecordCount = $null
                LogMode = $null
                MaximumSizeInBytes = $null
                Error = $_.Exception.Message
            }
            Add-CollectionIssue ('Logging configuration unavailable: ' + $logName + ': ' + $_.Exception.Message)
        }
    }
    return @($results)
}

function Write-TriageReports {
    param(
        [string]$Directory,
        [string]$Summary,
        [string]$Json,
        [array]$CsvRows
    )

    $paths = @(
        (Join-Path $Directory 'summary.txt')
        (Join-Path $Directory 'events.json')
        (Join-Path $Directory 'events.csv')
    )
    try {
        Set-Content -LiteralPath $paths[0] -Value $Summary -Encoding UTF8 -ErrorAction Stop
        Set-Content -LiteralPath $paths[1] -Value $Json -Encoding UTF8 -ErrorAction Stop
        if ($CsvRows.Count -gt 0) {
            $CsvRows | Export-Csv -LiteralPath $paths[2] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[2] -Value 'QueryName,EventId,Description,Category,Timestamp,LogName,Channel,ComputerName,Provider,EventRecordId,Actor,Target,SourceIpAddress,LogonType,GroupName,ServiceName,ExecutablePath,ProcessName,CommandLine,FailureCode,ScriptBlockId,ScriptBlockMessageNumber,ScriptBlockTotalMessages,Message,EventData,ParseError' -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) {
                try {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
                catch {
                    Write-Warning ('Could not remove incomplete output file: ' + $path)
                }
            }
        }
        throw
    }
}

function Get-TriageSummary {
    param(
        $Report,
        [array]$CollectionIssues,
        [array]$OutputIssues,
        [switch]$Detailed
    )

    $saved = if ($Report.ReportSaved) { 'Yes' } else { 'No' }
    $securityChanges = @($Report.Events | Where-Object {
        $_.Category -in @('AccountManagement', 'GroupMembership', 'ScheduledTasks', 'SecurityConfiguration', 'ServiceInstallation', 'Defender')
    } | Sort-Object @{ Expression = { if ($_.Timestamp) { [datetimeoffset]$_.Timestamp } else { [datetimeoffset]::MinValue } }; Descending = $true }, LogName, EventRecordId, EventId, QueryName)
    $authentication = @($Report.Events | Where-Object { $_.Category -eq 'Authentication' })
    $authQueries = @($Report.Queries | Where-Object { $_.Name -like 'Authentication *' })
    $lines = @(
        'Windows CCDC Security Event Triage v0.1'
        '========================================='
        ('Hostname: ' + (Format-Value $Report.Hostname))
        ('Mode: ' + $Report.Mode)
        ('Time window: ' + $Report.TimeWindow.Start + ' through ' + $Report.TimeWindow.End + ' (' + $Report.TimeWindow.Hours + ' hours)')
        ('Report saved: ' + $saved)
    )
    if ($Detailed) {
        $cappedQueries = @($Report.Queries | Where-Object { $_.Capped })
        $capNames = if ($cappedQueries.Count -gt 0) { ($cappedQueries | ForEach-Object { $_.Name }) -join '; ' } else { 'none' }
        $lines = @(
            'REPORT HEADER'
            ('Get-SecurityEventTriage.ps1 v' + (Format-Value $Report.Version))
            ('Hostname: ' + (Format-Value $Report.Hostname) + '; collected: ' + (Format-Value $Report.CollectedAt))
            ('Mode: ' + $Report.Mode)
            ('Requested window: ' + $Report.TimeWindow.Start + ' through ' + $Report.TimeWindow.End + ' (' + $Report.TimeWindow.Hours + ' hours)')
            ('Report saved: ' + $saved)
            ('Output directory: ' + (Format-Value $Report.OutputDirectory))
            ''
            'AT A GLANCE'
            ('Retained events: ' + @($Report.Events).Count + '; security-change events: ' + $securityChanges.Count + '; authentication events: ' + $authentication.Count)
            ('Query overview: ' + ((@($Report.Queries | Group-Object Status | Sort-Object Name | ForEach-Object { $_.Name + '=' + $_.Count })) -join '; '))
            ('Capped queries: ' + $cappedQueries.Count + ' (' + $capNames + ')')
            ('Collection issues: ' + $CollectionIssues.Count)
            ('Output directory: ' + (Format-Value $Report.OutputDirectory))
            'Counts are observed/retained records, not total activity; unavailable queries are not successful empty results.'
        )
    }

    $queryLines = @()
    foreach ($query in @($Report.Queries)) {
        $capText = if ($query.Capped) { '; capped at ' + $query.ReportingLimit } else { '' }
        $observed = if ($query.Status -eq 'Unavailable') { '<unavailable>' } else { [string]$query.ObservedCount }
        $queryLines += ('- ' + $query.Name + ' [' + $query.LogName + ']: ' + $query.Status + '; observed ' + $observed + $capText)
        if ($Detailed) {
            $queryLines += ('  Event IDs: ' + ($query.EventIds -join ', ') + '; reporting limit: ' + $query.ReportingLimit + '; query limit: ' + $query.QueryLimit + '; capped: ' + $query.Capped)
            if ($query.Error) { $queryLines += '  Error: ' + $query.Error }
            if ($query.Status -eq 'Partial' -and -not $query.Capped) {
                $queryLines += '  Event parsing limitations; see collection issues and ParseError in structured reports.'
            }
        }
    }
    if (-not $Detailed) {
        $lines += ''
        $lines += 'Collection status:'
        $lines += $queryLines
    }

    $lines += ''
    $lines += 'Observed counts by security category:'
    if (@($Report.Events).Count -eq 0) {
        $lines += '- no records retained; see query statuses and logging limitations'
    }
    else {
        foreach ($group in @($Report.Events | Group-Object Category | Sort-Object Name)) {
            $lines += ('- ' + $group.Name + ': ' + $group.Count)
        }
    }

    $lines += ''
    $lines += $(if ($Detailed) { 'SECURITY EVENTS TO REVIEW' } else { 'High-signal security-change events (first 10):' })
    $lines += ('Collected security-change events: ' + $securityChanges.Count)
    if ($Detailed) { $lines += 'Collected events for investigation; they do not establish malicious activity.' }
    $displayEvents = if ($Detailed) { $securityChanges } else { @($Report.ReviewPreview) }
    if ($securityChanges.Count -eq 0) {
        $lines += '- none retained; unavailable/capped queries and logging coverage limit conclusions'
    }
    else {
        $firstEvent = $true
        foreach ($event in $displayEvents) {
            if ($Detailed -and -not $firstEvent) { $lines += '' }
            $firstEvent = $false
            $lines += ('- [' + $event.Timestamp + '] ' + $event.Description + ' (' + $event.EventId + ')')
            if ($Detailed) {
                foreach ($field in @('Category', 'Channel', 'Actor', 'Target', 'GroupName', 'ServiceName', 'ExecutablePath', 'ProcessName', 'CommandLine', 'SourceIpAddress', 'FailureCode', 'EventRecordId')) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$event.$field)) {
                        $lines += ('  ' + $field + ': ' + [string]$event.$field)
                    }
                }
            }
            else {
                $lines += ('  Actor: ' + (Format-Value $event.Actor) + '; Target: ' + (Format-Value $event.Target) + '; Source: ' + (Format-Value $event.SourceIpAddress))
                $action = if ($event.CommandLine) { $event.CommandLine } else { $event.ExecutablePath }
                $lines += ('  Action/details: ' + (Format-Value $action))
                if ($event.ServiceName) { $lines += '  Service: ' + $event.ServiceName }
            }
        }
    }

    $lines += ''
    $lines += $(if ($Detailed) { 'AUTHENTICATION SUMMARY' } else { 'Authentication summaries:' })
    foreach ($query in $authQueries) {
        $capText = if ($query.Capped) { ' (bounded/capped sample)' } else { '' }
        $observed = if ($query.Status -eq 'Unavailable') { '<unavailable>' } else { [string]$query.ObservedCount }
        foreach ($eventId in $query.EventIds) {
            $description = (Get-EventDefinition $eventId).Description
            $lines += ('- ' + $eventId + ' ' + $description + ': ' + $query.Status + '; observed ' + $observed + $capText)
        }
    }
    if ($Detailed) {
        $lines += 'Breakdowns use retained authentication records only; queries may be empty, unavailable, partial, or capped.'
        if (@($authQueries | Where-Object { $_.Capped }).Count -gt 0) {
            $lines += 'BOUNDED SAMPLE: capped authentication queries do not represent total environmental activity.'
        }
        $breakdowns = [ordered]@{ 'Actor accounts' = 'Actor'; 'Target accounts' = 'Target'; 'Source IPs' = 'SourceIpAddress' }
        foreach ($label in $breakdowns.Keys) {
            $field = $breakdowns[$label]
            $lines += ''
            $lines += $label + ' (grouped separately by event ID):'
            if ($authentication.Count -eq 0) {
                $lines += 'No retained authentication data; see query coverage. Identities and sources cannot be established.'
                continue
            }
            $identified = @($authentication | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.$field) })
            $groups = @($identified | Group-Object EventId, $field | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name)
            $preview = @($groups | Select-Object -First 20)
            $lines += ('Displayed groups: ' + $preview.Count + '/' + $groups.Count + '; retained events missing this field: ' + ($authentication.Count - $identified.Count))
            if ($identified.Count -eq 0) { $lines += 'No populated values for this field in retained authentication records.' }
            foreach ($group in $preview) {
                $lines += ('- Event ' + $group.Group[0].EventId + '; ' + [string]$group.Group[0].$field + '; observed: ' + $group.Count)
            }
            if ($groups.Count -gt $preview.Count) { $lines += 'Additional groups omitted from TXT; all retained events remain in events.csv and events.json.' }
        }
        $lines += 'Actor, target, and source breakdowns can include the same event; their counts must not be added together.'
        $lines += ''
        $lines += 'COLLECTION STATUS AND LOGGING COVERAGE'
        $lines += $queryLines
        $lines += 'Success: records retained; Empty: no matching records; Partial: capped results or parsing limitations; Unavailable: collection failed.'
    }

    $lines += ''
    $lines += 'Logging configuration:'
    foreach ($log in @($Report.LogStatus)) {
        $lines += ('- ' + $log.LogName + ': ' + $log.Status + '; enabled=' + (Format-Value $log.IsEnabled) + '; records=' + (Format-Value $log.RecordCount))
    }
    $lines += '- Event absence does not prove that no relevant activity occurred; audit policy coverage is not changed by this script.'
    if ($Detailed) {
        $lines += '- Enabled channels do not guarantee appropriate audit-policy coverage; no matching events does not rule out suspicious activity.'
        $lines += '- Capped queries retain bounded results only. Unavailable collection is not equivalent to zero events.'
        $lines += '- Quick and Deep modes inspect different event sets; Deep adds process creation, additional authentication IDs, and PowerShell script blocks.'
        $lines += '- This report summarizes authentication; retained process-creation and PowerShell records remain in events.json and events.csv.'
    }

    if ($CollectionIssues.Count -gt 0) {
        $lines += ''
        $lines += 'Collection failures and limitations:'
        foreach ($issue in $CollectionIssues) {
            $lines += '- ' + $issue
        }
    }
    if ($OutputIssues.Count -gt 0) {
        $lines += ''
        $lines += 'Output issues:'
        foreach ($issue in $OutputIssues) {
            $lines += '- ' + $issue
        }
    }
    $lines += ''
    $lines += ('Output directory: ' + (Format-Value $Report.OutputDirectory))
    if ($Detailed) {
        $lines += ''
        $lines += 'REPORT FILE REFERENCES'
        $lines += 'summary.txt: all retained high-signal security changes, authentication summaries, and collection/logging coverage.'
        $lines += 'events.json: complete retained structured events, EventData, rendered Message, query metadata, and logging status.'
        $lines += 'events.csv: all retained event rows and extracted fields, including EventData and rendered Message.'
    }
    return ($lines -join [Environment]::NewLine)
}

$hostname = $env:COMPUTERNAME
$endTime = Get-Date
$startTime = $endTime.AddHours(-$Hours)
$mode = if ($Deep) { 'Deep' } else { 'Quick' }

$queries = @(
    [pscustomobject]@{
        Name = 'Security changes'
        LogName = 'Security'
        EventIds = @(4720, 4722, 4724, 4725, 4726, 4738, 4728, 4729, 4732, 4733, 4756, 4757, 4698, 4699, 4702, 4719, 1102)
        ReportingLimit = 500
    }
    [pscustomobject]@{
        Name = 'System service installation'
        LogName = 'System'
        EventIds = @(7045)
        ReportingLimit = 100
    }
    [pscustomobject]@{
        Name = 'Windows Defender'
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        EventIds = @(1116, 1117, 5007)
        ReportingLimit = 100
    }
)

foreach ($eventId in @(4624, 4625, 4648, 4672, 4740, 4771)) {
    $queries += [pscustomobject]@{
        Name = 'Authentication ' + $eventId
        LogName = 'Security'
        EventIds = @($eventId)
        ReportingLimit = 300
    }
}

if ($Deep) {
    $queries += [pscustomobject]@{
        Name = 'Process creation'
        LogName = 'Security'
        EventIds = @(4688)
        ReportingLimit = 300
    }
    foreach ($eventId in @(4768, 4769, 4776)) {
        $queries += [pscustomobject]@{
            Name = 'Authentication ' + $eventId
            LogName = 'Security'
            EventIds = @($eventId)
            ReportingLimit = 300
        }
    }
    $queries += [pscustomobject]@{
        Name = 'PowerShell script blocks'
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        EventIds = @(4104)
        ReportingLimit = 150
    }
}

$queryResults = @()
$allEvents = @()
foreach ($query in $queries) {
    $result = Get-EventQuery $query $startTime
    $queryResults += $result
    $allEvents += @($result.Events)
}

$logStatus = Get-LogStatus @($queries | ForEach-Object { $_.LogName })
$highSignalCategories = @('AccountManagement', 'GroupMembership', 'ScheduledTasks', 'SecurityConfiguration', 'ServiceInstallation', 'Defender')
$reviewPreview = @($allEvents |
    Where-Object { $_.Category -in $highSignalCategories } |
    Sort-Object @{ Expression = { if ($_.Timestamp) { [datetimeoffset]$_.Timestamp } else { [datetimeoffset]::MinValue } }; Descending = $true }, LogName, EventRecordId, EventId, QueryName |
    Select-Object -First 10)

$csvRows = @()
foreach ($event in $allEvents) {
    $csvRows += [pscustomobject][ordered]@{
        QueryName = $event.QueryName
        EventId = $event.EventId
        Description = $event.Description
        Category = $event.Category
        Timestamp = $event.Timestamp
        LogName = $event.LogName
        Channel = $event.Channel
        ComputerName = $event.ComputerName
        Provider = $event.Provider
        EventRecordId = $event.EventRecordId
        Actor = $event.Actor
        Target = $event.Target
        SourceIpAddress = $event.SourceIpAddress
        LogonType = $event.LogonType
        GroupName = $event.GroupName
        ServiceName = $event.ServiceName
        ExecutablePath = $event.ExecutablePath
        ProcessName = $event.ProcessName
        CommandLine = $event.CommandLine
        FailureCode = $event.FailureCode
        ScriptBlockId = $event.ScriptBlockId
        ScriptBlockMessageNumber = $event.ScriptBlockMessageNumber
        ScriptBlockTotalMessages = $event.ScriptBlockTotalMessages
        Message = $event.Message
        EventData = ($event.EventData | ConvertTo-Json -Compress -Depth 5)
        ParseError = $event.ParseError
    }
}

$hostFolder = if ($hostname) { $hostname -replace '[\\/:*?"<>|]', '_' } else { 'UnknownHost' }
$scriptDirectory = $PSScriptRoot
$repositoryDirectory = Split-Path -Parent $scriptDirectory
$isRepositoryLayout = (
    (Split-Path -Leaf $scriptDirectory) -eq 'Audit' -and
    (Test-Path -LiteralPath (Join-Path $repositoryDirectory 'AGENTS.md')) -and
    (Test-Path -LiteralPath (Join-Path $repositoryDirectory 'README.md'))
)
if ($OutputDir) {
    $baseOutput = $OutputDir
}
elseif ($isRepositoryLayout) {
    $baseOutput = Join-Path $repositoryDirectory 'Output'
}
else {
    $baseOutput = Join-Path $scriptDirectory 'Output'
}

$outputDirectory = $null
try {
    $outputDirectory = New-UniqueOutputDirectory $baseOutput $hostFolder
}
catch {
    Add-OutputIssue ('Requested output location failed: ' + $_.Exception.Message)
}
if (-not $outputDirectory) {
    try {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-SecurityEventTriage'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
    }
    catch {
        Add-OutputIssue ('Temporary-directory fallback failed: ' + $_.Exception.Message)
    }
}

$report = [ordered]@{
    Version = '0.1'
    CollectedAt = $endTime.ToString('o')
    Hostname = $hostname
    Mode = $mode
    TimeWindow = [ordered]@{
        Start = $startTime.ToString('o')
        End = $endTime.ToString('o')
        Hours = $Hours
    }
    Queries = @($queryResults)
    Events = @($allEvents)
    ReviewPreview = @($reviewPreview)
    LogStatus = @($logStatus)
    LoggingLimitations = 'Event presence or absence does not establish audit-policy coverage. This script does not enable auditing, logging, or channels.'
    CollectionIssues = @($CollectionIssues)
    OutputIssues = @($OutputIssues)
    OutputDirectory = $outputDirectory
    ReportSaved = $false
}

$summaryText = Get-TriageSummary $report $CollectionIssues $OutputIssues -Detailed
$jsonText = $report | ConvertTo-Json -Depth 10
if ($outputDirectory) {
    try {
        $report.ReportSaved = $true
        $summaryText = Get-TriageSummary $report $CollectionIssues $OutputIssues -Detailed
        $jsonText = $report | ConvertTo-Json -Depth 10
        Write-TriageReports $outputDirectory $summaryText $jsonText $csvRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Requested output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $report.ReportSaved = $false
    }
}
if (-not $outputDirectory) {
    try {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-SecurityEventTriage'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
        $report.OutputDirectory = $outputDirectory
        $report.OutputIssues = @($OutputIssues)
        $report.ReportSaved = $true
        $summaryText = Get-TriageSummary $report $CollectionIssues $OutputIssues -Detailed
        $jsonText = $report | ConvertTo-Json -Depth 10
        Write-TriageReports $outputDirectory $summaryText $jsonText $csvRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Final output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $report.ReportSaved = $false
    }
}

$report.OutputDirectory = $outputDirectory
$report.OutputIssues = @($OutputIssues)
$report.ReportSaved = $outputSaved
Write-Output (Get-TriageSummary $report $CollectionIssues $OutputIssues)
if (-not $outputSaved) {
    exit 1
}
