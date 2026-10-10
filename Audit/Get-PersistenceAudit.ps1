<#
.SYNOPSIS
    Collects common Windows persistence locations without changing system state.
#>
[CmdletBinding()]
param(
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

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
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

function Get-ReviewIndicators {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Command
    )

    $text = (($Name + ' ' + $Command).ToLowerInvariant())
    $indicators = @()

    if ($text -match '\\users\\[^\\]+\\(appdata|desktop|downloads|documents)\\|%appdata%|%userprofile%|\\users\\public\\') {
        $indicators += [pscustomobject][ordered]@{
            Indicator = 'UserWritableLocation'
            Reason = $Category + ' references a common user-writable location.'
        }
    }
    if ($text -match '\\temp(\\|$)|%temp%|%tmp%|\\windows\\temp\\|\\appdata\\local\\temp\\') {
        $indicators += [pscustomobject][ordered]@{
            Indicator = 'TemporaryDirectory'
            Reason = $Category + ' references a temporary directory.'
        }
    }
    $interpreterPattern = '(?<![a-z0-9_.-])(?:powershell|pwsh|cmd|wscript|cscript|mshta|python|perl|bash)(?:\.exe)?(?![a-z0-9_.-])'
    if ($text -match $interpreterPattern) {
        $indicators += [pscustomobject][ordered]@{
            Indicator = 'ScriptInterpreter'
            Reason = $Category + ' uses a commonly observed script interpreter.'
        }
    }
    return @($indicators)
}

function Get-RegistryAutoruns {
    $items = @()
    $locations = @()
    $failureCount = 0
    $machineViews = @()

    if ([Environment]::Is64BitOperatingSystem) {
        $machineViews = @(
            [Microsoft.Win32.RegistryView]::Registry64
            [Microsoft.Win32.RegistryView]::Registry32
        )
    }
    else {
        $machineViews = @([Microsoft.Win32.RegistryView]::Default)
    }

    $subKeys = @(
        'Software\Microsoft\Windows\CurrentVersion\Run'
        'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($view in $machineViews) {
        foreach ($subKeyPath in $subKeys) {
            $baseKey = $null
            $key = $null
            $displayPath = 'HKLM (' + $view.ToString() + ')\' + $subKeyPath
            try {
                $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $view
                )
                $key = $baseKey.OpenSubKey($subKeyPath)
                $locationCount = 0
                if ($key) {
                    foreach ($valueName in $key.GetValueNames()) {
                        $valueData = $key.GetValue(
                            $valueName,
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )
                        $command = if ($valueData -is [array]) {
                            [string]($valueData -join '; ')
                        }
                        else {
                            [string]$valueData
                        }
                        $valueKind = $null
                        try {
                            $valueKind = $key.GetValueKind($valueName).ToString()
                        }
                        catch {
                            $valueKind = $null
                        }
                        $items += [pscustomobject][ordered]@{
                            Category = 'RegistryAutorun'
                            Name = [string]$valueName
                            RegistryPath = $displayPath
                            ValueName = [string]$valueName
                            ValueKind = $valueKind
                            Command = $command
                            ReviewIndicators = @(Get-ReviewIndicators 'Registry autorun' $valueName $command)
                        }
                        $locationCount++
                    }
                }
                $locations += [pscustomobject]@{
                    Path = $displayPath
                    Status = if ($locationCount -gt 0) { 'Available' } else { 'Empty' }
                    Count = $locationCount
                }
            }
            catch {
                $failureCount++
                $locations += [pscustomobject]@{
                    Path = $displayPath
                    Status = 'Unavailable'
                    Count = $null
                    Error = $_.Exception.Message
                }
                Add-CollectionIssue ('Collection failure: ' + $displayPath + ': ' + $_.Exception.Message)
            }
            finally {
                if ($key) { $key.Dispose() }
                if ($baseKey) { $baseKey.Dispose() }
            }
        }
    }

    foreach ($subKeyPath in $subKeys) {
        $baseKey = $null
        $key = $null
        $displayPath = 'HKCU\' + $subKeyPath
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::CurrentUser,
                [Microsoft.Win32.RegistryView]::Default
            )
            $key = $baseKey.OpenSubKey($subKeyPath)
            $locationCount = 0
            if ($key) {
                foreach ($valueName in $key.GetValueNames()) {
                    $valueData = $key.GetValue(
                        $valueName,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $command = if ($valueData -is [array]) {
                        [string]($valueData -join '; ')
                    }
                    else {
                        [string]$valueData
                    }
                    $valueKind = $null
                    try {
                        $valueKind = $key.GetValueKind($valueName).ToString()
                    }
                    catch {
                        $valueKind = $null
                    }
                    $items += [pscustomobject][ordered]@{
                        Category = 'RegistryAutorun'
                        Name = [string]$valueName
                        RegistryPath = $displayPath
                        ValueName = [string]$valueName
                        ValueKind = $valueKind
                        Command = $command
                        ReviewIndicators = @(Get-ReviewIndicators 'Registry autorun' $valueName $command)
                    }
                    $locationCount++
                }
            }
            $locations += [pscustomobject]@{
                Path = $displayPath
                Status = if ($locationCount -gt 0) { 'Available' } else { 'Empty' }
                Count = $locationCount
            }
        }
        catch {
            $failureCount++
            $locations += [pscustomobject]@{
                Path = $displayPath
                Status = 'Unavailable'
                Count = $null
                Error = $_.Exception.Message
            }
            Add-CollectionIssue ('Collection failure: ' + $displayPath + ': ' + $_.Exception.Message)
        }
        finally {
            if ($key) { $key.Dispose() }
            if ($baseKey) { $baseKey.Dispose() }
        }
    }

    $status = if ($failureCount -eq $locations.Count) {
        'Unavailable'
    }
    elseif ($failureCount -gt 0) {
        'Partial'
    }
    elseif ($items.Count -eq 0) {
        'Empty'
    }
    else {
        'Success'
    }
    return [pscustomobject][ordered]@{
        Status = $status
        Count = $items.Count
        Items = @($items)
        Locations = @($locations)
        HKCUContext = 'Current execution context only; no additional user registry hives were loaded.'
        Error = if ($failureCount -gt 0) { 'One or more registry locations could not be read.' } else { $null }
    }
}

function Get-WmiSubscriptions {
    $namespace = 'root\subscription'
    $filters = @()
    $commandLineConsumers = @()
    $activeScriptConsumers = @()
    $bindings = @()
    $failureCount = 0

    try {
        foreach ($filter in @(Get-CimInstance -Namespace $namespace -ClassName __EventFilter -ErrorAction Stop)) {
            $filters += [pscustomobject][ordered]@{
                Category = 'WmiEventFilter'
                Name = [string]$filter.Name
                Query = [string]$filter.Query
                QueryLanguage = [string]$filter.QueryLanguage
                CreatorSID = [string]$filter.CreatorSID
                ReviewIndicators = @()
            }
        }
    }
    catch {
        $failureCount++
        Add-CollectionIssue ('Collection failure: WMI __EventFilter in ' + $namespace + ': ' + $_.Exception.Message)
    }

    try {
        foreach ($consumer in @(Get-CimInstance -Namespace $namespace -ClassName CommandLineEventConsumer -ErrorAction Stop)) {
            $command = (([string]$consumer.ExecutablePath) + ' ' + [string]$consumer.CommandLineTemplate).Trim()
            $indicators = @(
                [pscustomobject][ordered]@{
                    Indicator = 'WmiCommandConsumer'
                    Reason = 'WMI CommandLineEventConsumer is configured to launch a command.'
                }
            )
            $indicators += @(Get-ReviewIndicators 'WMI command consumer' $consumer.Name $command)
            $commandLineConsumers += [pscustomobject][ordered]@{
                Category = 'WmiCommandLineConsumer'
                Name = [string]$consumer.Name
                ExecutablePath = [string]$consumer.ExecutablePath
                CommandLineTemplate = [string]$consumer.CommandLineTemplate
                WorkingDirectory = [string]$consumer.WorkingDirectory
                CreatorSID = [string]$consumer.CreatorSID
                Command = $command
                ReviewIndicators = @($indicators)
            }
        }
    }
    catch {
        $failureCount++
        Add-CollectionIssue ('Collection failure: WMI CommandLineEventConsumer in ' + $namespace + ': ' + $_.Exception.Message)
    }

    try {
        foreach ($consumer in @(Get-CimInstance -Namespace $namespace -ClassName ActiveScriptEventConsumer -ErrorAction Stop)) {
            $command = (([string]$consumer.ScriptFileName) + ' ' + [string]$consumer.ScriptText).Trim()
            $indicators = @(
                [pscustomobject][ordered]@{
                    Indicator = 'WmiActiveScriptConsumer'
                    Reason = 'WMI ActiveScriptEventConsumer is configured to launch script content or a script file.'
                }
            )
            $indicators += @(Get-ReviewIndicators 'WMI ActiveScript consumer' $consumer.Name $command)
            $activeScriptConsumers += [pscustomobject][ordered]@{
                Category = 'WmiActiveScriptConsumer'
                Name = [string]$consumer.Name
                ScriptFileName = [string]$consumer.ScriptFileName
                ScriptText = [string]$consumer.ScriptText
                ScriptLanguage = [string]$consumer.ScriptLanguage
                CreatorSID = [string]$consumer.CreatorSID
                Command = $command
                ReviewIndicators = @($indicators)
            }
        }
    }
    catch {
        $failureCount++
        Add-CollectionIssue ('Collection failure: WMI ActiveScriptEventConsumer in ' + $namespace + ': ' + $_.Exception.Message)
    }

    try {
        foreach ($binding in @(Get-CimInstance -Namespace $namespace -ClassName __FilterToConsumerBinding -ErrorAction Stop)) {
            $bindings += [pscustomobject][ordered]@{
                Category = 'WmiFilterToConsumerBinding'
                Name = [string]$binding.__PATH
                FilterReference = [string]$binding.Filter
                ConsumerReference = [string]$binding.Consumer
                CreatorSID = [string]$binding.CreatorSID
                ReviewIndicators = @()
            }
        }
    }
    catch {
        $failureCount++
        Add-CollectionIssue ('Collection failure: WMI __FilterToConsumerBinding in ' + $namespace + ': ' + $_.Exception.Message)
    }

    $total = $filters.Count + $commandLineConsumers.Count + $activeScriptConsumers.Count + $bindings.Count
    $status = if ($failureCount -eq 4 -and $total -eq 0) {
        'Unavailable'
    }
    elseif ($failureCount -gt 0) {
        'Partial'
    }
    elseif ($total -eq 0) {
        'Empty'
    }
    else {
        'Success'
    }
    return [pscustomobject][ordered]@{
        Status = $status
        Count = $total
        Namespace = $namespace
        Filters = @($filters)
        CommandLineConsumers = @($commandLineConsumers)
        ActiveScriptConsumers = @($activeScriptConsumers)
        Bindings = @($bindings)
        UnsupportedConsumerTypes = 'Only __EventFilter, CommandLineEventConsumer, ActiveScriptEventConsumer, and __FilterToConsumerBinding are collected in v0.1; other consumer types are not enumerated.'
        NamespaceCoverage = 'Only root\subscription is inspected.'
        Error = if ($failureCount -gt 0) { 'One or more WMI subscription queries failed.' } else { $null }
    }
}

function Write-PersistenceReports {
    param(
        [string]$Directory,
        [string]$Summary,
        [string]$Json,
        [array]$EntryRows
    )

    $paths = @(
        (Join-Path $Directory 'summary.txt')
        (Join-Path $Directory 'persistence.json')
        (Join-Path $Directory 'entries.csv')
    )
    try {
        Set-Content -LiteralPath $paths[0] -Value $Summary -Encoding UTF8 -ErrorAction Stop
        Set-Content -LiteralPath $paths[1] -Value $Json -Encoding UTF8 -ErrorAction Stop
        if ($EntryRows.Count -gt 0) {
            $EntryRows | Export-Csv -LiteralPath $paths[2] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[2] -Value 'Category,Name,Path,Command,State,Enabled,Account,Details,ReviewIndicators' -Encoding UTF8 -ErrorAction Stop
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

function Get-PersistenceSummary {
    param(
        $Report,
        [array]$CollectionIssues,
        [array]$OutputIssues
    )

    $saved = if ($Report.ReportSaved) { 'Yes' } else { 'No' }
    $lines = @(
        'Windows CCDC Persistence Audit v0.1'
        '===================================='
        ('Hostname: ' + (Format-Value $Report.Hostname))
        ('Scheduled tasks: ' + $Report.ScheduledTasks.Status + ' (' + $Report.ScheduledTasks.Count + ')')
        ('Registry autoruns: ' + $Report.RegistryAutoruns.Status + ' (' + $Report.RegistryAutoruns.Count + ')')
        ('Startup files: ' + $Report.StartupFolders.Status + ' (' + $Report.StartupFolders.Count + ')')
        ('Automatic services: ' + $Report.AutomaticServices.Status + ' (' + $Report.AutomaticServices.Count + ')')
        ('WMI subscriptions: ' + $Report.WmiSubscriptions.Status + ' (' + $Report.WmiSubscriptions.Count + ')')
        ('Report saved: ' + $saved)
    )

    $lines += ''
    $lines += 'WMI subscription summary:'
    $lines += ('- Filters: ' + $Report.WmiSubscriptions.Filters.Count)
    $lines += ('- Command-line consumers: ' + $Report.WmiSubscriptions.CommandLineConsumers.Count)
    $lines += ('- ActiveScript consumers: ' + $Report.WmiSubscriptions.ActiveScriptConsumers.Count)
    $lines += ('- Filter-to-consumer bindings: ' + $Report.WmiSubscriptions.Bindings.Count)
    $lines += '- Nested or unsupported consumer types are not expanded in v0.1.'

    $candidateCount = @($Report.ReviewCandidates).Count
    $lines += ''
    $lines += ('Review candidates (first 10 of ' + $candidateCount + '):')
    if ($candidateCount -eq 0) {
        $lines += '- none'
    }
    else {
        foreach ($candidate in @($Report.ReviewCandidates | Select-Object -First 10)) {
            $lines += ('- [' + $candidate.Category + '] ' + (Format-Value $candidate.Name))
            $lines += ('  Command: ' + (Format-Value $candidate.Command))
            foreach ($reason in @($candidate.Reasons)) {
                $lines += ('  Reason: ' + $reason)
            }
        }
    }

    if ($CollectionIssues.Count -gt 0) {
        $lines += ''
        $lines += 'Collection failures:'
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
    return ($lines -join [Environment]::NewLine)
}

$hostname = $env:COMPUTERNAME
$scheduledItems = @()
$scheduledItemFailures = 0
$scheduledStatus = 'Unavailable'
$scheduledError = $null
if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            try {
                $actions = @($task.Actions | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Type = [string]$_.CimClass.CimClassName
                        Execute = [string]$_.Execute
                        Arguments = [string]$_.Arguments
                        WorkingDirectory = [string]$_.WorkingDirectory
                    }
                })
                $triggers = @($task.Triggers | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Type = [string]$_.CimClass.CimClassName
                        Enabled = $_.Enabled
                        StartBoundary = [string]$_.StartBoundary
                        EndBoundary = [string]$_.EndBoundary
                        UserId = [string]$_.UserId
                        Delay = [string]$_.Delay
                        RandomDelay = [string]$_.RandomDelay
                        Subscription = [string]$_.Subscription
                    }
                })
                $principal = [pscustomobject][ordered]@{
                    UserId = [string]$task.Principal.UserId
                    LogonType = [string]$task.Principal.LogonType
                    RunLevel = [string]$task.Principal.RunLevel
                    ProcessTokenSidType = [string]$task.Principal.ProcessTokenSidType
                }
                $command = @($actions | ForEach-Object {
                    (([string]$_.Execute + ' ' + [string]$_.Arguments).Trim())
                }) -join ' | '
                $scheduledItems += [pscustomobject][ordered]@{
                    Category = 'ScheduledTask'
                    Name = [string]$task.TaskName
                    TaskPath = [string]$task.TaskPath
                    State = [string]$task.State
                    Enabled = $task.Settings.Enabled
                    Actions = $actions
                    Triggers = $triggers
                    Principal = $principal
                    Command = $command
                    ReviewIndicators = @(Get-ReviewIndicators 'Scheduled task' $task.TaskName $command)
                    CollectionError = $null
                }
            }
            catch {
                $scheduledItemFailures++
                Add-CollectionIssue ('Collection failure: scheduled task ' + [string]$task.TaskName + ': ' + $_.Exception.Message)
                $scheduledItems += [pscustomobject][ordered]@{
                    Category = 'ScheduledTask'
                    Name = [string]$task.TaskName
                    TaskPath = [string]$task.TaskPath
                    State = $null
                    Enabled = $null
                    Actions = @()
                    Triggers = @()
                    Principal = $null
                    Command = $null
                    ReviewIndicators = @()
                    CollectionError = $_.Exception.Message
                }
            }
        }
        if ($scheduledItemFailures -gt 0) {
            $scheduledStatus = 'Partial'
        }
        elseif ($scheduledItems.Count -eq 0) {
            $scheduledStatus = 'Empty'
        }
        else {
            $scheduledStatus = 'Success'
        }
    }
    catch {
        $scheduledError = $_.Exception.Message
        Add-CollectionIssue ('Collection failure: scheduled tasks: ' + $scheduledError)
    }
}
else {
    $scheduledError = 'Get-ScheduledTask is unavailable.'
    Add-CollectionIssue $scheduledError
}
$scheduledResult = [ordered]@{
    Status = $scheduledStatus
    Count = $scheduledItems.Count
    Items = @($scheduledItems)
    Error = $scheduledError
}

$registryResult = Get-RegistryAutoruns

$startupItems = @()
$startupLocations = @()
$startupFailures = 0
$startupPaths = @(
    [pscustomobject]@{ Label = 'Common Startup'; Path = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup' }
    [pscustomobject]@{ Label = 'Current User Startup'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup' }
)
foreach ($startupLocation in $startupPaths) {
    try {
        $folder = Get-Item -LiteralPath $startupLocation.Path -Force -ErrorAction Stop
        $locationCount = 0
        foreach ($file in @(Get-ChildItem -LiteralPath $startupLocation.Path -Force -File -ErrorAction Stop)) {
            $startupIndicators = @()
            if ($file.Name -ine 'desktop.ini') {
                $startupIndicators = @(Get-ReviewIndicators 'Startup folder entry' $file.Name $file.FullName)
            }
            $startupItems += [pscustomobject][ordered]@{
                Category = 'StartupFolder'
                Name = [string]$file.Name
                Path = [string]$file.FullName
                Extension = [string]$file.Extension
                LastWriteTime = $file.LastWriteTime.ToString('o')
                Command = [string]$file.FullName
                ReviewIndicators = $startupIndicators
            }
            $locationCount++
        }
        $startupLocations += [pscustomobject]@{
            Label = $startupLocation.Label
            Path = $startupLocation.Path
            Status = if ($locationCount -gt 0) { 'Available' } else { 'Empty' }
            Count = $locationCount
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        $startupLocations += [pscustomobject]@{
            Label = $startupLocation.Label
            Path = $startupLocation.Path
            Status = 'Empty'
            Count = 0
            Note = 'Startup folder is not present.'
        }
    }
    catch {
        $startupFailures++
        Add-CollectionIssue ('Collection failure: ' + $startupLocation.Label + ': ' + $_.Exception.Message)
        $startupLocations += [pscustomobject]@{
            Label = $startupLocation.Label
            Path = $startupLocation.Path
            Status = 'Unavailable'
            Count = $null
            Error = $_.Exception.Message
        }
    }
}
$startupStatus = if ($startupFailures -eq $startupLocations.Count) {
    'Unavailable'
}
elseif ($startupFailures -gt 0) {
    'Partial'
}
elseif ($startupItems.Count -eq 0) {
    'Empty'
}
else {
    'Success'
}
$startupResult = [ordered]@{
    Status = $startupStatus
    Count = $startupItems.Count
    Items = @($startupItems)
    Locations = @($startupLocations)
    Note = 'Entries are listed only; shortcuts are not resolved or executed.'
    Error = if ($startupFailures -gt 0) { 'One or more startup folders could not be read.' } else { $null }
}

$serviceItems = @()
$serviceStatus = 'Unavailable'
$serviceError = $null
try {
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode = 'Auto'" -ErrorAction Stop)) {
        $serviceItems += [pscustomobject][ordered]@{
            Category = 'AutomaticService'
            Name = [string]$service.Name
            DisplayName = [string]$service.DisplayName
            State = [string]$service.State
            StartMode = [string]$service.StartMode
            PathName = [string]$service.PathName
            ServiceAccount = [string]$service.StartName
            ProcessId = $service.ProcessId
            Command = [string]$service.PathName
            ReviewIndicators = @(Get-ReviewIndicators 'Automatic service' $service.Name $service.PathName)
        }
    }
    $serviceStatus = if ($serviceItems.Count -eq 0) { 'Empty' } else { 'Success' }
}
catch {
    $serviceError = $_.Exception.Message
    Add-CollectionIssue ('Collection failure: automatic services: ' + $serviceError)
}
$serviceResult = [ordered]@{
    Status = $serviceStatus
    Count = $serviceItems.Count
    Items = @($serviceItems)
    Error = $serviceError
}

$wmiResult = Get-WmiSubscriptions

$allReviewedItems = @()
$allReviewedItems += @($scheduledItems)
$allReviewedItems += @($registryResult.Items)
$allReviewedItems += @($startupItems)
$allReviewedItems += @($serviceItems)
$allReviewedItems += @($wmiResult.Filters)
$allReviewedItems += @($wmiResult.CommandLineConsumers)
$allReviewedItems += @($wmiResult.ActiveScriptConsumers)
$allReviewedItems += @($wmiResult.Bindings)
$reviewCandidates = @()
foreach ($item in $allReviewedItems) {
    if (@($item.ReviewIndicators).Count -gt 0) {
        $reasons = @($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason })
        $reviewCandidates += [pscustomobject][ordered]@{
            Category = [string]$item.Category
            Name = [string]$item.Name
            Command = [string]$item.Command
            Reasons = $reasons
        }
    }
}

$entryRows = @()
foreach ($item in $scheduledItems) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $item.TaskPath
        Command = $item.Command
        State = $item.State
        Enabled = $item.Enabled
        Account = if ($item.Principal) { $item.Principal.UserId } else { $null }
        Details = ($item | Select-Object Actions,Triggers,Principal,CollectionError | ConvertTo-Json -Depth 6 -Compress)
        ReviewIndicators = (@($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason }) -join ' | ')
    }
}
foreach ($item in @($registryResult.Items)) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $item.RegistryPath
        Command = $item.Command
        State = $null
        Enabled = $true
        Account = $null
        Details = 'ValueName=' + $item.ValueName + '; ValueKind=' + [string]$item.ValueKind
        ReviewIndicators = (@($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason }) -join ' | ')
    }
}
foreach ($item in $startupItems) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $item.Path
        Command = $item.Command
        State = 'Present'
        Enabled = $true
        Account = $null
        Details = 'Extension=' + $item.Extension + '; LastWriteTime=' + $item.LastWriteTime
        ReviewIndicators = (@($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason }) -join ' | ')
    }
}
foreach ($item in $serviceItems) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $item.PathName
        Command = $item.Command
        State = $item.State
        Enabled = $true
        Account = $item.ServiceAccount
        Details = 'DisplayName=' + $item.DisplayName + '; StartMode=' + $item.StartMode + '; ProcessId=' + [string]$item.ProcessId
        ReviewIndicators = (@($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason }) -join ' | ')
    }
}
foreach ($item in @($wmiResult.Filters)) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $wmiResult.Namespace
        Command = $item.Query
        State = $item.QueryLanguage
        Enabled = $null
        Account = $item.CreatorSID
        Details = 'Query=' + $item.Query
        ReviewIndicators = ''
    }
}
foreach ($item in @($wmiResult.CommandLineConsumers) + @($wmiResult.ActiveScriptConsumers)) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = if ($item.ExecutablePath) { $item.ExecutablePath } else { $item.ScriptFileName }
        Command = $item.Command
        State = $null
        Enabled = $true
        Account = $item.CreatorSID
        Details = ($item | ConvertTo-Json -Depth 5 -Compress)
        ReviewIndicators = (@($item.ReviewIndicators | ForEach-Object { $_.Indicator + ': ' + $_.Reason }) -join ' | ')
    }
}
foreach ($item in @($wmiResult.Bindings)) {
    $entryRows += [pscustomobject][ordered]@{
        Category = $item.Category
        Name = $item.Name
        Path = $wmiResult.Namespace
        Command = $item.ConsumerReference
        State = $null
        Enabled = $true
        Account = $item.CreatorSID
        Details = 'FilterReference=' + $item.FilterReference + '; ConsumerReference=' + $item.ConsumerReference
        ReviewIndicators = ''
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-PersistenceAudit'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
    }
    catch {
        Add-OutputIssue ('Temporary-directory fallback failed: ' + $_.Exception.Message)
    }
}

$report = [ordered]@{
    Version = '0.1'
    CollectedAt = (Get-Date).ToString('o')
    Hostname = $hostname
    ScheduledTasks = $scheduledResult
    RegistryAutoruns = $registryResult
    StartupFolders = $startupResult
    AutomaticServices = $serviceResult
    WmiSubscriptions = $wmiResult
    ReviewCandidates = @($reviewCandidates)
    CollectionIssues = @($CollectionIssues)
    OutputIssues = @($OutputIssues)
    OutputDirectory = $outputDirectory
    ReportSaved = $false
}

$summaryText = Get-PersistenceSummary $report $CollectionIssues $OutputIssues
$jsonText = $report | ConvertTo-Json -Depth 12
if ($outputDirectory) {
    try {
        $report.ReportSaved = $true
        $summaryText = Get-PersistenceSummary $report $CollectionIssues $OutputIssues
        $jsonText = $report | ConvertTo-Json -Depth 12
        Write-PersistenceReports $outputDirectory $summaryText $jsonText $entryRows
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-PersistenceAudit'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
        $report.OutputDirectory = $outputDirectory
        $report.OutputIssues = @($OutputIssues)
        $report.ReportSaved = $true
        $summaryText = Get-PersistenceSummary $report $CollectionIssues $OutputIssues
        $jsonText = $report | ConvertTo-Json -Depth 12
        Write-PersistenceReports $outputDirectory $summaryText $jsonText $entryRows
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
Write-Output (Get-PersistenceSummary $report $CollectionIssues $OutputIssues)
if (-not $outputSaved) {
    exit 1
}
