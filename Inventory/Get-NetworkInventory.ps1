<#
.SYNOPSIS
    Collects a read-only Windows network inventory for CCDC use.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $false)][string]$OutputDir)

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
    param([string]$Root, [string]$HostFolder)
    $stamp = 'NetworkInventory_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
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

function Format-ResultCount {
    param($Result)
    if ($Result.Status -eq 'Unavailable') {
        return '<unavailable>'
    }
    return [string]$Result.Count
}

function Format-AddressList {
    param($Addresses)
    if ($null -eq $Addresses) {
        return '<unavailable>'
    }
    if (@($Addresses).Count -eq 0) {
        return '<none>'
    }
    return (($Addresses | ForEach-Object {
        (Format-Value $_.IPAddress) + '/' + (Format-Value $_.PrefixLength)
    }) -join ', ')
}

function Format-TextList {
    param($Values)
    if ($null -eq $Values) {
        return '<unavailable>'
    }
    if (@($Values).Count -eq 0) {
        return '<none>'
    }
    return (($Values | ForEach-Object { [string]$_ }) -join ', ')
}

function Write-NetworkReports {
    param(
        [string]$Directory,
        [string]$Summary,
        [string]$Json,
        [array]$ListenerRows,
        [array]$ServiceRows
    )
    $paths = @(
        (Join-Path $Directory 'summary.txt')
        (Join-Path $Directory 'network.json')
        (Join-Path $Directory 'listeners.csv')
        (Join-Path $Directory 'running-services.csv')
    )
    try {
        Set-Content -LiteralPath $paths[0] -Value $Summary -Encoding UTF8 -ErrorAction Stop
        Set-Content -LiteralPath $paths[1] -Value $Json -Encoding UTF8 -ErrorAction Stop
        if ($ListenerRows.Count -gt 0) {
            $ListenerRows | Export-Csv -LiteralPath $paths[2] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[2] -Value 'Protocol,EndpointType,LocalAddress,LocalPort,ProcessId,ProcessName,AssociatedServiceNames,ServiceAssociation' -Encoding UTF8 -ErrorAction Stop
        }
        if ($ServiceRows.Count -gt 0) {
            $ServiceRows | Export-Csv -LiteralPath $paths[3] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[3] -Value 'ServiceName,DisplayName,State,StartupType,ProcessId,ExecutablePath,ServiceAccount' -Encoding UTF8 -ErrorAction Stop
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

function Get-NetworkSummary {
    param($Inventory, [array]$CollectionIssues, [array]$OutputIssues, [switch]$Detailed)
    if ($Inventory.ReportSaved) { $saved = 'Yes' } else { $saved = 'No' }
    $lines = @(
        'Windows CCDC Network Inventory v0.1'
        '=================================='
        ('Hostname: ' + (Format-Value $Inventory.Hostname))
        ('Report saved: ' + $saved)
        ('Interfaces: ' + $Inventory.Interfaces.Status + ' (' + (Format-ResultCount $Inventory.Interfaces) + ')')
        ('Interface addresses: ' + $Inventory.InterfaceAddresses.Status)
        ('Gateways and DNS: ' + $Inventory.GatewayDns.Status)
        ('IPv4 routes: ' + $Inventory.Routes.IPv4.Status + ' (' + (Format-ResultCount $Inventory.Routes.IPv4) + ')')
        ('IPv6 routes: ' + $Inventory.Routes.IPv6.Status + ' (' + (Format-ResultCount $Inventory.Routes.IPv6) + ')')
        ('TCP listeners: ' + $Inventory.Listeners.TCP.Status + ' (' + (Format-ResultCount $Inventory.Listeners.TCP) + ')')
        ('UDP endpoints: ' + $Inventory.Listeners.UDP.Status + ' (' + (Format-ResultCount $Inventory.Listeners.UDP) + ')')
        ('Running services: ' + $Inventory.Services.Status + ' (' + (Format-ResultCount $Inventory.Services) + ')')
        ('Firewall profiles: ' + $Inventory.FirewallProfiles.Status + ' (' + (Format-ResultCount $Inventory.FirewallProfiles) + ')')
    )

    if ($Detailed) {
        # A single default-route interface with a single IPv4 address is unambiguous.
        # Do not choose between multiple interfaces/addresses using route metrics alone.
        $defaultV4 = @($Inventory.Routes.IPv4.Items | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
        $defaultIndices = @($defaultV4 | Select-Object -ExpandProperty InterfaceIndex -Unique)
        $primaryInterfaces = @($Inventory.Interfaces.Items | Where-Object { $_.InterfaceIndex -in $defaultIndices })
        $primary = 'Unknown; see NETWORK CONFIGURATION'
        if ($Inventory.Routes.IPv4.Status -eq 'Success' -and $Inventory.Interfaces.Status -eq 'Success' -and
            $Inventory.InterfaceAddresses.Status -eq 'Success' -and $defaultIndices.Count -eq 1 -and
            $primaryInterfaces.Count -eq 1 -and $null -ne $primaryInterfaces[0].IPv4Addresses -and
            @($primaryInterfaces[0].IPv4Addresses).Count -eq 1) {
            $primary = Format-AddressList $primaryInterfaces[0].IPv4Addresses
        }
        $configured = @($Inventory.Interfaces.Items | Where-Object {
            ($null -ne $_.DefaultGateways -and @($_.DefaultGateways).Count -gt 0) -or
            ($null -ne $_.IPv4Addresses -and @($_.IPv4Addresses).Count -gt 0) -or
            ($null -ne $_.IPv6Addresses -and @($_.IPv6Addresses).Count -gt 0)
        })
        $gatewayOverview = 'Unknown; see NETWORK CONFIGURATION'
        $dnsOverview = 'Unknown; see NETWORK CONFIGURATION'
        if ($Inventory.GatewayDns.Status -eq 'Unavailable' -or $Inventory.Interfaces.Status -eq 'Unavailable') {
            $gatewayOverview = '<unavailable>'
            $dnsOverview = '<unavailable>'
        }
        elseif ($configured.Count -eq 1) {
            $gatewayOverview = Format-TextList $configured[0].DefaultGateways
            $dnsOverview = Format-TextList $configured[0].DNSServers
        }
        elseif ($configured.Count -gt 1) {
            $gatewayOverview = 'Multiple interface configurations; see NETWORK CONFIGURATION'
            $dnsOverview = $gatewayOverview
        }
        $firewallOverview = @($Inventory.FirewallProfiles.Items | ForEach-Object {
            $_.ProfileName + '=' + (Format-Value $_.Enabled)
        }) -join '; '
        $lines = @(
            ('Get-NetworkInventory.ps1 v' + $Inventory.Version)
            ('Hostname: ' + (Format-Value $Inventory.Hostname) + '; Collected: ' + $Inventory.CollectedAt)
            ('Report saved: ' + $saved + '; Output: ' + (Format-Value $Inventory.OutputDirectory))
            ''
            'AT A GLANCE'
            ('Primary IPv4: ' + $primary)
            ('Default gateway: ' + $gatewayOverview)
            ('DNS servers: ' + $dnsOverview)
            ('TCP listeners: ' + (Format-ResultCount $Inventory.Listeners.TCP) + '; UDP endpoints: ' + (Format-ResultCount $Inventory.Listeners.UDP))
            ('Running services: ' + (Format-ResultCount $Inventory.Services))
            ('Firewall enabled: ' + $firewallOverview)
            ''
            'NETWORK CONFIGURATION'
            ('Interfaces: ' + $Inventory.Interfaces.Status + '; addresses: ' + $Inventory.InterfaceAddresses.Status + '; gateways/DNS: ' + $Inventory.GatewayDns.Status)
        )
    }

    $lines += ''
    $lines += 'Connected or operational interfaces:'
    if ($Inventory.Interfaces.Status -eq 'Unavailable') {
        $lines += '- unavailable: ' + (Format-Value $Inventory.Interfaces.Error)
    }
    else {
        $operationalStatuses = @(
            'Connected'
            'Connecting'
            'Disconnecting'
            'Authenticating'
            'Authentication succeeded'
            'Authentication failed'
            'Credentials required'
        )
        $operationalInterfaces = @($Inventory.Interfaces.Items | Where-Object {
            $operationalStatuses -contains $_.OperationalStatus -or
            ($null -ne $_.IPv4Addresses -and @($_.IPv4Addresses).Count -gt 0) -or
            ($null -ne $_.IPv6Addresses -and @($_.IPv6Addresses).Count -gt 0)
        })
        if ($operationalInterfaces.Count -eq 0) {
            $lines += '- none; disconnected interfaces remain in network.json'
        }
        else {
            foreach ($interface in $operationalInterfaces) {
                $lines += ('- ' + (Format-Value $interface.InterfaceName) +
                    ' [' + (Format-Value $interface.OperationalStatus) + ']')
                $lines += ('  IPv4: ' + (Format-AddressList $interface.IPv4Addresses))
                $lines += ('  IPv6: ' + (Format-AddressList $interface.IPv6Addresses))
                $lines += ('  Gateways: ' + (Format-TextList $interface.DefaultGateways))
                $lines += ('  DNS: ' + (Format-TextList $interface.DNSServers))
            }
        }
    }

    $lines += ''
    $lines += 'Default routes:'
    foreach ($family in @('IPv4', 'IPv6')) {
        $routeResult = $Inventory.Routes[$family]
        if ($routeResult.Status -eq 'Unavailable') {
            $lines += ('- ' + $family + ': unavailable')
            continue
        }
        $defaultPrefix = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
        $defaultRoutes = @($routeResult.Items | Where-Object { $_.DestinationPrefix -eq $defaultPrefix })
        if ($defaultRoutes.Count -eq 0) {
            $lines += ('- ' + $family + ': none')
        }
        else {
            foreach ($route in $defaultRoutes) {
                $lines += ('- ' + $family + ' ' + (Format-Value $route.NextHop) +
                    ' via interface ' + (Format-Value $route.InterfaceIndex) +
                    ' metric ' + (Format-Value $route.RouteMetric))
            }
        }
    }

    if ($Detailed) {
        $lines += ''
        $lines += 'LISTENING TCP PORTS'
        $lines += ('Total: ' + (Format-ResultCount $Inventory.Listeners.TCP) + '; status: ' + $Inventory.Listeners.TCP.Status)
        if ($Inventory.Listeners.TCP.Status -ne 'Unavailable') {
            $lines += ('Displayed listeners: ' + $Inventory.Listeners.TCP.Count + ' (all collected TCP listeners)')
        }
        $lines += 'Services are associated by PID; shared processes do not establish individual service socket ownership.'
        $lines += 'A local listener does not establish external reachability.'
    }
    $listenerLabel = if ($Detailed) { 'TCP listeners' } else { 'TCP listener preview' }
    if ($Inventory.Listeners.TCP.Status -eq 'Unavailable') {
        $lines += ''
        $lines += $listenerLabel + ': unavailable'
    }
    elseif ($Inventory.Listeners.TCP.Count -eq 0) {
        $lines += ''
        $lines += $listenerLabel + ': none'
    }
    else {
        $lines += ''
        $preview = @($Inventory.Listeners.TCP.Items |
            Sort-Object @{ Expression = { if ($null -eq $_.LocalPort) { [int]::MaxValue } else { [int]$_.LocalPort } } }, LocalAddress)
        if ($Detailed) {
            $lines += 'All TCP listeners, sorted by port, then address:'
            $tableText = ($preview | Format-Table -Wrap -Property @(
                @{ Label = 'PORT'; Expression = { Format-Value $_.LocalPort }; Width = 5 }
                @{ Label = 'ADDRESS'; Expression = { Format-Value $_.LocalAddress }; Width = 39 }
                @{ Label = 'PID'; Expression = { Format-Value $_.ProcessId }; Width = 8 }
                @{ Label = 'PROCESS'; Expression = { Format-Value $_.ProcessName }; Width = 18 }
                @{ Label = 'ASSOCIATED SERVICES'; Expression = { Format-TextList $_.AssociatedServiceNames }; Width = 26 }
            ) | Out-String -Width 110).TrimEnd()
        }
        else {
            $lines += 'TCP listener preview (first 20 by port, then address; PID associations are not proof of ownership):'
            $preview = @($preview | Select-Object -First 20)
            $previewRows = @($preview | ForEach-Object {
                [pscustomobject][ordered]@{
                    Address = Format-Value $_.LocalAddress
                    Port = Format-Value $_.LocalPort
                    Process = (Format-Value $_.ProcessName) + ' (' + (Format-Value $_.ProcessId) + ')'
                    'PID-associated services' = ($_.AssociatedServiceNames -join '; ')
                }
            })
            $tableText = ($previewRows | Format-Table -AutoSize | Out-String -Width 240).TrimEnd()
        }
        $lines += $tableText
        if (-not $Detailed -and $Inventory.Listeners.TCP.Count -gt 20) {
            $lines += ('... ' + ($Inventory.Listeners.TCP.Count - 20) + ' additional TCP listeners omitted from this preview; see summary.txt, listeners.csv and network.json')
        }
    }

    if ($Detailed) {
        $lines += ''
        $lines += 'UDP SUMMARY'
        $lines += ('Total endpoints: ' + (Format-ResultCount $Inventory.Listeners.UDP) + '; status: ' + $Inventory.Listeners.UDP.Status)
        $lines += 'Aggregate only: top 10 processes by endpoint count, not individual UDP ports.'
        if ($Inventory.Listeners.UDP.Status -ne 'Unavailable' -and $Inventory.Listeners.UDP.Count -gt 0) {
            $udpGroups = @($Inventory.Listeners.UDP.Items | Group-Object ProcessId, ProcessName |
                Sort-Object @{ Expression = { $_.Count }; Descending = $true }, Name)
            $udpRows = $udpGroups | Select-Object -First 10 | ForEach-Object {
                [pscustomobject][ordered]@{
                    Process = Format-Value $_.Group[0].ProcessName
                    PID = Format-Value $_.Group[0].ProcessId
                    Endpoints = $_.Count
                }
            }
            $lines += ($udpRows | Format-Table -AutoSize -Wrap | Out-String -Width 110).TrimEnd()
            if ($udpGroups.Count -gt 10) {
                $lines += (($udpGroups.Count - 10).ToString() + ' additional process groups omitted; see listeners.csv.')
            }
        }
        $lines += ''
        $lines += 'NETWORK-ASSOCIATED RUNNING SERVICES'
        $lines += ('All running services: ' + (Format-ResultCount $Inventory.Services) + '; status: ' + $Inventory.Services.Status)
        $lines += 'Subset associated by PID with TCP listeners; full details follow under ALL RUNNING SERVICES.'
        if ($Inventory.Services.Status -eq 'Unavailable' -or $Inventory.Listeners.TCP.Status -eq 'Unavailable') {
            $lines += 'Subset unavailable: service or TCP collection unavailable.'
        }
        else {
            $tcpPids = @{}
            foreach ($listener in $Inventory.Listeners.TCP.Items) {
                if ($null -ne $listener.ProcessId -and $listener.ProcessId -gt 0) {
                    $tcpPids[[string]$listener.ProcessId] = $true
                }
            }
            $associated = @($Inventory.Services.Items | Where-Object { $tcpPids.ContainsKey([string]$_.ProcessId) } | Sort-Object ServiceName)
            $lines += ('Associated running services: ' + $associated.Count + ' (first 20 shown)')
            foreach ($service in @($associated | Select-Object -First 20)) {
                $lines += ('- ' + $service.ServiceName + '; PID ' + (Format-Value $service.ProcessId))
            }
            if ($associated.Count -gt 20) {
                $lines += (($associated.Count - 20).ToString() + ' additional associated services omitted from overview; all services are listed below.')
            }
        }
        $lines += ''
        $lines += 'ALL RUNNING SERVICES'
        $lines += ('Total: ' + (Format-ResultCount $Inventory.Services) + '; status: ' + $Inventory.Services.Status)
        if ($Inventory.Services.Status -eq 'Unavailable') {
            $lines += 'Running services unavailable: ' + (Format-Value $Inventory.Services.Error)
        }
        elseif ($Inventory.Services.Count -eq 0) {
            $lines += 'No running services collected.'
        }
        else {
            foreach ($service in @($Inventory.Services.Items | Sort-Object ServiceName)) {
                $lines += ('- ' + (Format-Value $service.ServiceName))
                $lines += ('  Status: ' + (Format-Value $service.State) + '; startup: ' + (Format-Value $service.StartupType) + '; PID: ' + (Format-Value $service.ProcessId))
                $lines += ('  Path: ' + (Format-Value $service.ExecutablePath))
                $lines += ''
            }
        }
    }

    $lines += ''
    $lines += $(if ($Detailed) { 'WINDOWS FIREWALL' } else { 'Firewall profiles:' })
    foreach ($profile in $Inventory.FirewallProfiles.Items) {
        $lines += ('- ' + $profile.ProfileName + ': ' + $profile.Status +
            '; enabled=' + (Format-Value $profile.Enabled) +
            '; inbound=' + (Format-Value $profile.DefaultInboundAction) +
            '; outbound=' + (Format-Value $profile.DefaultOutboundAction))
    }
    if ($Detailed) {
        $lines += ''
        $lines += 'COLLECTION NOTES AND LIMITATIONS'
        $lines += ('IPv4 routes: ' + $Inventory.Routes.IPv4.Status + ' (' + (Format-ResultCount $Inventory.Routes.IPv4) + '); IPv6 routes: ' + $Inventory.Routes.IPv6.Status + ' (' + (Format-ResultCount $Inventory.Routes.IPv6) + ')')
        $lines += 'Only default routes are presented above; all collected routes and interfaces are in network.json.'
        $lines += $Inventory.ServiceAssociationNote
        $lines += 'Empty/none means queried with no matching entries; unavailable means collection or field lookup failed.'
    }
    if ($CollectionIssues.Count -gt 0) {
        $lines += ''
        $lines += 'Collection issues:'
        foreach ($issue in $CollectionIssues) { $lines += '- ' + $issue }
    }
    if ($OutputIssues.Count -gt 0) {
        $lines += ''
        $lines += 'Output issues:'
        foreach ($issue in $OutputIssues) { $lines += '- ' + $issue }
    }
    $lines += ''
    $lines += ('Output directory: ' + (Format-Value $Inventory.OutputDirectory))
    if ($Detailed) {
        $lines += ''
        $lines += 'REPORT FILE REFERENCES'
        $lines += 'summary.txt: curated presentation; presentation limits do not limit collection.'
        $lines += 'listeners.csv: complete collected TCP/UDP endpoint mapping.'
        $lines += 'running-services.csv: complete collected running-service inventory.'
        $lines += 'network.json: complete structured network inventory, collection statuses, and errors.'
    }
    return ($lines -join [Environment]::NewLine)
}

$hostname = $env:COMPUTERNAME
if (-not $hostname) {
    Add-CollectionIssue 'Missing: hostname.'
}

$adapterQueryFailed = $false
$adapters = @()
try {
    $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $adapterQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Win32_NetworkAdapter: ' + $_.Exception.Message)
}
$configQueryFailed = $false
$adapterConfigurations = @()
try {
    $adapterConfigurations = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $configQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Win32_NetworkAdapterConfiguration: ' + $_.Exception.Message)
}

$addressQueryFailed = $false
$netAddresses = @()
try {
    $netAddresses = @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $addressQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Get-NetIPAddress: ' + $_.Exception.Message)
}

$configByIndex = @{}
foreach ($configuration in $adapterConfigurations) {
    if ($null -ne $configuration.Index) {
        $configByIndex[[string]$configuration.Index] = $configuration
    }
}
$addressesByInterface = @{}
foreach ($address in $netAddresses) {
    if ($null -eq $address.InterfaceIndex) { continue }
    $key = [string]$address.InterfaceIndex
    if (-not $addressesByInterface.ContainsKey($key)) {
        $addressesByInterface[$key] = @()
    }
    $addressesByInterface[$key] += [pscustomobject][ordered]@{
        IPAddress = [string]$address.IPAddress
        PrefixLength = $address.PrefixLength
        AddressFamily = [string]$address.AddressFamily
    }
}

$statusNames = @{
    0 = 'Disconnected'
    1 = 'Connecting'
    2 = 'Connected'
    3 = 'Disconnecting'
    4 = 'Hardware not present'
    5 = 'Hardware disabled'
    6 = 'Hardware malfunction'
    7 = 'Media disconnected'
    8 = 'Authenticating'
    9 = 'Authentication succeeded'
    10 = 'Authentication failed'
    11 = 'Invalid address'
    12 = 'Credentials required'
}
$interfaceItems = @()
foreach ($adapter in $adapters) {
    $interfaceIndex = $adapter.InterfaceIndex
    $interfaceKey = if ($null -ne $interfaceIndex) { [string]$interfaceIndex } else { $null }
    $adapterIndex = if ($null -ne $adapter.Index) { [string]$adapter.Index } else { $interfaceKey }
    $interfaceName = if ($adapter.NetConnectionID) { [string]$adapter.NetConnectionID } else { [string]$adapter.Name }
    $operationalStatus = $null
    if ($null -ne $adapter.NetConnectionStatus) {
        $statusCode = [int]$adapter.NetConnectionStatus
        if ($statusNames.ContainsKey($statusCode)) {
            $operationalStatus = $statusNames[$statusCode]
        }
        else {
            $operationalStatus = 'Unknown (' + $statusCode + ')'
        }
    }
    $configuration = if ($adapterIndex -and $configByIndex.ContainsKey($adapterIndex)) { $configByIndex[$adapterIndex] } else { $null }
    if ($addressQueryFailed) {
        $ipv4Addresses = $null
        $ipv6Addresses = $null
        $addressStatus = 'Unavailable'
    }
    else {
        $interfaceAddresses = if ($interfaceKey -and $addressesByInterface.ContainsKey($interfaceKey)) { @($addressesByInterface[$interfaceKey]) } else { @() }
        $ipv4Addresses = @($interfaceAddresses | Where-Object { $_.AddressFamily -eq 'IPv4' })
        $ipv6Addresses = @($interfaceAddresses | Where-Object { $_.AddressFamily -eq 'IPv6' })
        $addressStatus = 'Success'
    }
    if ($configQueryFailed) {
        $gateways = $null
        $dnsServers = $null
        $gatewayDnsStatus = 'Unavailable'
    }
    elseif ($configuration) {
        $gateways = if ($configuration.DefaultIPGateway) { @($configuration.DefaultIPGateway) } else { @() }
        $dnsServers = if ($configuration.DNSServerSearchOrder) { @($configuration.DNSServerSearchOrder) } else { @() }
        $gatewayDnsStatus = 'Success'
    }
    else {
        $gateways = $null
        $dnsServers = $null
        $gatewayDnsStatus = 'Missing'
    }
    $interfaceItems += [pscustomobject][ordered]@{
        InterfaceName = $interfaceName
        Description = [string]$adapter.Description
        OperationalStatus = $operationalStatus
        InterfaceIndex = $interfaceIndex
        IPv4Addresses = $ipv4Addresses
        IPv6Addresses = $ipv6Addresses
        DefaultGateways = $gateways
        DNSServers = $dnsServers
        AddressDataStatus = $addressStatus
        GatewayDnsStatus = $gatewayDnsStatus
    }
}
$interfaceResult = [ordered]@{
    Status = if ($adapterQueryFailed) { 'Unavailable' } elseif ($interfaceItems.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($adapterQueryFailed) { $null } else { $interfaceItems.Count }
    Items = if ($adapterQueryFailed) { $null } else { @($interfaceItems) }
    Error = if ($adapterQueryFailed) { 'Network adapter collection failed.' } else { $null }
}
$interfaceAddressResult = [ordered]@{
    Status = if ($addressQueryFailed) { 'Unavailable' } elseif ($netAddresses.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($addressQueryFailed) { $null } else { $netAddresses.Count }
    Error = if ($addressQueryFailed) { 'Network address collection failed.' } else { $null }
}
$gatewayDnsResult = [ordered]@{
    Status = if ($configQueryFailed) { 'Unavailable' } elseif ($adapterConfigurations.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($configQueryFailed) { $null } else { $adapterConfigurations.Count }
    Error = if ($configQueryFailed) { 'Network configuration collection failed.' } else { $null }
}

$routeResults = [ordered]@{}
foreach ($family in @('IPv4', 'IPv6')) {
    $routeQueryFailed = $false
    $routes = @()
    try {
        $routes = @(Get-NetRoute -AddressFamily $family -ErrorAction Stop | Where-Object { $null -ne $_ })
    }
    catch {
        $routeQueryFailed = $true
        Add-CollectionIssue ('Collection failure: Get-NetRoute ' + $family + ': ' + $_.Exception.Message)
    }
    $routeItems = @()
    foreach ($route in $routes) {
        $routeItems += [pscustomobject][ordered]@{
            DestinationPrefix = [string]$route.DestinationPrefix
            NextHop = [string]$route.NextHop
            InterfaceIndex = $route.InterfaceIndex
            RouteMetric = $route.RouteMetric
        }
    }
    $routeResults[$family] = [ordered]@{
        Status = if ($routeQueryFailed) { 'Unavailable' } elseif ($routeItems.Count -eq 0) { 'Empty' } else { 'Success' }
        Count = if ($routeQueryFailed) { $null } else { $routeItems.Count }
        Items = if ($routeQueryFailed) { $null } else { @($routeItems) }
        Error = if ($routeQueryFailed) { 'Route collection failed.' } else { $null }
    }
}

$serviceQueryFailed = $false
$runningServiceObjects = @()
try {
    $runningServiceObjects = @(Get-CimInstance -ClassName Win32_Service -Filter "State = 'Running'" -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $serviceQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Win32_Service: ' + $_.Exception.Message)
}
$serviceItems = @()
$serviceNamesByPid = @{}
foreach ($service in $runningServiceObjects) {
    $pidValue = if ($null -ne $service.ProcessId) { [int]$service.ProcessId } else { $null }
    $serviceItems += [pscustomobject][ordered]@{
        ServiceName = [string]$service.Name
        DisplayName = [string]$service.DisplayName
        State = [string]$service.State
        StartupType = [string]$service.StartMode
        ProcessId = $pidValue
        ExecutablePath = [string]$service.PathName
        ServiceAccount = [string]$service.StartName
    }
    if ($null -ne $pidValue -and $pidValue -gt 0) {
        $pidKey = [string]$pidValue
        if (-not $serviceNamesByPid.ContainsKey($pidKey)) {
            $serviceNamesByPid[$pidKey] = @()
        }
        $serviceNamesByPid[$pidKey] += [string]$service.Name
    }
}
$serviceResult = [ordered]@{
    Status = if ($serviceQueryFailed) { 'Unavailable' } elseif ($serviceItems.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($serviceQueryFailed) { $null } else { $serviceItems.Count }
    Items = if ($serviceQueryFailed) { $null } else { @($serviceItems) }
    Error = if ($serviceQueryFailed) { 'Running service collection failed.' } else { $null }
}

$processNamesByPid = @{}
function Get-ProcessNameForPid {
    param($ProcessId)
    $key = [string]$ProcessId
    if ($processNamesByPid.ContainsKey($key)) { return $processNamesByPid[$key] }
    if ($null -eq $ProcessId) { return $null }
    try {
        $process = Get-Process -Id ([int]$ProcessId) -ErrorAction Stop
        $processNamesByPid[$key] = [string]$process.ProcessName
    }
    catch {
        Add-CollectionIssue ('Process name unavailable for PID ' + $ProcessId + ': ' + $_.Exception.Message)
        $processNamesByPid[$key] = $null
    }
    return $processNamesByPid[$key]
}

$tcpQueryFailed = $false
$tcpConnections = @()
try {
    $tcpConnections = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $tcpQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Get-NetTCPConnection: ' + $_.Exception.Message)
}
$tcpItems = @()
foreach ($connection in $tcpConnections) {
    $pidValue = $connection.OwningProcess
    $pidKey = if ($null -ne $pidValue) { [string]$pidValue } else { $null }
    if ($pidKey -and $serviceNamesByPid.ContainsKey($pidKey)) {
        $associatedServices = @($serviceNamesByPid[$pidKey])
        $associationStatus = 'PID-associated'
    }
    else {
        $associatedServices = @('Unknown')
        $associationStatus = 'Unknown'
    }
    $tcpItems += [pscustomobject][ordered]@{
        Protocol = 'TCP'
        EndpointType = 'Listening'
        LocalAddress = [string]$connection.LocalAddress
        LocalPort = $connection.LocalPort
        ProcessId = $pidValue
        ProcessName = Get-ProcessNameForPid $pidValue
        AssociatedServiceNames = $associatedServices
        ServiceAssociation = $associationStatus
    }
}
$udpQueryFailed = $false
$udpEndpoints = @()
try {
    $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $udpQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Get-NetUDPEndpoint: ' + $_.Exception.Message)
}
$udpItems = @()
foreach ($endpoint in $udpEndpoints) {
    $pidValue = $endpoint.OwningProcess
    $pidKey = if ($null -ne $pidValue) { [string]$pidValue } else { $null }
    if ($pidKey -and $serviceNamesByPid.ContainsKey($pidKey)) {
        $associatedServices = @($serviceNamesByPid[$pidKey])
        $associationStatus = 'PID-associated'
    }
    else {
        $associatedServices = @('Unknown')
        $associationStatus = 'Unknown'
    }
    $udpItems += [pscustomobject][ordered]@{
        Protocol = 'UDP'
        EndpointType = 'Bound'
        LocalAddress = [string]$endpoint.LocalAddress
        LocalPort = $endpoint.LocalPort
        ProcessId = $pidValue
        ProcessName = Get-ProcessNameForPid $pidValue
        AssociatedServiceNames = $associatedServices
        ServiceAssociation = $associationStatus
    }
}
$tcpResult = [ordered]@{
    Status = if ($tcpQueryFailed) { 'Unavailable' } elseif ($tcpItems.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($tcpQueryFailed) { $null } else { $tcpItems.Count }
    Items = if ($tcpQueryFailed) { $null } else { @($tcpItems) }
    Error = if ($tcpQueryFailed) { 'TCP listener collection failed.' } else { $null }
}
$udpResult = [ordered]@{
    Status = if ($udpQueryFailed) { 'Unavailable' } elseif ($udpItems.Count -eq 0) { 'Empty' } else { 'Success' }
    Count = if ($udpQueryFailed) { $null } else { $udpItems.Count }
    Items = if ($udpQueryFailed) { $null } else { @($udpItems) }
    Error = if ($udpQueryFailed) { 'UDP endpoint collection failed.' } else { $null }
}

$firewallQueryFailed = $false
$firewallObjects = @()
try {
    $firewallObjects = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $null -ne $_ })
}
catch {
    $firewallQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Get-NetFirewallProfile: ' + $_.Exception.Message)
}
$firewallByName = @{}
foreach ($profile in $firewallObjects) {
    $firewallByName[[string]$profile.Name] = $profile
}
$firewallItems = @()
foreach ($profileName in @('Domain', 'Private', 'Public')) {
    $profile = if ($firewallByName.ContainsKey($profileName)) { $firewallByName[$profileName] } else { $null }
    if ($firewallQueryFailed) {
        $profileStatus = 'Unavailable'
    }
    elseif ($profile) {
        $profileStatus = 'Available'
    }
    else {
        $profileStatus = 'Missing'
        Add-CollectionIssue ('Missing: firewall profile ' + $profileName + '.')
    }
    $firewallItems += [pscustomobject][ordered]@{
        ProfileName = $profileName
        Status = $profileStatus
        Enabled = if ($profile) { $profile.Enabled } else { $null }
        DefaultInboundAction = if ($profile) { [string]$profile.DefaultInboundAction } else { $null }
        DefaultOutboundAction = if ($profile) { [string]$profile.DefaultOutboundAction } else { $null }
    }
}
$firewallResult = [ordered]@{
    Status = if ($firewallQueryFailed) { 'Unavailable' } elseif (@($firewallItems | Where-Object { $_.Status -eq 'Missing' }).Count -gt 0) { 'Partial' } else { 'Success' }
    Count = if ($firewallQueryFailed) { $null } else { $firewallItems.Count }
    Items = @($firewallItems)
    Error = if ($firewallQueryFailed) { 'Firewall profile collection failed.' } else { $null }
}

if ($hostname) {
    $hostFolder = $hostname -replace '[\\/:*?"<>|]', '_'
}
else {
    $hostFolder = 'UnknownHost'
}
$scriptDirectory = $PSScriptRoot
$repositoryDirectory = Split-Path -Parent $scriptDirectory
# Repository markers distinguish the standard layout from a copied standalone script.
$isRepositoryLayout = (
    (Split-Path -Leaf $scriptDirectory) -eq 'Inventory' -and
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-NetworkInventory'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
    }
    catch {
        Add-OutputIssue ('Temporary-directory fallback failed: ' + $_.Exception.Message)
    }
}

$allListenerItems = @($tcpItems) + @($udpItems)
$listenerCsvRows = @($allListenerItems | ForEach-Object {
    [pscustomobject][ordered]@{
        Protocol = $_.Protocol
        EndpointType = $_.EndpointType
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        ProcessId = $_.ProcessId
        ProcessName = $_.ProcessName
        AssociatedServiceNames = ($_.AssociatedServiceNames -join '; ')
        ServiceAssociation = $_.ServiceAssociation
    }
})
$serviceCsvRows = @($serviceItems | ForEach-Object {
    [pscustomobject][ordered]@{
        ServiceName = $_.ServiceName
        DisplayName = $_.DisplayName
        State = $_.State
        StartupType = $_.StartupType
        ProcessId = $_.ProcessId
        ExecutablePath = $_.ExecutablePath
        ServiceAccount = $_.ServiceAccount
    }
})

$inventory = [ordered]@{
    Version = '0.1'
    CollectedAt = (Get-Date).ToString('o')
    Hostname = $hostname
    Interfaces = $interfaceResult
    InterfaceAddresses = $interfaceAddressResult
    GatewayDns = $gatewayDnsResult
    Routes = $routeResults
    Listeners = [ordered]@{ TCP = $tcpResult; UDP = $udpResult }
    Services = $serviceResult
    FirewallProfiles = $firewallResult
    ServiceAssociationNote = 'Service names are associated by owning process ID only and do not prove port ownership.'
    CollectionIssues = @($CollectionIssues)
    OutputIssues = @($OutputIssues)
    OutputDirectory = $outputDirectory
    ReportSaved = $false
}
$summaryText = Get-NetworkSummary $inventory $CollectionIssues $OutputIssues -Detailed
$jsonText = $inventory | ConvertTo-Json -Depth 10

if ($outputDirectory) {
    try {
        $inventory.ReportSaved = $true
        $summaryText = Get-NetworkSummary $inventory $CollectionIssues $OutputIssues -Detailed
        $jsonText = $inventory | ConvertTo-Json -Depth 10
        Write-NetworkReports $outputDirectory $summaryText $jsonText $listenerCsvRows $serviceCsvRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Requested output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $inventory.ReportSaved = $false
    }
}
if (-not $outputDirectory) {
    try {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-NetworkInventory'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
        $inventory.OutputDirectory = $outputDirectory
        $inventory.OutputIssues = @($OutputIssues)
        $inventory.ReportSaved = $true
        $summaryText = Get-NetworkSummary $inventory $CollectionIssues $OutputIssues -Detailed
        $jsonText = $inventory | ConvertTo-Json -Depth 10
        Write-NetworkReports $outputDirectory $summaryText $jsonText $listenerCsvRows $serviceCsvRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Final output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $inventory.ReportSaved = $false
    }
}

$inventory.OutputDirectory = $outputDirectory
$inventory.OutputIssues = @($OutputIssues)
$inventory.ReportSaved = $outputSaved
Write-Output (Get-NetworkSummary $inventory $CollectionIssues $OutputIssues)
if (-not $outputSaved) {
    exit 1
}
