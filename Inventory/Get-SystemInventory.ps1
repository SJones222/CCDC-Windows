<#
.SYNOPSIS
    Collects a small, read-only system inventory for Windows CCDC use.
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
    $stamp = 'SystemInventory_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
    $hostRoot = Join-Path $Root $HostFolder
    $candidate = Join-Path $hostRoot $stamp
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = Join-Path $hostRoot ($stamp + '-' + $suffix)
        $suffix++
    }
    New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop | Out-Null
    $candidate
}

function Format-InventoryValue {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return '<unavailable>'
    }
    return [string]$Value
}

function Write-InventoryFiles {
    param([string]$Directory, [string]$Summary, [string]$Json)
    $summaryPath = Join-Path $Directory 'summary.txt'
    $jsonPath = Join-Path $Directory 'inventory.json'
    try {
        Set-Content -LiteralPath $summaryPath -Value $Summary -Encoding UTF8 -ErrorAction Stop
        Set-Content -LiteralPath $jsonPath -Value $Json -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        foreach ($path in @($summaryPath, $jsonPath)) {
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

function Get-InventorySummary {
    param($Inventory, [array]$CollectionIssues, [array]$OutputIssues, [switch]$Detailed)
    if ($null -eq $Inventory.IsAdministrator) {
        $admin = '<unavailable>'
    }
    elseif ($Inventory.IsAdministrator) {
        $admin = 'Yes'
    }
    else {
        $admin = 'No'
    }
    if ($null -eq $Inventory.IsDomainJoined) {
        $domainJoined = '<unavailable>'
    }
    elseif ($Inventory.IsDomainJoined) {
        $domainJoined = 'Yes'
    }
    else {
        $domainJoined = 'No'
    }
    if ($Inventory.ReportSaved) {
        $reportSaved = 'Yes'
    }
    else {
        $reportSaved = 'No'
    }
    $lines = @(
        'Windows CCDC System Inventory v0.1'
        '================================='
        ('Hostname: ' + (Format-InventoryValue $Inventory.Hostname))
        ('Operating system: ' + (Format-InventoryValue $Inventory.OperatingSystemName))
        ('OS version: ' + (Format-InventoryValue $Inventory.OSVersion))
        ('OS build: ' + (Format-InventoryValue $Inventory.OSBuildNumber))
        ('OS architecture: ' + (Format-InventoryValue $Inventory.OSArchitecture))
        ('Domain/workgroup: ' + (Format-InventoryValue $Inventory.DomainOrWorkgroup))
        ('Domain joined: ' + $domainJoined)
        ('Machine domain role: ' + (Format-InventoryValue $Inventory.MachineDomainRole))
        ('Current username: ' + (Format-InventoryValue $Inventory.CurrentUsername))
        ('Administrator privileges: ' + $admin)
        ('Report saved: ' + $reportSaved)
    )
    if ($Detailed) {
        $lines = @(
            ('Get-SystemInventory.ps1 v' + (Format-InventoryValue $Inventory.Version))
            ('Hostname: ' + (Format-InventoryValue $Inventory.Hostname))
            ('Collected: ' + (Format-InventoryValue $Inventory.CollectedAt))
            ('Report saved: ' + $reportSaved)
            ('Output directory: ' + (Format-InventoryValue $Inventory.OutputDirectory))
            ''
            'AT A GLANCE'
            ('Operating system: ' + (Format-InventoryValue $Inventory.OperatingSystemName))
            ('Domain joined: ' + $domainJoined)
            ('Domain/workgroup: ' + (Format-InventoryValue $Inventory.DomainOrWorkgroup))
            ('Machine domain role: ' + (Format-InventoryValue $Inventory.MachineDomainRole))
            ('Administrator privileges: ' + $admin)
            ''
            'SYSTEM DETAILS'
            ('OS version: ' + (Format-InventoryValue $Inventory.OSVersion))
            ('OS build: ' + (Format-InventoryValue $Inventory.OSBuildNumber))
            ('OS architecture: ' + (Format-InventoryValue $Inventory.OSArchitecture))
            ('Domain role value: ' + (Format-InventoryValue $Inventory.DomainRoleValue))
            ('Current username: ' + (Format-InventoryValue $Inventory.CurrentUsername))
            ''
            'COLLECTION NOTES AND LIMITATIONS'
            'Values shown as <unavailable> were missing or could not be collected; they are not confirmed empty results.'
        )
        if ($CollectionIssues.Count -eq 0) {
            $lines += 'No collection issues reported.'
        }
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
    if ($Detailed) {
        $lines += 'REPORT FILE REFERENCES'
        $lines += 'summary.txt: complete human-readable system report.'
        $lines += 'inventory.json: structured system information, collection/output issues, and report metadata.'
    }
    else {
        $lines += ('Output directory: ' + (Format-InventoryValue $Inventory.OutputDirectory))
    }
    $lines -join [Environment]::NewLine
}

$computerSystem = $null
$operatingSystem = $null
$computerSystemQueryFailed = $false
$operatingSystemQueryFailed = $false
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
}
catch {
    $computerSystemQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Win32_ComputerSystem: ' + $_.Exception.Message)
}
try {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
}
catch {
    $operatingSystemQueryFailed = $true
    Add-CollectionIssue ('Collection failure: Win32_OperatingSystem: ' + $_.Exception.Message)
}
if (-not $computerSystem -and -not $computerSystemQueryFailed) {
    Add-CollectionIssue 'Collection failure: Win32_ComputerSystem returned no data.'
}
if (-not $operatingSystem -and -not $operatingSystemQueryFailed) {
    Add-CollectionIssue 'Collection failure: Win32_OperatingSystem returned no data.'
}

$hostname = $null
$osName = $null
$osVersion = $null
$buildNumber = $null
$architecture = $null
$domainOrWorkgroup = $null
$isDomainJoined = $null
$domainRole = $null
$domainRoleValue = $null
if ($computerSystem) {
    if ($computerSystem.Name) {
        $hostname = [string]$computerSystem.Name
    }
    else {
        Add-CollectionIssue 'Missing: hostname.'
    }
    if ($computerSystem.Domain) {
        $domainOrWorkgroup = [string]$computerSystem.Domain
    }
    else {
        Add-CollectionIssue 'Missing: domain or workgroup membership.'
    }
    if ($null -ne $computerSystem.PartOfDomain) {
        $isDomainJoined = [bool]$computerSystem.PartOfDomain
    }
    else {
        Add-CollectionIssue 'Missing: domain membership indicator.'
    }
    if ($null -ne $computerSystem.DomainRole) {
        $domainRoleValue = [int]$computerSystem.DomainRole
        switch ($domainRoleValue) {
            0 { $domainRole = 'Standalone workstation' }
            1 { $domainRole = 'Member workstation' }
            2 { $domainRole = 'Standalone server' }
            3 { $domainRole = 'Member server' }
            4 { $domainRole = 'Domain controller' }
            5 { $domainRole = 'Domain controller' }
            default { Add-CollectionIssue 'Missing: unrecognized machine domain role.' }
        }
    }
    else {
        Add-CollectionIssue 'Missing: machine domain role.'
    }
}
if ($operatingSystem) {
    if ($operatingSystem.Caption) {
        $osName = [string]$operatingSystem.Caption
    }
    else {
        Add-CollectionIssue 'Missing: operating system name.'
    }
    if ($operatingSystem.Version) {
        $osVersion = [string]$operatingSystem.Version
    }
    else {
        Add-CollectionIssue 'Missing: operating system version.'
    }
    if ($operatingSystem.BuildNumber) {
        $buildNumber = [string]$operatingSystem.BuildNumber
    }
    else {
        Add-CollectionIssue 'Missing: operating system build number.'
    }
    if ($operatingSystem.OSArchitecture) {
        $architecture = [string]$operatingSystem.OSArchitecture
    }
    else {
        Add-CollectionIssue 'Missing: operating system architecture.'
    }
}

$username = $null
try {
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-not $username) {
        Add-CollectionIssue 'Missing: current executing username.'
    }
}
catch {
    Add-CollectionIssue ('Collection failure: current executing username: ' + $_.Exception.Message)
}
$isAdministrator = $null
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    Add-CollectionIssue ('Collection failure: administrator privilege check: ' + $_.Exception.Message)
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-SystemInventory'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
    }
    catch {
        Add-OutputIssue ('Temporary-directory fallback failed: ' + $_.Exception.Message)
    }
}

$inventory = [ordered]@{
    Version = '0.1'
    CollectedAt = (Get-Date).ToString('o')
    Hostname = $hostname
    OperatingSystemName = $osName
    OSVersion = $osVersion
    OSBuildNumber = $buildNumber
    OSArchitecture = $architecture
    DomainOrWorkgroup = $domainOrWorkgroup
    IsDomainJoined = $isDomainJoined
    MachineDomainRole = $domainRole
    DomainRoleValue = $domainRoleValue
    CurrentUsername = $username
    IsAdministrator = $isAdministrator
    CollectionIssues = @($CollectionIssues)
    OutputIssues = @($OutputIssues)
    OutputDirectory = $outputDirectory
    ReportSaved = $false
}
$summaryText = Get-InventorySummary $inventory $CollectionIssues $OutputIssues -Detailed
$jsonText = $inventory | ConvertTo-Json -Depth 5

if ($outputDirectory) {
    try {
        $inventory.ReportSaved = $true
        $summaryText = Get-InventorySummary $inventory $CollectionIssues $OutputIssues -Detailed
        $jsonText = $inventory | ConvertTo-Json -Depth 5
        Write-InventoryFiles $outputDirectory $summaryText $jsonText
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-SystemInventory'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
        $inventory.OutputDirectory = $outputDirectory
        $inventory.OutputIssues = @($OutputIssues)
        $inventory.ReportSaved = $true
        $summaryText = Get-InventorySummary $inventory $CollectionIssues $OutputIssues -Detailed
        $jsonText = $inventory | ConvertTo-Json -Depth 5
        Write-InventoryFiles $outputDirectory $summaryText $jsonText
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
Write-Output (Get-InventorySummary $inventory $CollectionIssues $OutputIssues)
if (-not $outputSaved) {
    exit 1
}
