#requires -Version 5.1
<#
.SYNOPSIS
    Installs the reviewed CCDC-Windows repository into a new directory.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[A-Za-z]:[\\/]')]
    [ValidateScript({
        if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($_)) {
            throw 'Destination must not contain PowerShell wildcard characters.'
        }
        $true
    })]
    [string]$Destination = 'C:\CCDC',

    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]*$')]
    [ValidateScript({
        if ($_ -match '\.\.|//|(^|/)\.|[./]$|\.lock(/|$)') {
            throw 'Ref must be a valid branch name, such as main or deployment-test.'
        }
        $true
    })]
    [string]$Ref = 'main'
)

$repository = 'SJones222/CCDC-Windows'
$archiveUrl = 'https://github.com/' + $repository + '/archive/refs/heads/' + [uri]::EscapeDataString($Ref) + '.zip'
$requiredFiles = @(
    'Inventory\Get-SystemInventory.ps1'
    'Inventory\Get-NetworkInventory.ps1'
    'Audit\Get-UserAudit.ps1'
    'Audit\Get-PersistenceAudit.ps1'
    'Audit\Get-SecurityEventTriage.ps1'
    'Firewall\fireme-v2.0.ps1'
    'Passwords\pcr.ps1'
    'Passwords\pcra.ps1'
    'Passwords\restore_passwords.ps1'
    'SSH\WIN_SSH.ps1'
    'README.md'
    'AGENTS.md'
    'Install-CCDC.ps1'
)
$rootCopies = [ordered]@{
    'network.ps1' = 'Inventory\Get-NetworkInventory.ps1'
    'system.ps1' = 'Inventory\Get-SystemInventory.ps1'
    'users.ps1' = 'Audit\Get-UserAudit.ps1'
    'persistence.ps1' = 'Audit\Get-PersistenceAudit.ps1'
    'events.ps1' = 'Audit\Get-SecurityEventTriage.ps1'
    'dc-firewalls-barebones-v3.0.ps1' = 'Firewall\dc-firewalls-barebones-v3.0.ps1'
    'pcr.ps1' = 'Passwords\pcr.ps1'
    'pcra.ps1' = 'Passwords\pcra.ps1'
    'restore_passwords.ps1' = 'Passwords\restore_passwords.ps1'
    'WIN_SSH.ps1' = 'SSH\WIN_SSH.ps1'
}
$temporaryDirectory = $null
$pendingDirectory = $null
$previousTls = [Net.ServicePointManager]::SecurityProtocol
$step = 'destination validation'

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Run this installer in Windows PowerShell 5.1 on Windows.'
    }
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    if (Test-Path -LiteralPath $destinationPath -ErrorAction Stop) {
        throw ('Destination already exists: ' + $destinationPath + '. Nothing was changed. Choose a new directory with -Destination, for example C:\CCDC-InstallTest.')
    }
    $destinationPath = $destinationPath.TrimEnd([char[]]@('\', '/'))
    $parentDirectory = Split-Path -Parent $destinationPath
    if (-not (Test-Path -LiteralPath $parentDirectory -PathType Container -ErrorAction Stop)) {
        throw ('Destination parent directory does not exist: ' + $parentDirectory + '. Create the parent first or choose a directory under an existing parent.')
    }

    $step = 'temporary staging creation'
    $temporaryPath = Join-Path ([IO.Path]::GetTempPath()) ('CCDC-install-' + [guid]::NewGuid().ToString('N'))
    # Record cleanup paths only after this invocation successfully creates them.
    $temporaryDirectory = (New-Item -ItemType Directory -Path $temporaryPath -ErrorAction Stop).FullName
    $zipPath = Join-Path $temporaryDirectory 'repository.zip'
    $extractPath = Join-Path $temporaryDirectory 'extracted'

    $step = 'GitHub download (check network access, repository visibility, and -Ref)'
    [Net.ServicePointManager]::SecurityProtocol = $previousTls -bor [Net.SecurityProtocolType]::Tls12
    Write-Output ('Downloading ' + $repository + ' branch ' + $Ref + '...')
    Invoke-WebRequest -Uri $archiveUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop

    $step = 'ZIP extraction'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractPath -ErrorAction Stop
    $roots = @(Get-ChildItem -LiteralPath $extractPath -Force -ErrorAction Stop)
    if ($roots.Count -ne 1 -or -not $roots[0].PSIsContainer) {
        throw 'The archive does not contain a single repository directory.'
    }
    $repositoryRoot = $roots[0].FullName

    $step = 'repository validation'
    foreach ($relativePath in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $relativePath) -PathType Leaf -ErrorAction Stop)) {
            throw ('Required repository file is missing: ' + $relativePath)
        }
    }

    $step = 'destination staging (check permissions and free space)'
    # A sibling directory permits a same-volume rename, even when TEMP is on another drive.
    $pendingPath = Join-Path $parentDirectory ('.CCDC-stage-' + [guid]::NewGuid().ToString('N'))
    $pendingDirectory = (New-Item -ItemType Directory -Path $pendingPath -ErrorAction Stop).FullName
    foreach ($entry in @(Get-ChildItem -LiteralPath $repositoryRoot -Force -ErrorAction Stop)) {
        Copy-Item -LiteralPath $entry.FullName -Destination $pendingDirectory -Recurse -Force -ErrorAction Stop
    }
    # Git archives omit empty, untracked directories; retain the documented toolkit layout.
    foreach ($directory in @('Remediation', 'Tests', 'Output')) {
        New-Item -ItemType Directory -Path (Join-Path $pendingDirectory $directory) -Force -ErrorAction Stop | Out-Null
    }

    $step = 'root-level standalone script copies'
    foreach ($name in $rootCopies.Keys) {
        [IO.File]::Copy((Join-Path $pendingDirectory $rootCopies[$name]), (Join-Path $pendingDirectory $name), $false)
    }

    $step = 'installation promotion'
    if (Test-Path -LiteralPath $destinationPath -ErrorAction Stop) {
        throw ('Destination already exists: ' + $destinationPath + '. Choose a different -Destination; existing contents were not changed.')
    }
    # Directory.Move refuses an existing destination, including one created after the check.
    # Never copy into, merge with, or clean up the destination itself.
    [IO.Directory]::Move($pendingDirectory, $destinationPath)
    $pendingDirectory = $null
}
catch {
    throw ('CCDC installation failed during ' + $step + ': ' + $_.Exception.Message)
}
finally {
    [Net.ServicePointManager]::SecurityProtocol = $previousTls
    foreach ($cleanupPath in @($pendingDirectory, $temporaryDirectory)) {
        if ($cleanupPath) {
            try {
                Remove-Item -LiteralPath $cleanupPath -Recurse -Force -ErrorAction Stop
            }
            catch {
                Write-Warning ('Could not remove installer staging directory ' + $cleanupPath + ': ' + $_.Exception.Message)
            }
        }
    }
}

Write-Output 'Installation completed.'
Write-Output ('Destination: ' + $destinationPath)
Write-Output ('Source: https://github.com/' + $repository + '; branch: ' + $Ref)
Write-Output 'No audit or remediation scripts were executed. No Windows security settings were changed.'
Write-Output ''
Write-Output 'Installed standalone copies and preserved originals:'
foreach ($name in $rootCopies.Keys) {
    Write-Output ('- ' + (Join-Path $destinationPath $name))
    Write-Output ('  Original: ' + (Join-Path $destinationPath $rootCopies[$name]))
}
Write-Output ''
Write-Output 'Run from Windows PowerShell:'
Write-Output ("Set-Location -LiteralPath '" + $destinationPath.Replace("'", "''") + "'")
Write-Output '.\network.ps1'
Write-Output '.\system.ps1'
Write-Output '.\users.ps1'
Write-Output '.\persistence.ps1'
Write-Output '.\events.ps1'
Write-Output '.\events.ps1 -Deep'
