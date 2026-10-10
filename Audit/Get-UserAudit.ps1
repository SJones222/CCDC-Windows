<#
.SYNOPSIS
    Collects a read-only Windows user and privileged-group audit for CCDC use.
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

function Convert-AuditDate {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetime]) {
        return $Value.ToString('o')
    }
    return [string]$Value
}

function Get-ReviewIndicators {
    param($Account)
    $indicators = @()
    if ($Account.Disabled -eq $true) { $indicators += 'Disabled' }
    if ($Account.PasswordNeverExpires -eq $true) { $indicators += 'PasswordNeverExpires' }
    if ($Account.PasswordRequired -eq $false) { $indicators += 'PasswordNotRequired' }
    return $indicators
}

function Get-SidText {
    param($Sid)
    if ($null -eq $Sid) {
        return $null
    }
    if ($Sid.PSObject.Properties['Value']) {
        return [string]$Sid.Value
    }
    return [string]$Sid
}

function Write-AuditReports {
    param(
        [string]$Directory,
        [string]$Summary,
        [string]$Json,
        [array]$AccountRows,
        [array]$PrivilegedRows
    )
    $paths = @(
        (Join-Path $Directory 'summary.txt')
        (Join-Path $Directory 'users.json')
        (Join-Path $Directory 'accounts.csv')
        (Join-Path $Directory 'privileged-members.csv')
    )
    try {
        Set-Content -LiteralPath $paths[0] -Value $Summary -Encoding UTF8 -ErrorAction Stop
        Set-Content -LiteralPath $paths[1] -Value $Json -Encoding UTF8 -ErrorAction Stop
        if ($AccountRows.Count -gt 0) {
            $AccountRows | Export-Csv -LiteralPath $paths[2] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[2] -Value 'AccountType,Name,Domain,Principal,SID,Enabled,Disabled,PasswordRequired,PasswordNeverExpires,LastLogon,ReviewIndicators' -Encoding UTF8 -ErrorAction Stop
        }
        if ($PrivilegedRows.Count -gt 0) {
            $PrivilegedRows | Export-Csv -LiteralPath $paths[3] -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $paths[3] -Value 'GroupName,GroupSID,MemberName,MemberType,MemberSID,PrincipalSource,ResolutionStatus,DistinguishedName,MembershipStatus' -Encoding UTF8 -ErrorAction Stop
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

function Get-UserAuditSummary {
    param($Audit, [array]$CollectionIssues, [array]$OutputIssues)
    $saved = if ($Audit.ReportSaved) { 'Yes' } else { 'No' }
    $lines = @(
        'Windows CCDC User Audit v0.1'
        '============================'
        ('Hostname: ' + (Format-Value $Audit.Hostname))
        ('Domain: ' + (Format-Value $Audit.Domain))
        ('Domain membership: ' + (Format-Value $Audit.DomainMembership))
        ('Machine role: ' + (Format-Value $Audit.MachineRole))
        ('ActiveDirectory module: ' + (Format-Value $Audit.ActiveDirectoryModuleStatus))
        ('Accounts: ' + $Audit.Users.Status + ' (' + (Format-Value $Audit.Users.Count) + ')')
        ('Privileged groups: ' + $Audit.PrivilegedGroups.Status + ' (' + (Format-Value $Audit.PrivilegedGroups.Count) + ')')
        ('Report saved: ' + $saved)
    )

    if ($Audit.Users.Status -eq 'Unavailable') {
        $lines += 'Account details: unavailable'
    }
    else {
        $accounts = @($Audit.Users.Items)
        $disabled = @($accounts | Where-Object { $_.Disabled -eq $true }).Count
        $neverExpires = @($accounts | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
        $noPasswordRequired = @($accounts | Where-Object { $_.PasswordRequired -eq $false }).Count
        $lines += ''
        $lines += 'Account review indicators:'
        $lines += ('- Disabled accounts: ' + $disabled)
        $lines += ('- Password never expires: ' + $neverExpires)
        $lines += ('- Password not required: ' + $noPasswordRequired)
    }

    $lines += ''
    $lines += 'Privileged group memberships (direct members only):'
    foreach ($group in $Audit.PrivilegedGroups.Items) {
        $lines += ('- ' + $group.GroupName + ': ' + $group.Status)
        if ($group.Status -eq 'Available' -and @($group.DirectMembers).Count -gt 0) {
            foreach ($member in $group.DirectMembers) {
                $lines += ('  - ' + (Format-Value $member.MemberName) +
                    ' [' + (Format-Value $member.MemberType) + ']')
            }
        }
        elseif ($group.Status -eq 'Available') {
            $lines += '  - none'
        }
    }
    $lines += 'Nested membership is not resolved; direct group membership is reported only.'

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
    $lines += ('Output directory: ' + (Format-Value $Audit.OutputDirectory))
    return ($lines -join [Environment]::NewLine)
}

$hostname = $env:COMPUTERNAME
$computerSystem = $null
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
}
catch {
    Add-CollectionIssue ('Collection failure: Win32_ComputerSystem: ' + $_.Exception.Message)
}

$domain = $null
$domainRoleCode = $null
$machineRole = $null
$isDomainController = $false
if ($computerSystem) {
    $domain = [string]$computerSystem.Domain
    if ($null -ne $computerSystem.DomainRole) {
        $domainRoleCode = [int]$computerSystem.DomainRole
        switch ($domainRoleCode) {
            0 { $machineRole = 'Standalone workstation' }
            1 { $machineRole = 'Member workstation' }
            2 { $machineRole = 'Standalone server' }
            3 { $machineRole = 'Member server' }
            4 { $machineRole = 'Backup domain controller'; $isDomainController = $true }
            5 { $machineRole = 'Primary domain controller'; $isDomainController = $true }
            default { $machineRole = 'Unknown role (' + $domainRoleCode + ')' }
        }
    }
    else {
        Add-CollectionIssue 'Missing: machine domain role.'
    }
}
else {
    $machineRole = 'Unavailable'
}

$userItems = @()
$usersStatus = 'Unavailable'
$usersError = $null
$privilegedGroups = @()
$privilegedStatus = 'Unavailable'
$privilegedError = $null
$adModuleStatus = if ($isDomainController) { 'Unavailable' } else { 'Not required' }

$knownNonDomainRole = $domainRoleCode -in @(0, 1, 2, 3)
if ($knownNonDomainRole) {
    $localUserQueryFailed = $false
    $localUsers = @()
    try {
        $localUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE" -ErrorAction Stop | Where-Object { $null -ne $_ })
    }
    catch {
        $localUserQueryFailed = $true
        $usersError = 'Local user collection failed.'
        Add-CollectionIssue ('Collection failure: Win32_UserAccount local accounts: ' + $_.Exception.Message)
    }

    $localDetailsBySid = @{}
    $localDetailStatus = 'Unavailable'
    $localUserCommand = Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue
    if ($localUserCommand) {
        try {
            foreach ($detail in @(Get-LocalUser -ErrorAction Stop)) {
                $detailSid = Get-SidText $detail.SID
                if ($detailSid) { $localDetailsBySid[$detailSid] = $detail }
            }
            $localDetailStatus = 'Success'
        }
        catch {
            $localDetailStatus = 'Partial'
            Add-CollectionIssue ('Collection failure: Get-LocalUser enrichment: ' + $_.Exception.Message)
        }
    }
    else {
        $localDetailStatus = 'Partial'
        Add-CollectionIssue 'Get-LocalUser is unavailable; local last-logon enrichment is unavailable.'
    }

    foreach ($user in $localUsers) {
        $sid = [string]$user.SID
        $detail = if ($sid -and $localDetailsBySid.ContainsKey($sid)) { $localDetailsBySid[$sid] } else { $null }
        $disabled = if ($detail -and $null -ne $detail.Enabled) { -not [bool]$detail.Enabled } elseif ($null -ne $user.Disabled) { [bool]$user.Disabled } else { $null }
        $passwordRequired = if ($detail -and $null -ne $detail.PasswordRequired) { [bool]$detail.PasswordRequired } elseif ($null -ne $user.PasswordRequired) { [bool]$user.PasswordRequired } else { $null }
        $passwordNeverExpires = if ($detail -and $null -ne $detail.PasswordNeverExpires) { [bool]$detail.PasswordNeverExpires } elseif ($null -ne $user.PasswordExpires) { -not [bool]$user.PasswordExpires } else { $null }
        $lastLogon = if ($detail) { Convert-AuditDate $detail.LastLogon } elseif ($user.PSObject.Properties['LastLogon']) { Convert-AuditDate $user.LastLogon } else { $null }
        $account = [pscustomobject][ordered]@{
            AccountType = 'Local'
            Name = [string]$user.Name
            Domain = [string]$user.Domain
            Principal = ([string]$user.Domain + '\' + [string]$user.Name)
            SID = $sid
            Enabled = if ($null -eq $disabled) { $null } else { -not $disabled }
            Disabled = $disabled
            PasswordRequired = $passwordRequired
            PasswordNeverExpires = $passwordNeverExpires
            LastLogon = $lastLogon
            ReviewIndicators = @()
        }
        $account.ReviewIndicators = @(Get-ReviewIndicators $account)
        $userItems += $account
    }
    if ($localUserQueryFailed) {
        $usersStatus = 'Unavailable'
    }
    elseif ($userItems.Count -eq 0) {
        $usersStatus = 'Empty'
    }
    elseif ($localDetailStatus -eq 'Partial') {
        $usersStatus = 'Partial'
    }
    else {
        $usersStatus = 'Success'
    }

    $localAdminGroup = [ordered]@{
        GroupName = 'BUILTIN\Administrators'
        GroupSID = 'S-1-5-32-544'
        ResolvedGroupName = $null
        Status = 'Unavailable'
        DirectMembers = @()
        NestedMembershipResolved = $false
        NestedMembershipNote = 'Nested membership is not resolved.'
        Error = $null
    }
    $localGroupCommand = Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue
    $localGroupMemberCommand = Get-Command -Name Get-LocalGroupMember -ErrorAction SilentlyContinue
    if ($localGroupCommand -and $localGroupMemberCommand) {
        try {
            $localAdminGroupInfo = @(Get-CimInstance -ClassName Win32_Group -Filter "SID = 'S-1-5-32-544'" -ErrorAction Stop | Select-Object -First 1)
            if ($localAdminGroupInfo.Count -eq 0) {
                throw 'The local Administrators group could not be resolved by SID.'
            }
            $localAdminGroup.ResolvedGroupName = [string]$localAdminGroupInfo[0].Name
            $members = @(Get-LocalGroupMember -Group $localAdminGroup.ResolvedGroupName -ErrorAction Stop)
            foreach ($member in $members) {
                $memberSid = Get-SidText $member.SID
                $memberName = [string]$member.Name
                $resolution = if ($memberSid -and $memberName -and $memberName -notmatch '^S-1-') { 'Resolved' } else { 'Unresolved' }
                $localAdminGroup.DirectMembers += [pscustomobject][ordered]@{
                    MemberName = $memberName
                    MemberType = [string]$member.ObjectClass
                    MemberSID = $memberSid
                    PrincipalSource = [string]$member.PrincipalSource
                    ResolutionStatus = $resolution
                }
            }
            $localAdminGroup.Status = 'Available'
        }
        catch {
            $localAdminGroup.Error = $_.Exception.Message
            Add-CollectionIssue ('Collection failure: local Administrators membership: ' + $_.Exception.Message)
        }
    }
    else {
        $localAdminGroup.Error = 'Local group lookup commands are unavailable.'
        Add-CollectionIssue 'Get-LocalGroup or Get-LocalGroupMember is unavailable; local Administrators membership is unavailable.'
    }
    $privilegedGroups = @([pscustomobject]$localAdminGroup)
    $privilegedStatus = if ($localAdminGroup.Status -eq 'Available') { 'Success' } else { 'Unavailable' }
}
elseif ($isDomainController) {
    $adModuleAvailable = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
    if ($adModuleAvailable) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adModuleStatus = 'Available'
        }
        catch {
            $adModuleStatus = 'Unavailable'
            Add-CollectionIssue ('Collection failure: ActiveDirectory module import: ' + $_.Exception.Message)
        }
    }
    else {
        Add-CollectionIssue 'ActiveDirectory module is unavailable on this domain controller.'
    }

    if ($adModuleStatus -eq 'Available') {
        $adDomain = $null
        try {
            $adDomain = Get-ADDomain -ErrorAction Stop
        }
        catch {
            Add-CollectionIssue ('Collection failure: Get-ADDomain: ' + $_.Exception.Message)
        }

        $domainSid = if ($adDomain -and $adDomain.DomainSID) { [string]$adDomain.DomainSID.Value } else { $null }
        $forestRootDomainSid = $null
        $forestRootError = $null
        try {
            $adForest = Get-ADForest -ErrorAction Stop
            if (-not $adForest.RootDomain) {
                throw 'The forest root domain name was not returned.'
            }
            $forestRootDomain = Get-ADDomain -Identity $adForest.RootDomain -ErrorAction Stop
            if (-not $forestRootDomain.DomainSID) {
                throw 'The forest root domain SID was not returned.'
            }
            $forestRootDomainSid = [string]$forestRootDomain.DomainSID.Value
        }
        catch {
            $forestRootError = $_.Exception.Message
            Add-CollectionIssue ('Collection failure: forest root domain discovery: ' + $forestRootError)
        }
        $groupDefinitions = @(
            [pscustomobject]@{ Label = 'Domain Admins'; SID = if ($domainSid) { $domainSid + '-512' } else { $null }; UnavailableReason = 'Domain SID is unavailable.' }
            [pscustomobject]@{ Label = 'Enterprise Admins'; SID = if ($forestRootDomainSid) { $forestRootDomainSid + '-519' } else { $null }; UnavailableReason = if ($forestRootError) { 'Forest root domain SID is unavailable: ' + $forestRootError } else { 'Forest root domain SID is unavailable.' } }
            [pscustomobject]@{ Label = 'BUILTIN\Administrators'; SID = 'S-1-5-32-544'; UnavailableReason = $null }
            [pscustomobject]@{ Label = 'Account Operators'; SID = 'S-1-5-32-548'; UnavailableReason = $null }
            [pscustomobject]@{ Label = 'Server Operators'; SID = 'S-1-5-32-549'; UnavailableReason = $null }
            [pscustomobject]@{ Label = 'Backup Operators'; SID = 'S-1-5-32-551'; UnavailableReason = $null }
        )
        foreach ($definition in $groupDefinitions) {
            $groupAudit = [ordered]@{
                GroupName = $definition.Label
                GroupSID = $definition.SID
                ResolvedGroupName = $null
                Status = 'Unavailable'
                DirectMembers = @()
                NestedMembershipResolved = $false
                NestedMembershipNote = 'Nested membership is not resolved.'
                Error = $null
            }
            if (-not $definition.SID) {
                $groupAudit.Error = $definition.UnavailableReason
                Add-CollectionIssue ('Collection unavailable: ' + $definition.Label + ': ' + $definition.UnavailableReason)
                $privilegedGroups += [pscustomobject]$groupAudit
                continue
            }
            try {
                $adGroup = Get-ADGroup -Identity $definition.SID -Properties objectSid -ErrorAction Stop
                $groupAudit.ResolvedGroupName = [string]$adGroup.Name
                $groupAudit.GroupSID = Get-SidText $adGroup.SID
                $groupMembers = @(Get-ADGroupMember -Identity $adGroup.DistinguishedName -ErrorAction Stop)
                foreach ($member in $groupMembers) {
                    $memberSid = Get-SidText $member.SID
                    $memberName = [string]$member.Name
                    $groupAudit.DirectMembers += [pscustomobject][ordered]@{
                        MemberName = $memberName
                        MemberType = [string]$member.objectClass
                        MemberSID = $memberSid
                        PrincipalSource = 'ActiveDirectory'
                        ResolutionStatus = if ($memberSid -and $memberName) { 'Resolved' } else { 'Unresolved' }
                        DistinguishedName = [string]$member.DistinguishedName
                    }
                }
                $groupAudit.Status = 'Available'
            }
            catch {
                $groupAudit.Error = $_.Exception.Message
                Add-CollectionIssue ('Collection failure: privileged group ' + $definition.Label + ': ' + $_.Exception.Message)
            }
            $privilegedGroups += [pscustomobject]$groupAudit
        }
        $groupUnavailable = @($privilegedGroups | Where-Object { $_.Status -eq 'Unavailable' }).Count
        $privilegedStatus = if ($groupUnavailable -eq $privilegedGroups.Count) { 'Unavailable' } elseif ($groupUnavailable -gt 0) { 'Partial' } else { 'Success' }

        $domainUserQueryFailed = $false
        try {
            $domainUsers = @(Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,objectSid,UserPrincipalName -ResultSetSize $null -ErrorAction Stop)
            foreach ($user in $domainUsers) {
                $disabled = if ($null -eq $user.Enabled) { $null } else { -not [bool]$user.Enabled }
                $passwordNeverExpires = if ($null -eq $user.PasswordNeverExpires) { $null } else { [bool]$user.PasswordNeverExpires }
                $passwordRequired = if ($null -eq $user.PasswordNotRequired) { $null } else { -not [bool]$user.PasswordNotRequired }
                $account = [pscustomobject][ordered]@{
                    AccountType = 'Domain'
                    Name = [string]$user.SamAccountName
                    Domain = [string]$adDomain.NetBIOSName
                    Principal = if ($user.UserPrincipalName) { [string]$user.UserPrincipalName } else { [string]$user.SamAccountName }
                    SID = Get-SidText $user.SID
                    Enabled = if ($null -eq $disabled) { $null } else { -not $disabled }
                    Disabled = $disabled
                    PasswordRequired = $passwordRequired
                    PasswordNeverExpires = $passwordNeverExpires
                    LastLogon = Convert-AuditDate $user.LastLogonDate
                    ReviewIndicators = @()
                }
                $account.ReviewIndicators = @(Get-ReviewIndicators $account)
                $userItems += $account
            }
        }
        catch {
            $domainUserQueryFailed = $true
            $usersError = 'Domain user collection failed.'
            Add-CollectionIssue ('Collection failure: Get-ADUser: ' + $_.Exception.Message)
        }
        if ($domainUserQueryFailed) {
            $usersStatus = 'Unavailable'
        }
        elseif ($userItems.Count -eq 0) {
            $usersStatus = 'Empty'
        }
        else {
            $usersStatus = 'Success'
        }
    }
    else {
        $usersError = 'ActiveDirectory module is unavailable.'
        $privilegedError = 'ActiveDirectory module is unavailable.'
    }
}
else {
    $usersError = 'Machine role is unavailable.'
    $privilegedError = 'Machine role is unavailable.'
    Add-CollectionIssue 'User collection skipped because the machine role could not be determined.'
}

$usersResult = [ordered]@{
    Status = $usersStatus
    Count = if ($usersStatus -eq 'Unavailable') { $null } else { $userItems.Count }
    Items = if ($usersStatus -eq 'Unavailable') { $null } else { @($userItems) }
    Error = $usersError
}
$privilegedResult = [ordered]@{
    Status = $privilegedStatus
    Count = if ($privilegedStatus -eq 'Unavailable') { $null } else { $privilegedGroups.Count }
    Items = if ($privilegedGroups.Count -eq 0) { $null } else { @($privilegedGroups) }
    Error = $privilegedError
}

$accountRows = @($userItems | ForEach-Object {
    [pscustomobject][ordered]@{
        AccountType = $_.AccountType
        Name = $_.Name
        Domain = $_.Domain
        Principal = $_.Principal
        SID = $_.SID
        Enabled = $_.Enabled
        Disabled = $_.Disabled
        PasswordRequired = $_.PasswordRequired
        PasswordNeverExpires = $_.PasswordNeverExpires
        LastLogon = $_.LastLogon
        ReviewIndicators = ($_.ReviewIndicators -join '; ')
    }
})
$privilegedRows = @($privilegedGroups | ForEach-Object {
    $group = $_
    foreach ($member in @($group.DirectMembers)) {
        [pscustomobject][ordered]@{
            GroupName = $group.GroupName
            GroupSID = $group.GroupSID
            MemberName = $member.MemberName
            MemberType = $member.MemberType
            MemberSID = $member.MemberSID
            PrincipalSource = $member.PrincipalSource
            ResolutionStatus = $member.ResolutionStatus
            DistinguishedName = $member.DistinguishedName
            MembershipStatus = $group.Status
        }
    }
})

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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-UserAudit'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
    }
    catch {
        Add-OutputIssue ('Temporary-directory fallback failed: ' + $_.Exception.Message)
    }
}

$audit = [ordered]@{
    Version = '0.1'
    CollectedAt = (Get-Date).ToString('o')
    Hostname = $hostname
    Domain = $domain
    DomainMembership = if ($computerSystem -and $null -ne $computerSystem.PartOfDomain) {
        [bool]$computerSystem.PartOfDomain
    }
    else {
        $null
    }
    MachineRole = $machineRole
    DomainRoleCode = $domainRoleCode
    ActiveDirectoryModuleStatus = $adModuleStatus
    Users = $usersResult
    PrivilegedGroups = $privilegedResult
    NestedMembershipResolved = $false
    NestedMembershipNote = 'Nested membership is not resolved; only direct privileged-group membership is reported.'
    CollectionIssues = @($CollectionIssues)
    OutputIssues = @($OutputIssues)
    OutputDirectory = $outputDirectory
    ReportSaved = $false
}
$summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues
$jsonText = $audit | ConvertTo-Json -Depth 10

if ($outputDirectory) {
    try {
        $audit.ReportSaved = $true
        $summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues
        $jsonText = $audit | ConvertTo-Json -Depth 10
        Write-AuditReports $outputDirectory $summaryText $jsonText $accountRows $privilegedRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Requested output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $audit.ReportSaved = $false
    }
}
if (-not $outputDirectory) {
    try {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-UserAudit'
        $outputDirectory = New-UniqueOutputDirectory $tempRoot $hostFolder
        Add-OutputIssue 'Using temporary-directory fallback for output.'
        $audit.OutputDirectory = $outputDirectory
        $audit.OutputIssues = @($OutputIssues)
        $audit.ReportSaved = $true
        $summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues
        $jsonText = $audit | ConvertTo-Json -Depth 10
        Write-AuditReports $outputDirectory $summaryText $jsonText $accountRows $privilegedRows
        $outputSaved = $true
    }
    catch {
        Add-OutputIssue ('Final output write failed: ' + $_.Exception.Message)
        $outputDirectory = $null
        $audit.ReportSaved = $false
    }
}

$audit.OutputDirectory = $outputDirectory
$audit.OutputIssues = @($OutputIssues)
$audit.ReportSaved = $outputSaved
Write-Output (Get-UserAuditSummary $audit $CollectionIssues $OutputIssues)
if (-not $outputSaved) {
    exit 1
}
