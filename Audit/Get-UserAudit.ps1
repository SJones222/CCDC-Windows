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
    $stamp = 'UserAudit_' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
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
    param($Audit, [array]$CollectionIssues, [array]$OutputIssues, [switch]$Detailed)
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

    if ($Detailed) {
        $scope = if ($Audit.DomainRoleCode -in @(4, 5)) { 'Domain accounts (domain controller)' }
            elseif ($Audit.DomainRoleCode -in @(0, 1, 2, 3)) { 'Local accounts (workstation/member or standalone server)' }
            else { '<unavailable: machine role not determined>' }
        $members = @($Audit.PrivilegedGroups.Items | ForEach-Object { $_.DirectMembers })
        $membershipCount = if ($Audit.PrivilegedGroups.Status -eq 'Unavailable' -and $members.Count -eq 0) { '<unavailable>' } else { [string]$members.Count }
        $reviewAccounts = @($Audit.Users.Items | Where-Object { $_.ReviewIndicators.Count -gt 0 } | Sort-Object Principal, SID)
        $indicatorCount = 0
        foreach ($account in $reviewAccounts) {
            $indicatorCount += $account.ReviewIndicators.Count
        }
        $reviewOverview = if ($Audit.Users.Status -eq 'Unavailable') { '<unavailable>' }
            else { $reviewAccounts.Count.ToString() + ' accounts; ' + $indicatorCount + ' indicator occurrences' }
        $accountsAvailable = $Audit.Users.Status -in @('Success', 'Partial', 'Empty')
        $auditedAccounts = @($Audit.Users.Items | Where-Object { $null -ne $_ })
        $enabledAccounts = @($auditedAccounts | Where-Object { $_.Enabled -eq $true } | Sort-Object Name, Principal, SID)
        $statusCounts = 'Total audited accounts: <unavailable>; enabled: <unavailable>; disabled: <unavailable>; unknown enabled status: <unavailable>'
        if ($accountsAvailable) {
            $disabledCount = @($auditedAccounts | Where-Object { $_.Enabled -eq $false }).Count
            $unknownCount = $auditedAccounts.Count - $enabledAccounts.Count - $disabledCount
            $statusCounts = 'Total audited accounts: ' + $auditedAccounts.Count + '; enabled: ' + $enabledAccounts.Count + '; disabled: ' + $disabledCount
            if ($unknownCount -gt 0) { $statusCounts += '; unknown enabled status: ' + $unknownCount }
        }
        $lines = @(
            'REPORT HEADER'
            ('Get-UserAudit.ps1 v' + (Format-Value $Audit.Version))
            ('Report saved: ' + $saved)
            ''
            'AT A GLANCE'
            ('Hostname: ' + (Format-Value $Audit.Hostname) + '; collected: ' + (Format-Value $Audit.CollectedAt))
            ('Domain: ' + (Format-Value $Audit.Domain) + '; domain membership: ' + (Format-Value $Audit.DomainMembership))
            ('Machine role: ' + (Format-Value $Audit.MachineRole))
            ('Account scope: ' + $scope)
            ('Accounts: ' + $Audit.Users.Status + ' (' + (Format-Value $Audit.Users.Count) + ')')
            $statusCounts
            ('Privileged groups: ' + $Audit.PrivilegedGroups.Status + ' (' + (Format-Value $Audit.PrivilegedGroups.Count) + ')')
            ('Collected direct membership entries: ' + $membershipCount + ' (not unique accounts; group status applies)')
            ('Existing review indicators: ' + $reviewOverview)
            ('Collection issues reported: ' + $CollectionIssues.Count + '; see COLLECTION NOTES AND LIMITATIONS')
            ('Output directory: ' + (Format-Value $Audit.OutputDirectory))
            ''
            'ENABLED ACCOUNTS'
            'Enabled=True does not guarantee logon access to a particular machine.'
        )
        if (-not $accountsAvailable) {
            $lines += 'Unavailable: enabled accounts could not be determined.'
        }
        elseif ($enabledAccounts.Count -eq 0) {
            $lines += $(if ($Audit.Users.Status -eq 'Partial') { 'No enabled accounts in the collected partial results.' } else { 'No enabled accounts returned by the successful collection.' })
        }
        else {
            foreach ($account in $enabledAccounts) {
                $lines += ('- ' + (Format-Value $account.Name) + '; principal: ' + (Format-Value $account.Principal))
            }
        }
        $lines += @(
            ''
            'ACCOUNTS TO REVIEW'
            'Existing indicators are review prompts; they do not establish malicious activity.'
        )
        if ($Audit.Users.Status -eq 'Unavailable') {
            $lines += 'Unavailable: account collection failed or could not run.'
        }
        elseif ($reviewAccounts.Count -eq 0) {
            $lines += 'No collected accounts have existing review indicators.'
        }
        $firstReviewAccount = $true
        foreach ($account in $reviewAccounts) {
            if (-not $firstReviewAccount) { $lines += '' }
            $firstReviewAccount = $false
            $lines += ('- ' + (Format-Value $account.Principal) + '; SID: ' + (Format-Value $account.SID))
            $lines += ('  Indicators: ' + ($account.ReviewIndicators -join '; '))
        }
    }

    $lines += ''
    $lines += $(if ($Detailed) { 'PRIVILEGED GROUP MEMBERSHIP' } else { 'Privileged groups (direct membership counts; full details in summary.txt):' })
    if ($Detailed) {
        $lines += ('Collection status: ' + $Audit.PrivilegedGroups.Status)
        if ($Audit.PrivilegedGroups.Error) { $lines += 'Error: ' + $Audit.PrivilegedGroups.Error }
    }
    $firstGroup = $true
    foreach ($group in $Audit.PrivilegedGroups.Items) {
        if ($Detailed -and -not $firstGroup) { $lines += '' }
        $firstGroup = $false
        $lines += ('- ' + $group.GroupName + ': ' + $group.Status)
        if ($Detailed) {
            $lines += ('  Group SID: ' + (Format-Value $group.GroupSID) + '; resolved name: ' + (Format-Value $group.ResolvedGroupName))
            if ($group.Error) { $lines += '  Error: ' + $group.Error }
        }
        if (@($group.DirectMembers).Count -gt 0) {
            if ($Detailed) {
                $firstMember = $true
                foreach ($member in $group.DirectMembers) {
                    if (-not $firstMember) { $lines += '' }
                    $firstMember = $false
                    $lines += ('  - ' + (Format-Value $member.MemberName) + ' [' + (Format-Value $member.MemberType) + ']')
                    $lines += ('    SID: ' + (Format-Value $member.MemberSID))
                    $lines += ('    Source: ' + (Format-Value $member.PrincipalSource) + '; resolution: ' + (Format-Value $member.ResolutionStatus))
                    if ($member.DistinguishedName) { $lines += '    DN: ' + $member.DistinguishedName }
                }
            }
            else {
                $lines += ('  Direct members: ' + @($group.DirectMembers).Count)
            }
        }
        elseif ($group.Status -eq 'Available') {
            $lines += '  - none'
        }
    }
    $lines += 'Nested membership is not resolved; direct group membership is reported only.'

    if ($Detailed) {
        $lines += ''
        $lines += 'ALL AUDITED ACCOUNTS'
        $lines += ('Collection status: ' + $Audit.Users.Status + '; count: ' + (Format-Value $Audit.Users.Count))
        if ($Audit.Users.Error) { $lines += 'Error: ' + $Audit.Users.Error }
        if ($Audit.Users.Status -eq 'Empty') { $lines += 'No accounts returned by the successful query.' }
        foreach ($account in @($Audit.Users.Items | Sort-Object Principal, SID)) {
            $lines += ''
            $lines += ('- ' + (Format-Value $account.Name) + ' [' + (Format-Value $account.AccountType) + ']')
            $lines += ('  Principal: ' + (Format-Value $account.Principal) + '; domain: ' + (Format-Value $account.Domain))
            $lines += ('  SID: ' + (Format-Value $account.SID))
            $lines += ('  Enabled: ' + (Format-Value $account.Enabled) + '; disabled: ' + (Format-Value $account.Disabled))
            $lines += ('  Password required: ' + (Format-Value $account.PasswordRequired) + '; password never expires: ' + (Format-Value $account.PasswordNeverExpires))
            $lines += ('  Last logon: ' + (Format-Value $account.LastLogon))
            $indicators = if ($account.ReviewIndicators.Count -gt 0) { $account.ReviewIndicators -join '; ' } else { '<none>' }
            $lines += ('  Review indicators: ' + $indicators)
        }
        $lines += ''
        $lines += 'COLLECTION NOTES AND LIMITATIONS'
        $lines += 'Domain controllers use ActiveDirectory for domain users/groups; other known roles audit local users and local Administrators.'
        $lines += ('ActiveDirectory module: ' + (Format-Value $Audit.ActiveDirectoryModuleStatus))
        $lines += 'Only direct privileged-group members are collected; nested/effective privileges are not resolved.'
        $lines += 'Partial means available results have collection limitations; unavailable is not a confirmed empty result.'
        $lines += '<unavailable> fields were not supplied; a missing last logon does not prove the account never logged on.'
        if ($CollectionIssues.Count -eq 0) { $lines += 'No collection issues reported.' }
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
    $lines += ('Output directory: ' + (Format-Value $Audit.OutputDirectory))
    if ($Detailed) {
        $lines += ''
        $lines += 'REPORT FILE REFERENCES'
        $lines += 'summary.txt: complete human-readable account and direct privileged-membership report.'
        $lines += 'users.json: complete structured audit, collection statuses, and issues.'
        $lines += 'accounts.csv: complete collected account inventory and existing review indicators.'
        $lines += 'privileged-members.csv: collected direct privileged-group membership entries.'
    }
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
$summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues -Detailed
$jsonText = $audit | ConvertTo-Json -Depth 10

if ($outputDirectory) {
    try {
        $audit.ReportSaved = $true
        $summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues -Detailed
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
        $summaryText = Get-UserAuditSummary $audit $CollectionIssues $OutputIssues -Detailed
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
