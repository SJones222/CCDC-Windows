#requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free synthetic tests for Milestone 1.2A. Run in Windows PowerShell 5.1.
.DESCRIPTION
    Loads function ASTs only, never the collector's entry point. CIM, registry roots,
    and filesystem ACL probes are mocked. Writes synthetic reports to its own temp
    directory; does not enumerate real services/software or modify system settings.
#>
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'This synthetic suite requires 64-bit Windows; use Windows PowerShell 5.1 for compatibility validation.'
}
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Inventory\Get-ServiceSoftwareInventory.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Collector syntax parsing failed.' }
$definitions = @{}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    $definitions[$node.Name] = $node.Body.GetScriptBlock()
    Set-Item -Path ('Function:script:' + $node.Name) -Value $definitions[$node.Name]
}
$script:Passed = 0; $script:Failed = 0
$script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('CCDC-ServiceSoftware-Tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:TestRoot)
$script:UserSid = 'S-1-5-21-1-2-3-1001'
$script:Allowed = @($script:UserSid, 'S-1-5-18', 'S-1-5-32-544')

function Assert-True {
    param([bool]$Condition, [string]$Reason = 'Assertion failed')
    if (-not $Condition) { throw $Reason }
}

function Assert-Throws {
    param([scriptblock]$Action)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw 'An expected failure was not raised.'
}

function New-FakeKey {
    param([hashtable]$Values = @{}, [hashtable]$Children = @{}, [string[]]$Denied = @())
    $key = [pscustomobject]@{ Values = $Values; Children = $Children; Denied = $Denied; Disposed = $false }
    $key | Add-Member ScriptMethod GetValueNames { return ,[string[]]@($this.Values.Keys) }
    $key | Add-Member ScriptMethod GetSubKeyNames { return ,[string[]]@($this.Children.Keys) }
    $key | Add-Member ScriptMethod OpenSubKey {
        param($Name, $Writable)
        if ($Writable) { throw 'Writable registry access attempted.' }
        if ($this.Denied -contains $Name) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        return $this.Children[$Name]
    }
    $key | Add-Member ScriptMethod GetValue {
        param($Name, $Default, $Options)
        if ($this.Denied -contains $Name) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        return $this.Values[$Name]
    }
    $key | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
    $key
}

function Reset-Fixture {
    foreach ($name in $definitions.Keys) { Set-Item -Path ('Function:script:' + $name) -Value $definitions[$name] }
    $script:CollectionIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:OutputIssues = New-Object 'System.Collections.Generic.List[object]'
    $script:WarningCount = 0
    $script:CimMode = 'Success'; $script:CimCalls = 0
    $script:FakeServices = @([pscustomobject]@{
        Name = 'SyntheticService'; DisplayName = 'Synthetic service'; State = 'Running'
        StartMode = 'Auto'; StartName = 'LocalSystem'; ProcessId = 123
        PathName = '"C:\Fixture\Service.exe" --synthetic-token SYNTHETIC_SECRET_MARKER'
    })
    $script:FakeRoots = @{ Registry64 = New-FakeKey; Registry32 = New-FakeKey }
    $script:DeniedViews = @(); $script:ProtectionFailure = $false
    $script:MissingViews = @(); $script:FailedViews = @()
    $script:PreparationFailures = 0; $script:FailWrites = $false
    $script:WrittenNames = New-Object 'System.Collections.Generic.List[string]'
    $script:AncestorChecks = New-Object 'System.Collections.Generic.List[string]'
    $script:UnsafeAncestor = $null
    function script:Get-CimInstance {
        [CmdletBinding()]
        param([string]$ClassName, [string[]]$Property, [int]$OperationTimeoutSec)
        if ($ClassName -ne 'Win32_Service' -or $OperationTimeoutSec -ne 30) { throw 'Unexpected query.' }
        $script:CimCalls++
        if ($script:CimMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        if ($script:CimMode -eq 'Missing') { throw [System.Management.Automation.CommandNotFoundException]::new('Synthetic capability') }
        if ($script:CimMode -eq 'Failed') { throw [InvalidOperationException]::new('Synthetic provider failure') }
        if ($script:CimMode -eq 'AfterOne') { Write-Output $script:FakeServices[0]; throw 'Synthetic late failure' }
        $script:FakeServices
    }
    function script:Open-UninstallRoot {
        param([string]$View)
        if ($script:DeniedViews -contains $View) { throw [UnauthorizedAccessException]::new('Synthetic denial') }
        if ($script:MissingViews -contains $View) { throw [PlatformNotSupportedException]::new('Synthetic capability') }
        if ($script:FailedViews -contains $View) { throw [InvalidOperationException]::new('Synthetic provider failure') }
        [pscustomobject]@{ BaseKey = (New-FakeKey); Key = $script:FakeRoots[$View] }
    }
    # Filesystem publication tests isolate ACL decisions; descriptor tests below
    # exercise the actual policy without changing any real ACL.
    function script:Assert-ProtectedReportPath {
        param([string]$Path, [string[]]$AllowedSids)
        if ($script:ProtectionFailure) { throw 'Synthetic protection failure' }
    }
    function script:Assert-ReportAncestors { param([string]$Path, [string[]]$AllowedSids) }
    function script:Get-Acl {
        [CmdletBinding()]
        param([string]$LiteralPath)
        $script:AncestorChecks.Add($LiteralPath)
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')(A;;FRFX;;;AU)'
        if ($LiteralPath -eq $script:UnsafeAncestor) { $sddl += '(A;;0x00000040;;;AU)' }
        $acl = [pscustomobject]@{ Descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl) }
        $acl | Add-Member ScriptMethod GetSecurityDescriptorBinaryForm {
            $bytes = New-Object byte[] $this.Descriptor.BinaryLength
            $this.Descriptor.GetBinaryForm($bytes, 0)
            return ,$bytes
        }
        $acl
    }
}

function Run-Test {
    param([string]$Name, [scriptblock]$Test)
    Reset-Fixture
    try { & $Test; $script:Passed++; Write-Host ('PASS: ' + $Name) }
    catch { $script:Failed++; Write-Host ('FAIL: ' + $Name + ' (' + $_.Exception.GetType().Name + ')') }
}

function New-TestLocation {
    $directory = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    $location = [pscustomobject]@{
        Directory = $directory; TemporaryPaths = [ordered]@{}
        CreatedPaths = (New-Object 'System.Collections.Generic.List[string]')
    }
    foreach ($name in @('summary.txt', 'services.csv', 'software.csv', 'service-software.json')) {
        $path = Join-Path $directory ($name + '.tmp')
        [IO.File]::Open($path, [IO.FileMode]::CreateNew).Dispose()
        $location.TemporaryPaths[$name] = $path
        $location.CreatedPaths.Add($path)
    }
    $location
}

function New-TestReport {
    param($Location)
    $services = Get-ServiceDataset
    $software = Get-SoftwareDataset
    $processes = New-InventoryDataset Processes $true Unavailable @() @('NotImplemented')
    [ordered]@{
        SchemaVersion = '0.1.0'; ModuleId = 'service-software-inventory'; Version = '0.1.0'
        DevelopmentStage = 'Milestone 1.2A'; ReleaseReady = $false
        RunId = [guid]::NewGuid().ToString(); Hostname = 'SYNTHETIC_HOST'
        StartedAt = [datetime]::UtcNow.ToString('o'); CompletedAt = [datetime]::UtcNow.ToString('o')
        Collection = [ordered]@{ Status = 'Partial'; Datasets = @($services, $software, $processes); Issues = @($script:CollectionIssues.ToArray()) }
        Assessment = [ordered]@{ Status = 'NotPerformed'; Findings = @() }
        Output = [ordered]@{
            Status = 'Failed'; Directory = $Location.Directory; FallbackUsed = $false
            ProtectionStatus = 'VerifiedRestricted'
            Files = @('summary.txt', 'services.csv', 'software.csv', 'service-software.json'); Issues = @()
        }
    }
}

try {
    Run-Test 'status aggregation and all four exits' {
        $success = New-InventoryDataset A $true Success @() @()
        $failed = New-InventoryDataset B $true Failed @() @()
        $unavailable = New-InventoryDataset C $true Unavailable @() @()
        $optional = New-InventoryDataset D $false Failed @() @()
        Assert-True ((Get-AggregateStatus @($success, $optional)) -eq 'Success')
        Assert-True ((Get-AggregateStatus @($success, $failed)) -eq 'Partial')
        Assert-True ((Get-AggregateStatus @($failed, $unavailable)) -eq 'Failed')
        Assert-True ((Get-AggregateStatus @($unavailable)) -eq 'Unavailable')
        Assert-True ((Get-InventoryExitCode Success $true) -eq 0)
        Assert-True ((Get-InventoryExitCode Failed $true) -eq 1)
        Assert-True ((Get-InventoryExitCode Partial $true) -eq 2)
        Assert-True ((Get-InventoryExitCode Unavailable $true) -eq 2)
        Assert-True ((Get-InventoryExitCode Success $false) -eq 3)
    }
    Run-Test 'zero/one/many JSON arrays and unknown counts' {
        foreach ($size in @(0, 1, 2)) {
            $items = @(for ($i = 0; $i -lt $size; $i++) { [pscustomobject]@{ Id = $i } })
            $dataset = New-InventoryDataset A $true Success $items @()
            $json = $dataset | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            Assert-True ($json.Items -is [array] -and $json.Items.Count -eq $size -and $json.Count -eq $size)
        }
        $missing = New-InventoryDataset A $true Unavailable @() @()
        Assert-True ($null -eq $missing.Count -and $missing.Items.Count -eq 0)
    }
    Run-Test 'all service states, PID zero, raw-only separation' {
        $stopped = $script:FakeServices[0].PSObject.Copy()
        $stopped.Name = 'Stopped'; $stopped.State = 'Stopped'; $stopped.StartMode = 'Disabled'; $stopped.ProcessId = 0
        $manual = $stopped.PSObject.Copy()
        $manual.Name = 'Manual'; $manual.StartMode = 'Manual'
        $script:FakeServices += @($stopped, $manual)
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 3)
        Assert-True ($data.Items[1].ProcessId -eq 0 -and $null -eq $data.Items[0].ExecutablePath)
        Assert-True ($data.Items[0].RawCommandLine.Contains('SYNTHETIC_SECRET_MARKER'))
    }
    Run-Test 'successful empty service query' {
        $script:FakeServices = @()
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0 -and $data.Items.Count -eq 0)
    }
    Run-Test 'denied, genuine failure, and late partial service queries' {
        foreach ($mode in @('Denied', 'Missing', 'Failed', 'AfterOne')) {
            $script:CimMode = $mode
            $data = Get-ServiceDataset
            $expectedByMode = @{ Denied = 'Unavailable'; Missing = 'Unavailable'; Failed = 'Failed'; AfterOne = 'Partial' }
            $expected = $expectedByMode[$mode]
            Assert-True ($data.Status -eq $expected)
            $codeByMode = @{ Denied = 'AccessDenied'; Missing = 'CapabilityMissing'; Failed = 'QueryFailed'; AfterOne = 'QueryFailed' }
            Assert-True ($script:CollectionIssues[$script:CollectionIssues.Count - 1].Code -eq $codeByMode[$mode])
            if ($mode -ne 'AfterOne') { Assert-True ($null -eq $data.Count) }
        }
    }
    Run-Test 'wrapped exception and CIM error identities use stable codes' {
        $denial = [InvalidOperationException]::new('Synthetic wrapper', [UnauthorizedAccessException]::new('Synthetic secret'))
        $record = [System.Management.Automation.ErrorRecord]::new($denial, 'Synthetic', 'NotSpecified', $null)
        Assert-True ((Get-CollectionFailure $record).Code -eq 'AccessDenied')
        foreach ($nativeCode in @('AccessDenied', 'InvalidClass', 'InvalidNamespace', 'NotSupported')) {
            $exception = [Exception]::new('Synthetic secret')
            $exception | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue $nativeCode
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'Synthetic', 'NotSpecified', $null)
            $problem = Get-CollectionFailure $record
            $expected = if ($nativeCode -eq 'AccessDenied') { 'AccessDenied' } else { 'CapabilityMissing' }
            Assert-True ($problem.Status -eq 'Unavailable' -and $problem.Code -eq $expected)
        }
    }
    Run-Test 'missing service field is partial, empty command is not unknown' {
        $script:FakeServices[0].PathName = ''
        $script:FakeServices[0].StartName = $null
        $data = Get-ServiceDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Items[0].RawCommandLineState -eq 'Empty')
        Assert-True ($data.Items[0].RawCommandLine -ceq '')
    }
    Run-Test 'both software views preserve duplicates and missing values' {
        foreach ($view in @('Registry64', 'Registry32')) {
            $script:FakeRoots[$view] = New-FakeKey -Children @{ Duplicate = New-FakeKey -Values @{ DisplayName = 'Synthetic app' } }
        }
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 2)
        Assert-True ($data.Items[0].Id -ne $data.Items[1].Id)
        Assert-True ($data.Items[0].MissingValueNames.Count -eq 2)
    }
    Run-Test 'absent uninstall roots are successful empty sources' {
        $script:FakeRoots = @{ Registry64 = $null; Registry32 = $null }
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Success' -and $data.Count -eq 0)
    }
    Run-Test 'denied view is partial overall, not successful empty' {
        $script:DeniedViews = @('Registry64')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Coverage[0].Status -eq 'Unavailable')
        Assert-True ($script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'unavailable registry capability differs from genuine view failure' {
        $script:MissingViews = @('Registry64', 'Registry32')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Unavailable' -and $null -eq $data.Count)
        Assert-True (@($script:CollectionIssues | Where-Object { $_.Code -ne 'CapabilityMissing' }).Count -eq 0)
        $script:MissingViews = @(); $script:FailedViews = @('Registry64', 'Registry32')
        $before = $script:CollectionIssues.Count
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Failed' -and $null -eq $data.Count)
        Assert-True ($script:CollectionIssues[$before].Code -eq 'QueryFailed')
    }
    Run-Test 'denied child registration retains identity and one access issue' {
        $script:FakeRoots.Registry64 = New-FakeKey -Children @{ SyntheticKey = New-FakeKey } -Denied @('SyntheticKey')
        $data = Get-SoftwareDataset
        Assert-True ($data.Status -eq 'Partial' -and $data.Count -eq 1)
        Assert-True ($data.Items[0].Id -eq 'software:Registry64:SyntheticKey' -and $data.Items[0].RecordStatus -eq 'Partial')
        Assert-True ($script:CollectionIssues.Count -eq 1 -and $script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'denied software value differs from absent value' {
        $key = New-FakeKey -Values @{ DisplayName = 'Synthetic'; Publisher = 'Synthetic publisher' } -Denied @('Publisher')
        $row = Read-SoftwareRegistration Registry64 SyntheticKey $key
        Assert-True ($row.RecordStatus -eq 'Partial' -and $null -eq $row.Publisher)
        Assert-True ($row.MissingValueNames -contains 'DisplayVersion' -and $row.MissingValueNames -notcontains 'Publisher')
        Assert-True ($script:CollectionIssues[0].Code -eq 'AccessDenied')
    }
    Run-Test 'creator-owner inheritance template is not an effective broad grant' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')'
        $template = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;OICIIO;FA;;;CO)'))
        Assert-True (Test-RestrictedDescriptor $template $script:Allowed)
        $effective = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FA;;;CO)'))
        Assert-True (-not (Test-RestrictedDescriptor $effective $script:Allowed))
        $broadTemplate = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;OICIIO;FR;;;AU)'))
        Assert-True (-not (Test-RestrictedDescriptor $broadTemplate $script:Allowed))
    }
    Run-Test 'ancestors permit traversal but reject replacement and DACL/owner rights' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')'
        $readOnly = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FRFX;;;AU)'))
        Assert-True (Test-RestrictedDescriptor $readOnly $script:Allowed -Ancestor)
        foreach ($mask in @('0x00000040', '0x00010000', '0x00040000', '0x00080000', '0x10000000', '0x40000000')) {
            $unsafe = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;' + $mask + ';;;AU)'))
            Assert-True (-not (Test-RestrictedDescriptor $unsafe $script:Allowed -Ancestor))
        }
        $unknownOwner = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl.Replace(('O:' + $script:UserSid), 'O:AU')))
        Assert-True (-not (Test-RestrictedDescriptor $unknownOwner $script:Allowed -Ancestor))
    }
    Run-Test 'existing ancestors are checked before creating a missing report tree' {
        Set-Item -Path Function:script:Assert-ReportAncestors -Value $definitions['Assert-ReportAncestors']
        $missing = Join-Path $script:TestRoot 'MissingRoot\Host\Run'
        Assert-ReportAncestors $missing $script:Allowed
        Assert-True ($script:AncestorChecks -contains $script:TestRoot)
        Assert-True ($script:AncestorChecks -contains [IO.Path]::GetPathRoot($missing))
        Assert-True (-not [IO.Directory]::Exists((Join-Path $script:TestRoot 'MissingRoot')))
        $script:UnsafeAncestor = $script:TestRoot
        Assert-Throws { Assert-ReportAncestors $missing $script:Allowed }
    }
    Run-Test 'local path checks reject files used as intermediate directories' {
        $file = Join-Path $script:TestRoot 'IntermediateFile'
        [IO.File]::WriteAllText($file, 'Synthetic fixture')
        Assert-True (-not (Test-LocalNonReparsePath (Join-Path $file 'MissingChild') $false))
        Assert-True (-not (Test-LocalNonReparsePath '\\SYNTHETIC\Share' $false))
    }
    Run-Test 'ACL allowlist, broad access, unknown owner, null DACL' {
        $sddl = 'O:' + $script:UserSid + 'G:SYD:(A;;FA;;;' + $script:UserSid + ')(A;;FA;;;SY)(A;;FA;;;BA)'
        $safe = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        Assert-True (Test-RestrictedDescriptor $safe $script:Allowed)
        $broad = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl + '(A;;FR;;;AU)'))
        Assert-True (-not (Test-RestrictedDescriptor $broad $script:Allowed))
        $other = [System.Security.AccessControl.RawSecurityDescriptor]::new(($sddl.Replace(('O:' + $script:UserSid), 'O:AU')))
        Assert-True (-not (Test-RestrictedDescriptor $other $script:Allowed))
        $nullDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
            [System.Security.Principal.SecurityIdentifier]::new($script:UserSid), $null, $null, $null)
        Assert-True (-not (Test-RestrictedDescriptor $nullDacl $script:Allowed))
    }
    Run-Test 'structured issues do not serialize native exception text' {
        $script:CimMode = 'Denied'; $null = Get-ServiceDataset
        $issue = $script:CollectionIssues[0]
        Assert-True ($issue.DatasetId -eq 'Services' -and $issue.Stage -eq 'Collect' -and $issue.Code -eq 'AccessDenied')
        Assert-True (-not $issue.Message.Contains('Synthetic denial'))
    }
    Run-Test 'report round trip, CSV headers, Unicode and command-line confinement' {
        $script:FakeServices[0].DisplayName = "Synthetic, quoted `"display`"`nsecond line " + [char]0x03A9
        $location = New-TestLocation; $report = New-TestReport $location
        Publish-InventoryReports $report $location $script:Allowed
        $json = [IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')) | ConvertFrom-Json
        $csv = @(Import-Csv -LiteralPath (Join-Path $location.Directory 'services.csv'))
        Assert-True ($json.RunId -eq $report.RunId -and $csv.Count -eq 1)
        Assert-True ($report.Output.Status -eq 'Success' -and $json.Output.Status -eq 'Success')
        $summary = [IO.File]::ReadAllText((Join-Path $location.Directory 'summary.txt'))
        Assert-True ($summary.Contains('not certified by this supporting report') -and -not $summary.Contains('Report-save status: Success'))
        Assert-True ($csv[0].DisplayName -ceq $script:FakeServices[0].DisplayName)
        foreach ($name in @('summary.txt','services.csv','software.csv')) {
            Assert-True (-not [IO.File]::ReadAllText((Join-Path $location.Directory $name)).Contains('SYNTHETIC_SECRET_MARKER'))
        }
        Assert-True ([IO.File]::ReadAllText((Join-Path $location.Directory 'service-software.json')).Contains('SYNTHETIC_SECRET_MARKER'))
        Assert-True (([IO.File]::ReadAllLines((Join-Path $location.Directory 'software.csv'))).Count -eq 1)
    }
    Run-Test 'publication order and failure before canonical JSON' {
        function script:Write-ProtectedReportText {
            param($Path, $Text, $AllowedSids)
            $name = [IO.Path]::GetFileName($Path)
            $script:WrittenNames.Add($name)
            if ($name -eq 'software.csv.tmp') { throw 'Synthetic write failure' }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed')
        Assert-True (-not [IO.File]::Exists((Join-Path $location.Directory 'service-software.json')))
        # Surviving supporting files must not certify the incomplete report set.
        $script:ProtectionFailure = $true
        Remove-IncompleteReportFiles $location $script:Allowed
        $summary = [IO.File]::ReadAllText((Join-Path $location.Directory 'summary.txt'))
        Assert-True ($summary.Contains('not certified by this supporting report') -and -not $summary.Contains('Report-save status: Success'))
        $script:ProtectionFailure = $false
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ((Get-ChildItem -LiteralPath $location.Directory -Force).Count -eq 0)
        Assert-True (($script:WrittenNames.ToArray() -join ',') -eq 'summary.txt.tmp,services.csv.tmp,software.csv.tmp')
    }
    Run-Test 'candidate JSON does not mark live output successful during publication' {
        function script:Write-ProtectedReportText {
            param($Path, $Text, $AllowedSids)
            Assert-True ($script:PublishingReport.Output.Status -eq 'Failed')
            $script:WrittenNames.Add([IO.Path]::GetFileName($Path))
            if ([IO.Path]::GetFileName($Path) -eq 'service-software.json.tmp') {
                foreach ($name in @('summary.txt', 'services.csv', 'software.csv')) {
                    Assert-True ([IO.File]::Exists((Join-Path ([IO.Path]::GetDirectoryName($Path)) $name)))
                }
                Assert-True (($Text | ConvertFrom-Json).Output.Status -eq 'Success')
                $script:CandidateChecked = $true
                throw 'Synthetic canonical write failure'
            }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $location = New-TestLocation; $script:PublishingReport = New-TestReport $location
        $script:CandidateChecked = $false
        Assert-Throws { Publish-InventoryReports $script:PublishingReport $location $script:Allowed }
        Assert-True ($script:PublishingReport.Output.Status -eq 'Failed' -and $script:CandidateChecked)
        Assert-True (($script:WrittenNames.ToArray() -join ',') -eq 'summary.txt.tmp,services.csv.tmp,software.csv.tmp,service-software.json.tmp')
    }
    Run-Test 'post-promotion failure retains failed status and cleans canonical JSON first' {
        function script:Assert-ProtectedReportPath {
            param($Path, $AllowedSids)
            if ([IO.Path]::GetFileName($Path) -eq 'service-software.json') { throw 'Synthetic final verification failure' }
        }
        $location = New-TestLocation; $report = New-TestReport $location
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        Assert-True ($report.Output.Status -eq 'Failed')
        Assert-True ([IO.File]::Exists((Join-Path $location.Directory 'service-software.json')))
        $script:CleanupChecks = New-Object 'System.Collections.Generic.List[string]'
        function script:Assert-ProtectedReportPath {
            param($Path, $AllowedSids)
            $script:CleanupChecks.Add([IO.Path]::GetFileName($Path))
        }
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ($script:CleanupChecks[1] -eq 'service-software.json')
        Assert-True ((Get-ChildItem -LiteralPath $location.Directory -Force).Count -eq 0)
    }
    Run-Test 'protection failure prevents writes and cleanup records its refusal' {
        $location = New-TestLocation; $report = New-TestReport $location
        $script:ProtectionFailure = $true
        Assert-Throws { Publish-InventoryReports $report $location $script:Allowed }
        foreach ($path in $location.CreatedPaths) { Assert-True ((Get-Item -LiteralPath $path).Length -eq 0) }
        Remove-IncompleteReportFiles $location $script:Allowed
        Assert-True ($script:OutputIssues.Count -gt 0)
    }
    Run-Test 'both output preparations rejected before service/software collection' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); throw 'Synthetic unverified output' }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 3 -and $script:CimCalls -eq 0)
    }
    Run-Test 'preflight fallback, development placeholders, and saved exit 2' {
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $script:PreparationFailures++
            if ($script:PreparationFailures -eq 1) { throw 'Synthetic primary denial' }
            $script:LastLocation = New-TestLocation
            $script:LastLocation
        }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 2 -and $script:CimCalls -eq 1)
        $report = [IO.File]::ReadAllText((Join-Path $script:LastLocation.Directory 'service-software.json')) | ConvertFrom-Json
        $processes = @($report.Collection.Datasets | Where-Object { $_.Id -eq 'Processes' })[0]
        Assert-True ($processes.Required -and $processes.Status -eq 'Unavailable' -and $null -eq $processes.Count)
        Assert-True ($report.Output.FallbackUsed -and -not $report.ReleaseReady)
        Assert-True ($report.Output.Files.Count -eq 4)
    }
    Run-Test 'total publication failure returns 3, never a saved success' {
        function script:New-ProtectedReportLocation { param($Root,$HostFolder,$RunId,$AllowedSids); New-TestLocation }
        function script:Write-ProtectedReportText { param($Path,$Text,$AllowedSids); throw 'Synthetic persistent write failure' }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 3)
        Assert-True (-not (($result[0..($result.Count-2)] -join ' ').Contains('Report-save status: Success')))
    }
    Run-Test 'write failure falls back without collecting twice' {
        $script:Locations = New-Object 'System.Collections.Generic.List[object]'
        function script:New-ProtectedReportLocation {
            param($Root,$HostFolder,$RunId,$AllowedSids)
            $location = New-TestLocation
            $script:Locations.Add($location)
            $location
        }
        function script:Write-ProtectedReportText {
            param($Path,$Text,$AllowedSids)
            if (-not $script:FailWrites) { $script:FailWrites = $true; throw 'Synthetic first write failure' }
            & $definitions['Write-ProtectedReportText'] $Path $Text $AllowedSids
        }
        $result = @(Invoke-ServiceSoftwareInventory $script:TestRoot)
        Assert-True ($result[-1] -eq 2 -and $script:CimCalls -eq 1 -and $script:Locations.Count -eq 2)
        $report = [IO.File]::ReadAllText((Join-Path $script:Locations[1].Directory 'service-software.json')) | ConvertFrom-Json
        Assert-True ($report.Output.FallbackUsed -and @($report.Output.Issues).Count -gt 0)
        Assert-True ((Get-ChildItem -LiteralPath $script:Locations[0].Directory -Force).Count -eq 0)
    }
    Run-Test 'native location preparation resolves relative roots and avoids collisions' {
        $base = Join-Path $script:TestRoot 'RelativeRoot'
        [void][IO.Directory]::CreateDirectory($base)
        Push-Location -LiteralPath $base
        try {
            $first = New-ProtectedReportLocation '.' SYNTHETIC_HOST ([guid]::NewGuid().ToString()) $script:Allowed
            $second = New-ProtectedReportLocation '.' SYNTHETIC_HOST ([guid]::NewGuid().ToString()) $script:Allowed
            Assert-True ([IO.Path]::IsPathRooted($first.Directory) -and $first.Directory -ne $second.Directory)
            Assert-True ($first.TemporaryPaths.Count -eq 4 -and $second.TemporaryPaths.Count -eq 4)
        }
        finally { Pop-Location }
    }
}
finally {
    # Only the GUID-named test directory created above; no real reports or ACLs.
    if ($script:TestRoot -like (Join-Path ([IO.Path]::GetTempPath()) 'CCDC-ServiceSoftware-Tests-*')) {
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction Stop
    }
}
Write-Host ('Synthetic tests: ' + $script:Passed + ' passed; ' + $script:Failed + ' failed.')
if ($script:Failed -gt 0) { exit 1 }
