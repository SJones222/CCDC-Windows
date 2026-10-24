#Requires -Modules ActiveDirectory
<#
.SYNOPSIS  Restore accounts touched by Reset-PrivPasswords.ps1 to a known baseline password (for repeat testing).
.DESCRIPTION
  AD never reveals old passwords, so "reverting" means setting accounts back to a baseline you already know.
  Two modes:
    A) -ResetLog <csv> -BaselinePassword <securestring>
       Every account listed in a reset log gets the same baseline password.
    B) -BaselineCsv <csv>   (columns: Username,Password)
       Each account gets its own baseline password. Use this if your lab accounts had different passwords.
  If -ResetLog is omitted in mode A, the newest C:\Secure\pwreset_*.csv is used.
.EXAMPLE   $pw = Read-Host 'Baseline' -AsSecureString; .\Restore-PrivPasswords.ps1 -BaselinePassword $pw -WhatIf
.EXAMPLE   .\Restore-PrivPasswords.ps1 -BaselineCsv C:\Secure\baseline.csv
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High', DefaultParameterSetName='Single')]
param(
    [Parameter(ParameterSetName='Single')][string]$ResetLog,
    [Parameter(ParameterSetName='Single', Mandatory)][securestring]$BaselinePassword,
    [Parameter(ParameterSetName='PerUser', Mandatory)][string]$BaselineCsv,
    [switch]$ClearForceChange    # also clears "change password at next logon" if the reset run set it
)

$accounts = @()   # list of [pscustomobject]@{ Sam; Secure }

if ($PSCmdlet.ParameterSetName -eq 'PerUser') {
    if (-not (Test-Path $BaselineCsv)) { throw "Baseline CSV not found: $BaselineCsv" }
    foreach ($row in Import-Csv $BaselineCsv) {
        $accounts += [pscustomobject]@{
            Sam    = $row.Username
            Secure = (ConvertTo-SecureString $row.Password -AsPlainText -Force)
        }
    }
}
else {
    if (-not $ResetLog) {
        $latest = Get-ChildItem 'C:\Secure\pwreset_*.csv' -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) { throw 'No reset log found. Pass -ResetLog or use -BaselineCsv.' }
        $ResetLog = $latest.FullName
        Write-Host "Using reset log: $ResetLog" -ForegroundColor Cyan
    }
    if (-not (Test-Path $ResetLog)) { throw "Reset log not found: $ResetLog" }
    foreach ($row in Import-Csv $ResetLog) {
        $accounts += [pscustomobject]@{ Sam = $row.Username; Secure = $BaselinePassword }
    }
}

Write-Host "`nAccounts to restore: $($accounts.Count)" -ForegroundColor Cyan
$accounts | Select-Object Sam | Format-Table -AutoSize

foreach ($a in $accounts) {
    if ($PSCmdlet.ShouldProcess($a.Sam, 'Restore baseline password')) {
        try {
            # -Reset bypasses password history and minimum age, so this works repeatedly
            Set-ADAccountPassword -Identity $a.Sam -Reset -NewPassword $a.Secure -ErrorAction Stop
            if ($ClearForceChange) { Set-ADUser $a.Sam -ChangePasswordAtLogon $false }
            Unlock-ADAccount -Identity $a.Sam -ErrorAction SilentlyContinue
            Write-Host "[ok]   $($a.Sam)" -ForegroundColor Green
        } catch {
            Write-Warning "[fail] $($a.Sam): $($_.Exception.Message)"
        }
    }
}