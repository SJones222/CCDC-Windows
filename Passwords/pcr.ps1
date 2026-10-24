#Requires -Modules ActiveDirectory
<#
.SYNOPSIS  Reset passwords for privileged/high-exposure AD user accounts using AdjectiveAnimal##! passphrases.
.EXAMPLE   .\Reset-PrivPasswords.ps1 -WhatIf
.EXAMPLE   .\Reset-PrivPasswords.ps1 -ExcludeUsers 'krbtgt','scoring_svc'
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [string[]]$ExcludeUsers = @('krbtgt'),
    [string]$OutFile = "C:\Secure\pwreset_$(Get-Date -Format yyyyMMdd_HHmmss).txt",
    [switch]$IncludeSPNAccounts,     # service accounts: reset only if you know what depends on them
    [switch]$ForceChangeAtLogon
)

# --- Word lists (replace with your own; don't reuse these verbatim) ---
$Adjectives = @(
 'Sneaky','Brave','Clever','Swift','Mighty','Gentle','Fierce','Lucky','Sleepy','Grumpy',
 'Happy','Jolly','Quiet','Loud','Bold','Shy','Wild','Calm','Proud','Silly',
 'Frosty','Sunny','Stormy','Cosmic','Rusty','Shiny','Dusty','Fuzzy','Spicy','Salty',
 'Crimson','Golden','Silver','Amber','Violet','Scarlet','Teal','Ivory','Cobalt','Emerald',
 'Nimble','Rapid','Steady','Stubborn','Curious','Cheerful','Daring','Eager','Fearless','Graceful',
 'Honest','Humble','Jumpy','Kindly','Lively','Merry','Noble','Plucky','Restless','Witty'
)
$Animals = @(
 'Zebra','Tiger','Otter','Falcon','Badger','Panda','Koala','Moose','Lemur','Gecko',
 'Heron','Walrus','Bison','Cobra','Dolphin','Eagle','Ferret','Gazelle','Hedgehog','Iguana',
 'Jaguar','Kiwi','Llama','Marmot','Narwhal','Ocelot','Penguin','Quokka','Raven','Salmon',
 'Toucan','Urchin','Viper','Wombat','Yak','Beaver','Cougar','Dingo','Elk','Fox',
 'Giraffe','Hamster','Ibis','Jackal','Kestrel','Lynx','Mantis','Newt','Osprey','Puffin',
 'Rhino','Sparrow','Turtle','Vulture','Weasel','Mongoose','Pelican','Squirrel','Stork','Tapir'
)

# --- Helpers ---
$script:rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function Get-Rand([int]$max) {   # unbiased CSPRNG integer in [0, max)
    $b = New-Object byte[] 4
    do { $script:rng.GetBytes($b); $v = [BitConverter]::ToUInt32($b,0) }
    while ($v -ge ([uint32]::MaxValue - ([uint32]::MaxValue % $max)))
    [int]($v % $max)
}

function New-PassPhrase {        # e.g. SneakyZebra67!
    $adj    = $Adjectives[(Get-Rand $Adjectives.Count)]
    $animal = $Animals[(Get-Rand $Animals.Count)]
    $digits = '{0:D2}' -f (Get-Rand 100)
    "$adj$animal$digits!"
}

function New-RandomPassword {    # kept for krbtgt / highest-value accounts
    param([int]$Length = 32)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#$%^*-_=+')
    $all = -join $sets
    $chars = @()
    foreach ($s in $sets) { $chars += $s[(Get-Rand $s.Length)] }
    while ($chars.Count -lt $Length) { $chars += $all[(Get-Rand $all.Length)] }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-Rand ($i + 1); $chars[$i], $chars[$j] = $chars[$j], $chars[$i]
    }
    -join $chars
}

# --- 1. Collect privileged groups ---
$privGroups = @(
    'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
    'Account Operators','Server Operators','Backup Operators','Print Operators',
    'DnsAdmins','Group Policy Creator Owners','Remote Desktop Users',
    'Remote Management Users','Cert Publishers'
)

$targets = @{}

foreach ($g in $privGroups) {
    try {
        Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
            Where-Object objectClass -eq 'user' |
            ForEach-Object { $targets[$_.SamAccountName] = "Group:$g" }
    } catch { Write-Warning "Skipping group '$g': $($_.Exception.Message)" }
}

# AdminCount=1 catches accounts that are/were protected by AdminSDHolder
Get-ADUser -Filter 'AdminCount -eq 1' | ForEach-Object {
    if (-not $targets.ContainsKey($_.SamAccountName)) { $targets[$_.SamAccountName] = 'AdminCount=1' }
}

# --- 2. Filter ---
$me = $env:USERNAME
$final = foreach ($sam in $targets.Keys) {
    if ($sam -in $ExcludeUsers) { Write-Host "[skip] $sam (excluded)"; continue }
    if ($sam -eq $me)           { Write-Host "[skip] $sam (current user)"; continue }

    $u = Get-ADUser $sam -Properties Enabled,ServicePrincipalName,PasswordNeverExpires,LastLogonDate
    if (-not $u.Enabled) { Write-Host "[skip] $sam (disabled)"; continue }
    if ($u.ServicePrincipalName -and -not $IncludeSPNAccounts) {
        Write-Warning "[skip] $sam has SPNs (service account). Use -IncludeSPNAccounts if intended."
        continue
    }
    [pscustomobject]@{ Sam = $sam; Why = $targets[$sam]; LastLogon = $u.LastLogonDate }
}

Write-Host "`nAccounts to reset:" -ForegroundColor Cyan
$final | Format-Table -AutoSize

# --- 3. Prepare secure output file ---
$dir = Split-Path $OutFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
if (-not $WhatIfPreference) {
    New-Item -ItemType File -Path $OutFile -Force | Out-Null
    icacls $dir /inheritance:r /grant:r "Administrators:(OI)(CI)F" | Out-Null
}

# --- 4. Reset ---
foreach ($acct in $final) {
    $pw = New-PassPhrase
    if ($PSCmdlet.ShouldProcess($acct.Sam, 'Reset password')) {
        try {
            Set-ADAccountPassword -Identity $acct.Sam -Reset `
                -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
            if ($ForceChangeAtLogon) { Set-ADUser $acct.Sam -ChangePasswordAtLogon $true }
            "$($acct.Sam), $pw" | Out-File $OutFile -Append -Encoding ascii
            Write-Host "[ok]   $($acct.Sam)" -ForegroundColor Green
        } catch {
            Write-Warning "[fail] $($acct.Sam): $($_.Exception.Message)"
        }
    }
}

if (-not $WhatIfPreference) {
    Write-Host "`nPasswords saved to $OutFile. Move to your team's password manager, then delete the file." -ForegroundColor Yellow
}