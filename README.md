# Windows CCDC PowerShell Toolkit

A small, specification-driven Windows PowerShell 5.1 toolkit for Windows CCDC inventory, auditing, and explicitly requested administration tasks. The five read-only inventory/audit scripts use built-in Windows capabilities. Separately attributed team scripts retain their original behavior and prerequisites.

## Directory structure

```text
Inventory/    Read-only system inventory scripts
Audit/        Read-only security and configuration audit scripts
Remediation/  Explicitly requested remediation scripts
Firewall/     Teammate domain-controller firewall script
Passwords/    Teammate Active Directory password reset/restore scripts
SSH/          Teammate OpenSSH installation/configuration script
Tests/        Tests for implemented behavior
```

## Quick Install

Use Windows PowerShell 5.1. The default installation destination is `C:\CCDC`. Git and third-party modules are not required. The command below downloads and executes `Install-CCDC.ps1` from `main`, which then downloads the complete repository ZIP over HTTPS. Review and trust the repository code before running it. The repository and selected branch must be accessible without authentication; this installer does not handle credentials.

Production bootstrap (installs `main`, including the teammate-script integration and the approved barebones v3.0 firewall script):

```powershell
& { $ccdcTls = [Net.ServicePointManager]::SecurityProtocol; try { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/SJones222/CCDC-Windows/main/Install-CCDC.ps1' -ErrorAction Stop).Content)) } finally { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls } }
```

Administrator permissions may be necessary to write to `C:\CCDC`. The installer does not elevate, change execution policy, or execute any audit or remediation scripts. It temporarily enables TLS 1.2 for downloads and restores the process's previous protocol setting afterward.

Existing destinations are intentionally refused, even if they contain only `Output/`. Files, local modifications, and previous reports are never overwritten or merged. Use a new destination for another installation. The destination must be an absolute local Windows path with an existing parent directory; PowerShell wildcard characters are not supported in the path.

After installation, run the short-named standalone copies directly from the installation root when ready:

```powershell
cd C:\CCDC
.\network.ps1
.\system.ps1
.\users.ps1
.\persistence.ps1
.\events.ps1
.\events.ps1 -Deep
```

These files are complete copies of the original scripts, created only in the staged installation. The original scripts remain unchanged in `Inventory/` and `Audit/`. Both forms use the installation's `Output/<Hostname>/` hierarchy by default, preserve the existing report-folder prefixes and temporary-directory fallback, and accept the same parameters, including `-OutputDir`.

The installer also deploys five [Windows Team Scripts](#windows-team-scripts) as root-level copies, for ten scripts total. Those five scripts change firewall, account, or SSH configuration when explicitly executed; their original output paths and prompts are preserved. None runs automatically during installation.

See [Current scripts](#current-scripts) for parameters and report filenames, and [COMMAND-CHEATSHEET.md](COMMAND-CHEATSHEET.md) for further execution examples.

### Testing the installer

To use an installer already saved locally with a clean test destination:

```powershell
.\Install-CCDC.ps1 -Ref 'firewall-version-fix' -Destination 'C:\CCDC-FirewallTest'
```

To test the firewall replacement from its testing branch, run this one-line bootstrap into a new directory. Both the installer and ZIP come from the published `firewall-version-fix` branch; the production default remains `main`.

```powershell
& { $ccdcTls = [Net.ServicePointManager]::SecurityProtocol; try { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/SJones222/CCDC-Windows/firewall-version-fix/Install-CCDC.ps1' -ErrorAction Stop).Content)) -Ref 'firewall-version-fix' -Destination 'C:\CCDC-FirewallTest' } finally { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls } }
```

`-Ref` selects a repository branch. Installation validates all ten scripts, README, contribution rules, and installer before copying the complete snapshot, including hidden tracked files. Empty `Remediation/` and `Tests/` directories and `Output/` are created if absent. The prepared installation is renamed into place only after all preparation succeeds. Failures before promotion leave a new destination absent; preexisting destinations are left untouched. Cleanup targets only staging directories created by that invocation. A forced process termination may leave temporary staging directories, but does not expose a partly copied destination.

On NOVA, verify a clean test installation, the directory layout, script/documentation contents, cleanup, and the displayed execution examples. Re-run against an existing test directory containing an `Output/` sentinel file and confirm refusal without changes. Also test invalid refs, unavailable downloads, and denied destination permissions. Do not use an existing investigation directory for installation testing.

## Current scripts

The following five inventory/audit scripts are standalone, read-only collectors intended for Windows PowerShell 5.1. They use built-in Windows commands, modules, and .NET APIs only. The state-changing team scripts are documented separately below.

The short filenames below are generated by the installer; they are not separate source files in a repository checkout.

| Original script | Installed root copy | Parameters | Reports |
| --- | --- | --- | --- |
| `Inventory/Get-SystemInventory.ps1` | `system.ps1` | `-OutputDir` | `summary.txt`, `inventory.json` |
| `Inventory/Get-NetworkInventory.ps1` | `network.ps1` | `-OutputDir` | `summary.txt`, `network.json`, `listeners.csv`, `running-services.csv` |
| `Audit/Get-UserAudit.ps1` | `users.ps1` | `-OutputDir` | `summary.txt`, `users.json`, `accounts.csv`, `privileged-members.csv` |
| `Audit/Get-PersistenceAudit.ps1` | `persistence.ps1` | `-OutputDir` | `summary.txt`, `persistence.json`, `entries.csv` |
| `Audit/Get-SecurityEventTriage.ps1` | `events.ps1` | `-Deep`, `-Hours`, `-OutputDir` | `summary.txt`, `events.json`, `events.csv` |

The user audit uses the built-in ActiveDirectory module when available for domain-controller collection. The security event triage script defaults to the last 24 hours; `-Deep` enables its additional deep-mode queries.

Reports are written to a unique timestamped directory under `Output/<Hostname>/` when run from this repository. When a script is copied and run independently, its output is placed alongside the script under `Output/<Hostname>/`. `-OutputDir` overrides the output root. If the requested location cannot be used, scripts attempt a temporary-directory fallback and report the actual location.

See [COMMAND-CHEATSHEET.md](COMMAND-CHEATSHEET.md) for executable examples.

## Windows Team Scripts

These five approved files are imported byte-for-byte from the contributors below. The installer preserves these source paths and creates identically named standalone copies in the installation root. Run them manually from an elevated Windows PowerShell 5.1 session after `cd C:\CCDC`; installation itself executes none of them. Their outputs do **not** follow the inventory/audit `Output/` convention.

| Filename / preserved source | Purpose | Original contributor and repository |
| --- | --- | --- |
| [fireme-v2.0.ps1](Firewall/fireme-v2.0.ps1) | Firewall rules and policy backups | [Enhan540 / CCDCTesting](https://github.com/Enhan540/CCDCTesting), [original source](https://github.com/Enhan540/CCDCTesting/blob/main/fireme-v2.0.ps1) |
| [pcr.ps1](Passwords/pcr.ps1) | Reset privileged/high-exposure AD user passwords | [Tausetii / CCDC-tings](https://github.com/Tausetii/CCDC-tings), `PCRs/pcr.ps1` |
| [pcra.ps1](Passwords/pcra.ps1) | Reset AD administrator-account passwords | [Tausetii / CCDC-tings](https://github.com/Tausetii/CCDC-tings), `PCRs/pcra.ps1` |
| [restore_passwords.ps1](Passwords/restore_passwords.ps1) | Set known baseline AD passwords from CSV input | [Tausetii / CCDC-tings](https://github.com/Tausetii/CCDC-tings), `PCRs/restore_passwords.ps1` |
| [WIN_SSH.ps1](SSH/WIN_SSH.ps1) | Install/configure OpenSSH Server and its firewall rule | [nosodium / yesodium](https://github.com/nosodium/yesodium), `WIN_SSH.ps1` |

### Active directory firewall script

`fireme-v2.0.ps1` supports Client and Domain Controller workflows in an Active Directory environment. It requires Windows PowerShell 5.1, Administrator privileges, and the built-in NetSecurity firewall cmdlets. Running it without a report-only or modify switch applies changes immediately; there is no `-Preview` or `-WhatIf` mode.

Retain console or out-of-band access before running it and review the intended network scope.

Run an auto-detecting workflow:

```powershell
cd C:\CCDC
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1
```
> DC workflow will create baseline inbound AD firewall rules for local subnet and disable others. Client workflow will disable all inbound. Backups will be created before and after modification.

Run the Domain Controller workflow using the default `LocalSubnet4` scope:

```powershell
cd C:\CCDC
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Role DC
```

Run it with an explicit authorized client network:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Role DC -ClientNetworks '192.168.1.0/24'
```

The Domain Controller workflow creates or updates 13 inbound AD Allow rules covering DNS, Kerberos, LDAP, SMB, RPC, dynamic RPC, NTP, and Global Catalog services. It then disables other enabled local inbound rules. Group Policy rules may remain effective, and services such as SSH, RDP, and WinRM may require separate accommodation.

To update remote scopes on existing managed AD rules:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Modify -ClientNetworks '192.168.1.0/24'
```

Full runs create before/after firewall policy backups and readable reports under `C:\CCDC\FirewallBackups`. Modify runs create before/after modification backups and reports. The script prints a `netsh advfirewall import` rollback command; rollback is not automatic.

### Password reset scripts

`pcr.ps1` and `pcra.ps1` require the ActiveDirectory PowerShell module, domain connectivity, and rights to reset the targeted AD accounts. Neither has mandatory explicit parameters. Both accept `-ExcludeUsers`, `-OutFile`, `-IncludeSPNAccounts`, and `-ForceChangeAtLogon`; both implement `-WhatIf` and high-impact confirmation prompts.

```powershell
cd C:\CCDC
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\pcr.ps1 -WhatIf
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\pcra.ps1 -WhatIf
```

`pcr.ps1` selects users through its existing privileged/exposure group list and `AdminCount=1`; `pcra.ps1` selects administrator groups and the domain RID-500 Administrator. Both skip `krbtgt` by default, the executing username, disabled accounts, and SPN-bearing accounts unless `-IncludeSPNAccounts` is supplied. Group lookups use English names and can be skipped with warnings. These are AD-account operations, not local-account reset tools. Resetting service-account passwords can disrupt dependent services.

Applying runs create **plaintext password records** at `C:\Secure\pwreset_<timestamp>.txt` (`pcr.ps1`) or `C:\Secure\admin_pwreset_<timestamp>.txt` (`pcra.ps1`) unless `-OutFile` overrides the path. Output lines are headerless `account, password` records, not the restore script's CSV schema. The scripts use embedded word lists for generated passphrases, modify the output directory's ACL with `icacls`, and initialize the selected output file with overwrite behavior. Choose a unique output path and protect these records; never commit them to this repository.

### Restore known passwords

`restore_passwords.ps1` also requires the ActiveDirectory module, domain access, and appropriate reset/unlock rights. It sets passwords to a **known baseline**; it cannot recover unknown previous passwords. Use either:

- `-BaselineCsv <path>`: mandatory CSV columns `Username,Password`, containing each account and its known plaintext baseline password.
- `-BaselinePassword <securestring>` with an optional `-ResetLog <path>`: the reset-log CSV must have a `Username` column. If `-ResetLog` is omitted, the script searches for the newest `C:\Secure\pwreset_*.csv`.

```powershell
cd C:\CCDC
.\restore_passwords.ps1 -BaselineCsv 'C:\Secure\baseline.csv' -WhatIf
$baseline = Read-Host 'Known baseline password' -AsSecureString
.\restore_passwords.ps1 -ResetLog 'C:\Secure\reset-targets.csv' -BaselinePassword $baseline -WhatIf
```

The reset scripts' default `.txt` records are **not directly compatible** with either restore input. Renaming a TXT file to CSV does not supply the required header or validate its contents; prepare and review correctly formatted input separately. Restore supports `-WhatIf`, confirmation prompts, and `-ClearForceChange`; an applying run also attempts to unlock each account. It reports to the console and does not create a standard inventory report. It is intended for controlled baseline restoration, not automatic rollback of prior passwords.

### Windows SSH

`WIN_SSH.ps1` has no script parameters or `-WhatIf` mode. Run it only when SSH configuration changes are approved, with administrator privileges in Windows PowerShell 5.1. It installs/configures OpenSSH, starts and restarts `sshd`, and configures automatic startup:

```powershell
cd C:\CCDC
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WIN_SSH.ps1
```

For builds 17763 and later it uses the Windows OpenSSH capability, with a DISM fallback that needs an available capability source. The legacy path downloads the x64 Win32-OpenSSH package from GitHub, installs under `$env:ProgramFiles\OpenSSH`, invokes that package's `install-sshd.ps1`, and changes its working directory. It does not require or execute `HardenTest.ps1`, `HardenTest2.ps1`, `MockDCPt1.ps1`, or `MockDCPt2.ps1`.

It replaces the named `OpenSSH-Server (TCP-In)` rule and creates an inbound TCP 22 Allow rule for all profiles without a source-address restriction. It edits `$env:ProgramData\ssh\sshd_config` in place: matched directives enable password/keyboard-interactive authentication and disable public-key authentication. Missing or differently formatted directives are not inserted, so verify the effective configuration. Output is console progress, not `Output/` reports. Legacy setup may need GitHub connectivity; native capability installation may need Windows feature-source access. The separate barebones firewall script's initial setup disables other enabled local inbound rules, including this SSH rule.

### Provenance and redistribution

The following approved SHA256 values were verified before import. Files retain their exact upstream bytes, filenames, parameters, prompts, and output paths; upstream limitations were documented rather than patched.

| Imported file | SHA256 |
| --- | --- |
| `Firewall/fireme-v2.0.ps1` | `BEC1EB85402EDC181EB3AAF127CCBC8AF18AD0DF799D959CE4088F87888C06D6` |
| `Passwords/pcr.ps1` | `09f6e600788419b10c734a32f5fcc17545d1b6ad347bc6c69807dda8159b93ac` |
| `Passwords/pcra.ps1` | `b7536d3e2e59c6f786c0610494fc779a033fa69f7c37b0cd35c36fd9ad17ec57` |
| `Passwords/restore_passwords.ps1` | `17f815732156f00421e97a221b4036af20f89b091ddd263a83ebf08b13c9df8b` |
| `SSH/WIN_SSH.ps1` | `b8e40eced52cf6087dd1a59aabeaff7e2c4f7139e65871f0d6027a43a1397e9d` |

The CCDC-Windows maintainer has explicitly confirmed that contributors from Enhan540/CCDCTesting, Tausetii/CCDC-tings, and nosodium/yesodium authorized inclusion and redistribution of their scripts in CCDC-Windows for the team's CCDC practice. This permission resolves the integration's contributor-permission requirement; it does not imply that the upstream repositories have adopted a general open-source license. No GitHub-recognized license was reported during integration, and no license grant appears in these script headers.

## Network Inventory v0.1 baseline

The initial tested baseline was executed successfully on a Windows Server 2025 domain controller in Kamino. Testing covered script execution, network configuration collection, TCP listeners, running services, firewall profiles, and successful report generation.

Outstanding validation includes Windows client testing, non-elevated execution, and comprehensive output validation.
