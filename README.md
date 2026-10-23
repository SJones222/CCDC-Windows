# Windows CCDC PowerShell Toolkit

A small, specification-driven toolkit for Windows CCDC inventory, auditing, and explicitly requested remediation tasks. Scripts target Windows PowerShell 5.1 and use only built-in Windows capabilities.

## Directory structure

```text
Inventory/    Read-only system inventory scripts
Audit/        Read-only security and configuration audit scripts
Remediation/  Explicitly requested remediation scripts
Tests/        Tests for implemented behavior
```

## Quick Install

Use Windows PowerShell 5.1. The default installation destination is `C:\CCDC`. Git and third-party modules are not required. The command below downloads and executes `Install-CCDC.ps1` from `main`, which then downloads the complete repository ZIP over HTTPS. Review and trust the repository code before running it. The repository and selected branch must be accessible without authentication; this installer does not handle credentials.

Production bootstrap (available after the installer is merged into `main`):

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

See [Current scripts](#current-scripts) for parameters and report filenames, and [COMMAND-CHEATSHEET.md](COMMAND-CHEATSHEET.md) for further execution examples.

### Testing the installer

To use an installer already saved locally with a clean test destination:

```powershell
.\Install-CCDC.ps1 -Destination 'C:\CCDC-InstallTest'
```

To test before merging, first publish the reviewed `deployment-test` branch, then run this one-line bootstrap. Both the installer and ZIP come from that branch; the production default remains `main`.

```powershell
& { $ccdcTls = [Net.ServicePointManager]::SecurityProtocol; try { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/SJones222/CCDC-Windows/deployment-test/Install-CCDC.ps1' -ErrorAction Stop).Content)) -Ref 'deployment-test' -Destination 'C:\CCDC-InstallTest' } finally { [Net.ServicePointManager]::SecurityProtocol = $ccdcTls } }
```

`-Ref` selects a repository branch. Installation validates the five scripts, README, contribution rules, and installer before copying the complete snapshot, including hidden tracked files. Empty `Remediation/` and `Tests/` directories and `Output/` are created if absent. The prepared installation is renamed into place only after all preparation succeeds. Failures before promotion leave a new destination absent; preexisting destinations are left untouched. Cleanup targets only staging directories created by that invocation. A forced process termination may leave temporary staging directories, but does not expose a partly copied destination.

On NOVA, verify a clean test installation, the directory layout, script/documentation contents, cleanup, and the displayed execution examples. Re-run against an existing test directory containing an `Output/` sentinel file and confirm refusal without changes. Also test invalid refs, unavailable downloads, and denied destination permissions. Do not use an existing investigation directory for installation testing.

## Current scripts

All scripts are standalone, read-only collectors intended for Windows PowerShell 5.1. They use built-in Windows commands, modules, and .NET APIs only.

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

## Network Inventory v0.1 baseline

The initial tested baseline was executed successfully on a Windows Server 2025 domain controller in Kamino. Testing covered script execution, network configuration collection, TCP listeners, running services, firewall profiles, and successful report generation.

Outstanding validation includes Windows client testing, non-elevated execution, and comprehensive output validation.
