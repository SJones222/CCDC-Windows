# Windows CCDC PowerShell Toolkit

A small, specification-driven toolkit for Windows CCDC inventory, auditing, and explicitly requested remediation tasks. Scripts target Windows PowerShell 5.1 and use only built-in Windows capabilities.

## Directory structure

```text
Inventory/    Read-only system inventory scripts
Audit/        Read-only security and configuration audit scripts
Remediation/  Explicitly requested remediation scripts
Tests/        Tests for implemented behavior
```

## Current scripts

All scripts are standalone, read-only collectors intended for Windows PowerShell 5.1. They use built-in Windows commands, modules, and .NET APIs only.

| Script | Parameters | Reports |
| --- | --- | --- |
| `Inventory/Get-SystemInventory.ps1` | `-OutputDir` | `summary.txt`, `inventory.json` |
| `Inventory/Get-NetworkInventory.ps1` | `-OutputDir` | `summary.txt`, `network.json`, `listeners.csv`, `running-services.csv` |
| `Audit/Get-UserAudit.ps1` | `-OutputDir` | `summary.txt`, `users.json`, `accounts.csv`, `privileged-members.csv` |
| `Audit/Get-PersistenceAudit.ps1` | `-OutputDir` | `summary.txt`, `persistence.json`, `entries.csv` |
| `Audit/Get-SecurityEventTriage.ps1` | `-Deep`, `-Hours`, `-OutputDir` | `summary.txt`, `events.json`, `events.csv` |

The user audit uses the built-in ActiveDirectory module when available for domain-controller collection. The security event triage script defaults to the last 24 hours; `-Deep` enables its additional deep-mode queries.

Reports are written to a unique timestamped directory under `Output/<Hostname>/` when run from this repository. When a script is copied and run independently, its output is placed alongside the script under `Output/<Hostname>/`. `-OutputDir` overrides the output root. If the requested location cannot be used, scripts attempt a temporary-directory fallback and report the actual location.

See [COMMAND-CHEATSHEET.md](COMMAND-CHEATSHEET.md) for executable examples.

## Network Inventory v0.1 baseline

The initial tested baseline was executed successfully on a Windows Server 2025 domain controller in Kamino. Testing covered script execution, network configuration collection, TCP listeners, running services, firewall profiles, and successful report generation.

Outstanding validation includes Windows client testing, non-elevated execution, and comprehensive output validation.
