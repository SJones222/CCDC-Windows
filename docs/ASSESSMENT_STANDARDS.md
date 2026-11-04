# Assessment Development Standards

Status: **Approved — Milestone 0**

Applies to new Inventory/Audit collectors after approval. Existing scripts, schemas,
installer behavior, and hash-pinned teammate scripts remain unchanged. “Module”
means a standalone assessment script, not a required PowerShell module.

## 1. Script and execution conventions

- Use `Inventory/Get-<Purpose>Inventory.ps1` or `Audit/Get-<Purpose>Audit.ps1`;
  another descriptive `Get-<Purpose>.ps1` name requires an approved specification.
- Use `#requires -Version 5.1`, `[CmdletBinding()]`, comment-based help, and small,
  readable functions defined within the script. No mandatory shared `.psm1` files
  or third-party runtime dependencies. Collectors must not depend on an engine,
  launcher, or external configuration file.
- Execute independently, noninteractively, and locally. Do not require a working
  directory, internet access, automatic elevation, or installation of components.
- Support optional `[string]$OutputDir` as an output **root**, not a final run folder.
  Resolve relative roots against the caller's working directory and report the
  absolute directory actually used. Validate other parameters and bound expensive
  queries only as approved for that collector; do not add generic switches yet.
- Inventory/Audit scripts may write their reports, but must not change settings,
  services, accounts, permissions, logging, or the collected sources. Never execute
  collected commands, scripts, shortcuts, or uninstall strings.

## 2. Files and output directories

- Require `summary.txt`, one module-specific JSON report, and a CSV for each approved
  tabular dataset. The module specification fixes filenames and columns; a module
  without tabular datasets may explicitly omit CSV. Do not rename legacy reports.
- Use `Output/<Hostname>/<ScriptLabel>_<yyyyMMdd-HHmmssfff>/`. Detect the standard
  repository layout using its category directory and `AGENTS.md`/`README.md` markers;
  otherwise place `Output/` alongside the script, including installed root copies.
- Preserve hostname sanitization and `UnknownHost` when unavailable. Create a unique
  folder without overwriting previous results; use a suffix on collision. Future
  parallel execution must not allow concurrent writers to share a folder.
- If directory creation or report writing fails, attempt a fresh directory under
  the system temporary directory, namespaced by collector and host. Record the
  original failure and fallback use, and display the actual report directory.
- Use UTF-8 text, explicit CSV columns, `-NoTypeInformation`, and tested JSON depth.
  Preserve complete approved data in JSON; flatten CSV without silently dropping
  records. Empty tabular results still produce a header-only CSV.
- Keep the terminal concise: identity/run ID, collection status/counts, review summary,
  collection limitations, save status, and directory. Detailed TXT is navigable;
  label any presentation limits and point to the complete structured records.

## 3. Proposed JSON contract

This is an illustrative instance with synthetic identity/path values, not a JSON
Schema validator or a new implementation. Dataset items and findings require
module-specific definitions; this empty example contains no assessment rules.

```json
{
  "SchemaVersion": "0.1.0-proposal",
  "ModuleId": "example-inventory",
  "Version": "0.1.0",
  "RunId": "11a9ad04-7013-4939-b811-ed8838ad4fa2",
  "Hostname": "EXAMPLEHOST",
  "StartedAt": "2026-11-03T20:00:00.000Z",
  "CompletedAt": "2026-11-03T20:00:01.000Z",
  "Collection": {
    "Status": "Success",
    "Datasets": [
      {
        "Id": "ExampleRecords",
        "Required": true,
        "Status": "Success",
        "Count": 0,
        "Items": [],
        "Limitations": []
      }
    ],
    "Issues": []
  },
  "Assessment": {
    "Status": "NotPerformed",
    "Findings": []
  },
  "Output": {
    "Status": "Success",
    "Directory": "C:\\ExampleReports\\EXAMPLEHOST\\ExampleInventory_20261103-120000000",
    "FallbackUsed": false,
    "Files": ["summary.txt", "example.json", "examples.csv"],
    "Issues": []
  }
}
```

- `ModuleId` is a stable, unique lowercase identifier; changing a filename or root
  shortcut does not change it. `Version` identifies implementation changes;
  `SchemaVersion` independently identifies the reporting contract. Use semantic
  versions for new work; adopt a released schema version only after review.
- Generate a fresh GUID `RunId` per invocation. Use UTC ISO 8601 timestamps with
  explicit `Z`; start/completion bracket collection, not a single atomic snapshot.
  Folder timestamps retain the existing local-clock naming convention. An engine
  may later assign a separate assessment-run ID without changing collector IDs.
- Always serialize dataset `Items`, `Limitations`, `Issues`, and `Findings` as arrays,
  including zero/one items. Use real booleans/numbers and JSON `null` for unavailable
  scalar values, not presentation strings such as `<unavailable>`.
- Declare each dataset's `Required` boolean in the approved specification, not in
  response to runtime failures. At least one dataset must be required.
- `Count` is the retained item count for `Success`/`Partial`, not an inferred total.
  `Success` with `Count: 0` confirms an empty collection within the approved scope.
  For `Unavailable`/`Failed`, use `Count: null` and `Items: []`: no usable collection
  count is known, not a confirmed zero. A `Partial` dataset may retain zero records
  from successful subqueries; total coverage remains incomplete and unknown.
- Record query scope, caps/truncation, and unsupported coverage in `Limitations` as
  applicable. Do not put native CIM, process, or event objects directly into JSON.

## 4. Status and failure semantics

Collection statuses apply to each dataset and to the collection overall:

| Status | Meaning |
| --- | --- |
| `Success` | Approved scope completed, including a genuinely empty result (`Count: 0`). No implication that the host is secure. |
| `Partial` | Usable results exist, but approved coverage is incomplete because of missing fields/sources, parsing limits, failures, or collection caps. Retain usable results. |
| `Unavailable` | A missing prerequisite or required capability, including required access, prevents collection. Explain which prerequisite is missing. |
| `Failed` | Collection or processing failed without usable results; this is not merely an identified missing prerequisite. Explain the failure. |

`Collection.Status` is the overall module collection status, calculated from
**required datasets only**, in this order:

1. All required datasets are `Success`: `Success`.
2. Otherwise, any required dataset has usable results (`Success` or `Partial`):
   `Partial`.
3. Otherwise, any required dataset is `Failed`: `Failed`.
4. Otherwise: `Unavailable`.

A successful empty query counts as usable coverage. This defines sufficient usable
results for aggregation; optional results cannot substitute for required coverage.
Optional dataset failures remain visible in their statuses, issues, and terminal
limitations, but do not downgrade overall status or change the exit code. Never
silently skip a required dataset or present optional coverage as completed.

- Isolate independent queries and per-record parsing. Preserve usable records as
  `Partial`; discard only records that cannot be represented reliably. Missing
  optional fields need explicit null/coverage semantics, not fabricated defaults.
- Use terminating errors where collection needs `try/catch`. Identify expected
  no-match conditions by error identity where practical, not English messages.
- Every issue requires `DatasetId`, `Stage`, `Code`, and a sanitized human-readable
  `Message`. For example: `{ "DatasetId": "ExampleRecords", "Stage": "Collect",
  "Code": "QueryFailed", "Message": "The local query failed." }`. Use a null
  `DatasetId` for report-wide operations, not an invented dataset. Stages identify the
  operation, such as `Prerequisite`, `Collect`, `Parse`, `Write`, `Publish`, `Verify`,
  or `Cleanup`; codes are stable identifiers, not English exception-message matches.
- Put collection issues in `Collection.Issues` and reporting issues in
  `Output.Issues`; emit concise warnings as well. An optional `RecordId` may locate
  a failed record. Do not serialize raw exception objects, stacks, or secret-bearing
  commands into issue messages.
- `Assessment.Status` is `NotPerformed` for inventory-only collection. Future
  approved checks may use `Completed`, `Partial`, or `Unavailable`; `Completed` means
  evaluation finished, not “passed.” Findings must have stable IDs, explanations,
  and dataset/record evidence references. No inferred compliance from missing data,
  arbitrary scores, or automatic malicious/safe classifications.

### Exit codes for new collectors

| Code | Meaning |
| --- | --- |
| `0` | Required collection is `Success` and the complete required report set is saved. |
| `1` | Required collection is `Failed`, without sufficient usable results; reports were saved. |
| `2` | Required collection is `Partial` or `Unavailable`; reports were saved. |
| `3` | Required report generation failed, including after fallback, regardless of collection status. |

Report failure (`3`) takes precedence over collection outcomes. Exit codes summarize
execution, not security findings, and never replace detailed JSON statuses/issues.
PowerShell startup or parameter-binding errors may occur before the script can
enforce these codes or write reports; a caller must recognize that no valid report
was produced. Existing scripts retain their current exit conventions.

### Report publication and external verification

`Output.Status` is `Success` only for a complete required report set, including a
successful fallback; otherwise `Failed`. A JSON file cannot independently attest
to its own successful creation. Its success value describes the intended completed
set and is meaningful only after publication and external verification:

1. In the unique run directory, write supporting TXT/CSV reports to invocation-owned
   temporary files. Close and check them before renaming to their final filenames.
2. Write the canonical JSON last, also through a temporary file in the same directory.
   Include supporting-report results and prior fallback issues. Close it, verify it
   parses, then rename it to its final filename without overwriting an existing file.
3. Check that the canonical JSON and every required report exist and are readable;
   only then announce a successful save, the run ID, and absolute directory. Return
   `0`, `1`, or `2` according to collection status, not merely JSON publication.
4. If any required write/publication/verification fails, remove only this invocation's
   incomplete files, including its published JSON if necessary. Report cleanup
   failures visibly; never treat remaining files as a complete set. Attempt fallback
   in a fresh directory. If it also fails, return `3`; a final JSON may not exist.

An external verifier checks process completion/exit code, the explicitly reported
actual directory, parseable canonical JSON with matching module/run identity, and
all declared required files. `Output.Status: Success` or file existence alone is
insufficient; exit codes `1`/`2` can still accompany a complete diagnostic report.
The machine-readable discovery interface remains deferred. This is ordinary local
temporary-file/rename handling, not a reporting framework or a guarantee against
power loss or external modification.

## 5. Compatibility, privileges, and sensitive data

- Target Windows PowerShell 5.1; initially validate 64-bit Windows 10/11 and Windows
  Server 2016+. Record tested versions rather than claiming universal coverage.
- Probe optional Windows capabilities and report limitations. Do not install them,
  elevate automatically, or require administrator privileges merely to start a
  collector. Test standard-user execution and enhanced elevated coverage separately.
- Avoid machine-specific configuration paths and identities; resolve Windows paths
  from environment/system APIs. Preserve full collected values unless an approved
  data-minimization policy requires omission; document every such omission.
- Treat reports, command lines, configurations, event content, and error messages
  as sensitive.
  Do not collect credential stores, password recovery data, or actual passwords.
  Do not echo secrets in warnings, examples, fixtures, or diagnostic stacks.
- Choose report locations with read access restricted to the executing user and
  authorized team/admin accounts; review inherited permissions, including temporary
  fallback locations. Do not weaken ACLs or change system policy automatically.
  Explain access limitations; changing permissions needs separate approval.
- Retain completed reports locally until explicitly removed. No automatic upload,
  Git staging/commits, or report-retention cleanup. Cleanup of incomplete files and
  temporary publication files is distinct from deleting completed reports.
- Before sharing reports, sanitize a separate copy for secrets, personal information,
  and environment details; preserve the protected original and label any omissions.
  Use only sanitized/synthetic fixtures. Reports are data, not executable content;
  `.gitignore` is not a security boundary, especially for custom output roots.

## 6. Testing and acceptance

Before accepting a new module:

1. Approve its scope, read-only sources, parameters, stable ID, report filenames,
   item/CSV definitions, required/optional datasets, coverage limits, and prerequisites.
2. Run `git diff --check` and Windows PowerShell 5.1 native syntax parsing. Do not
   describe static checks as Windows execution tests.
3. Add focused automated tests under `Tests/` with synthetic, sanitized fixtures:
   success/empty, partial/capped, unavailable/failed, zero/one/many serialization,
   required/optional status aggregation, all four exit codes, minimum issue fields,
   schema/count/CSV consistency, and complete values in detailed reports.
4. Test repository, standalone, and installed-root output behavior; collisions,
   denied writes, fallback, incomplete writes, cleanup failures, and total save
   failure. Verify canonical-JSON-last publication and externally checked completion.
   Mock system queries where practical; never execute collected commands or remediation.
5. Record actual client/server and non-elevated/elevated Windows validation, observed
   limitations, and report review. Untested combinations remain explicitly untested.
6. Confirm unrelated collectors, legacy schemas, installer behavior, and imported
   hashes are unchanged. Test tooling may be introduced only with approval; no
   automatic installation or new runtime dependency is authorized by this document.

## 7. Legacy integration and policy boundaries

- Preserve existing JSON/CSV schemas and execution behavior. A future engine uses
  an explicit read-only allowlist and isolated invocation, not dot-sourcing or broad
  `.ps1` discovery. Firewall, password, and SSH administration are excluded.
- Keep original reports as evidence. An engine-owned adapter may normalize them
  into a separate representation, preserving source status/version and limitations.
  For example, legacy `Empty` maps to new `Success` with zero retained records;
  legacy `Unavailable` with a zero count must not become a successful empty result.
  Legacy exit codes are interpreted per script, not reassigned these new meanings.
- Associate exact report paths with the specific invocation, including fallback;
  never select “the newest JSON.” Defining a machine-readable invocation receipt or
  other discovery interface is a later approved task, not a schema change here.
- `AGENTS.md` rules 2–4 remain binding: shared runtime helpers, third-party runtime
  dependencies, remote collection, or mixed assessment/remediation would conflict.
  Existing AD queries and teammate administration exceptions do not authorize new
  network behavior. Any exception needs explicit approval and policy clarification.
- The proposed `Success`-with-zero convention, `Failed` status, structured issues,
  UTC timestamps, and separate schema version apply only to new work; retrofitting
  them into legacy scripts is outside Milestone 0. Installer mappings are unchanged.

## Deferred decisions and final review

- This envelope, required/optional status policy, publication procedure, and
  new-collector exit codes are approved as Milestone 0 development standards.
- Set future module scope, identifiers, filenames, and item/CSV schemas separately;
  no service/software inventory scope or implementation is approved here.
- Deferred: shared runtime modules/helpers; full orchestration implementation; the
  final machine-readable output-discovery mechanism; automated vulnerability
  enrichment; and comprehensive cross-version testing infrastructure. None is
  authorized by this document. Incremental test tooling remains subject to approval.
