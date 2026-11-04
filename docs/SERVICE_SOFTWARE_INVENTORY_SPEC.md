# Service and Software Inventory — Module Specification

Status: **Milestone 1.1 draft — architectural review required; no implementation authorized.**

Normative baseline: [Assessment Development Standards](ASSESSMENT_STANDARDS.md).
All choices below are proposed for review, not changes to existing collectors.

## 1. Identity and scope

- Script: `Inventory/Get-ServiceSoftwareInventory.ps1`.
- Proposed `ModuleId`: `service-software-inventory`; initial `Version`: `0.1.0`.
- Proposed first released `SchemaVersion`: `0.1.0`, subject to approval. The standards
  document's illustrative `0.1.0-proposal` value is not a released schema.
- Standalone Windows PowerShell 5.1, initially tested in 64-bit Windows 10/11 and
  Windows Server 2016+. No shared modules, external runtime packages, elevation,
  remote targets, installation, or configuration changes.
- Inventory only: `Assessment.Status = NotPerformed`, `Findings = []`. No service
  security analysis, vulnerability enrichment, reputation lookups, scoring, or
  remediation. No existing script, schema, teammate hash, or installer change.
- Only proposed explicit parameter: optional `[string]$OutputDir`, with the standard
  output-root semantics. Limits below are reviewed constants, not new switches.

### Included sources

| Dataset ID | Required | Approved scope proposed for this module | Source |
| --- | --- | --- | --- |
| `Services` | Yes | Every service returned, including stopped, manual, and disabled services; no state/start-mode filter | One local `Get-CimInstance Win32_Service` query |
| `InstalledSoftware` | Yes | Direct registration subkeys in both HKLM uninstall registry views; preserve duplicates and unnamed registrations | Read-only .NET registry access, `Registry64` and `Registry32` |
| `NetworkEndpoints` | No | IPv4/IPv6 TCP listening endpoints and bound UDP endpoints, used for optional process discovery/correlation | One `Get-NetTCPConnection -State Listen` and one `Get-NetUDPEndpoint` query |
| `Processes` | Yes | All observed running-service PIDs are required targets; additional endpoint-derived PIDs are optional enrichment | Targeted local `Win32_Process` queries |
| `ExecutableFiles` | No | Bounded file metadata, SHA256, and native Windows signature results for unambiguously resolved executables | Local file/.NET APIs and `Get-AuthenticodeSignature`; signature network-policy gate below |

“All services” means the `Win32_Service` inventory, including returned per-user
service instances; no separate driver inventory or service-template expansion.
The proposed network scope deliberately excludes established TCP connections and
remote endpoint data. These scope interpretations require review, not assumption.

Software source in each view is
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`. Enumerate direct
subkeys, reading only `DisplayName`, `DisplayVersion`, and `Publisher`. Record the
view explicitly; it is the registration view, not proof of application architecture.
Do not filter out Microsoft entries, updates, duplicates, or absent display names.
Absent values are null with `MissingValueNames`; an absent parent key is a successful
empty source. Access/query errors are not empty results.

Excluded: HKCU/other-user hives, AppX/MSIX, Windows features/updates outside these
registrations, portable software discovery, recursive disk scans, loaded DLLs,
service DLL resolution, credentials, and software-to-service ownership inference.
Registry registrations are not a complete list of every installed application.
Never query `Win32_Product` or execute uninstall strings or collected commands.

## 2. Collection flow and association limits

1. Verify a restricted output destination under the protection rules below, then
   snapshot services, both registry views, and both endpoint protocols independently.
   Do not reuse prior reports or rely on another collector having run.
2. Build a PID-to-many-service index from services whose observed `State` is
   `Running` and `ProcessId > 0`. Preserve actual PID values, including zero for
   stopped services; zero is not an unknown value or a process-enrichment target.
3. Select every distinct positive running-service PID, then a bounded additional set
   from available endpoints. Query only selected PIDs for `ProcessId`, `Name`,
   `CreationDate`, `ExecutablePath`, and `CommandLine`.
   Do not request command lines for every other process. Batch numeric PID filters;
   no process-owner/token queries, process-memory reads, or privilege adjustment.
4. Preserve process creation time where available. Services, endpoints, and processes
   are sampled at different times: exits and PID reuse are possible. Associations
   are explicitly `PID-only, non-atomic`, never proof of service socket ownership.
   Preserve raw source PIDs even if the target disappears. Compare process creation
   time with source query windows: creation after the source query completed flags
   `PossiblePidReuse`; overlapping windows or missing creation time cannot exclude
   reuse. No timestamp comparison proves ownership. Do not add retry loops.
5. Resolve configured service executable paths conservatively. Build file candidates
   from resolved configured paths for **all** services and observed process paths.
   Deduplicate normalized absolute paths case-insensitively, preserving all references.
   This does not imply identical paths/content across hard links or during the run.

No corresponding service is a valid outcome for a network process. Preserve an
empty `RelatedServiceIds` array; do not guess service names or assign a host process's
endpoint to one service in a shared PID. These are local table queries, not scans
or outbound connection attempts. An empty association array confirms no observed
match only when service enumeration completed; otherwise association coverage is
unknown and must be reported as such.

### Required process scope versus optional discovery

- `Processes.Status` evaluates running-service targets only. If service enumeration
  and these process queries complete, endpoint failure does **not** downgrade it:
  retain required process results, mark endpoint coverage unavailable/failed, and
  show optional discovery/correlation as incomplete. Required module status can
  remain `Success` and exit `0` when software collection/reporting also succeeds.
- Additional endpoint-derived rows have `RequiredForCollection: false`. Their query
  failures, partial fields, and budget skips affect optional coverage only. They
  cannot substitute for missing required process coverage. A PID also observed for
  a running service is queried once and always has `RequiredForCollection: true`.
- Partial service enumeration makes required target coverage partial, even if all
  known PIDs were queried. If Services is `Unavailable`/`Failed` without usable
  coverage, Processes inherits that status with null count/empty items; do not query
  additional endpoint targets under an unknown required scope. Preserve their PIDs
  in NetworkEndpoints and mark their enrichment skipped by prerequisite.
- Finish required process work before additional targets. If required process work
  yields `Unavailable`/`Failed` without usable results, skip additional work so
  optional rows do not mask or contradict the required dataset status. Successful
  empty queries for disappeared targets are usable but incomplete coverage, not
  fabricated process records.

Required process status is calculated before optional rows are added:

| Required process outcome | Processes.Status |
| --- | --- |
| Services completed; all running-service targets returned with requested metadata | Success |
| Services completed; no positive running-service targets | Success, zero required records |
| Some required process results/empty query coverage are usable, but targets, fields, or service selection are incomplete | Partial |
| Service selection is Partial with no known targets to query | Partial, zero required records; unknown total |
| No usable process coverage and all required queries are blocked by prerequisites/access | Unavailable |
| No usable process coverage and any required query unexpectedly fails | Failed |
| Service enumeration is Unavailable/Failed without usable coverage | Inherit that status; no process enrichment |

A successful service-selection query alone does not make a wholly denied/failed
process query usable. Optional endpoint/process successes cannot rescue those cases.

### Raw command lines versus executable paths

- `Services.RawCommandLine` is the exact available `Win32_Service.PathName` string.
  `Processes.RawCommandLine` is the actual process command line, not its service
  configuration. Never substitute one for the other or call either a bare file path.
- A configured executable can be resolved from a properly closed leading quoted
  absolute executable path, or an unquoted absolute executable token with no spaces.
  Require a clear executable boundary. Do not search for the first existing prefix
  of an ambiguous unquoted path, infer a service's current directory, or search PATH.
- Allow only unambiguous Windows system-root expansion/normalization. Service-account
  environment variables must not be expanded using the caller's user environment.
  Relative paths, malformed quoting, and ambiguous command strings remain unresolved.
- A running process's provider-reported executable path is separate evidence, not
  proof of the configured service binary. Never execute a string to resolve it.
- Reject UNC/device paths, mapped network drives, and paths with reparse-point
  components before content inspection. Unknown locality is skipped, not assumed
  local. Do not follow shortcuts, junctions, or symbolic links into arbitrary targets.

## 3. JSON datasets and exact item schemas

Use the standards envelope unchanged: module/schema versions, run GUID, hostname,
UTC start/completion times, `Collection`, `Assessment`, and `Output`.
Each dataset has `Id`, `Required`, `Status`, `Count`, `Items`, and `Limitations`.
Module-specific `Coverage` is an array of `{SourceId, Required, Status,
QueryStartedAt, QueryCompletedAt}` objects. Statuses use the standard four values;
timestamps are UTC or null if no query ran. Windows are observations, not atomic
snapshots. `Required` identifies which source/stage controls its containing dataset.

Source IDs include `Win32_Service`, `Registry64`, `Registry32`, `TCPListeners`,
`UDPEndpoints`, `ServiceProcessTargets`, and `AdditionalEndpointTargets`. Software and endpoint dataset status
aggregate their two required sources using the standards' required-dataset algorithm.
Process coverage separates required `ServiceProcessTargets` from optional
`AdditionalEndpointTargets`; `Processes.InputStatus` separately records `Services`
and `NetworkEndpoints` status strings as diagnostic prerequisites, not usable process
query results for aggregation. Optional
endpoint loss must not propagate into required process status. Missing required
service-target coverage must not be reported as complete. Processes.Status aggregates
its required Coverage entries only; optional partial rows can coexist with required
Success. This is an explicit internal required/optional boundary, not suppression
of optional failures. NetworkEndpoints itself still aggregates both protocol sources.

`Collection.BudgetUsage` contains `ServiceProcesses`, `AdditionalProcesses`, `Files`,
`Hashes`, and `Signatures`. Each has integer `AttemptedCount`, `CompletedCount`,
`UnusableCount`, and `SkippedCount`, plus nullable integer `CandidateCount`.
For a known candidate set, candidates equal attempted plus skipped, and attempted
equals completed plus unusable. Completed means usable operation results, including
partial metadata and definitive negative facts, not complete coverage or a positive
security result. Unknown candidate scope uses null, never zero. Skips and failures
are separated in issues;
counts refer to observed candidates, not an inferred machine-wide total.
Also record `HashBytesRead` and `FilePhaseElapsedSeconds`, and applied limits in
`Limitations`. File-stage counters cover selected file candidates; the file count
separately records paths omitted before enrichment. Files.CandidateCount counts
safe, resolved, deduplicated paths before the 256-path cap; resolution/locality
exclusions are counted separately per source record, not invented unique files.

Types: `string?`/`integer?` allow null; other fields are non-null. PID values are
unsigned 32-bit integers serialized as numbers. Timestamps are UTC ISO 8601 strings.
All listed fields are present; arrays remain arrays at zero/one/many items.
No native CIM objects or raw exception objects enter reports.

Each retained item has `Id: string` and `RecordStatus: Success|Partial`. IDs are unique
within a dataset/run. Entirely unusable records become issues, not fictitious items.
`Unavailable`/`Failed` datasets have `Count: null`, `Items: []`; issues preserve the
failed source/target identity. Known missing files can be retained as negative facts.

### Services

| Fields | Type / meaning |
| --- | --- |
| `Id`, `Name` | Strings; ID is `service:<Name>`; original service name/case is preserved |
| `DisplayName`, `State`, `StartMode`, `ServiceAccount` | `string?`; preserve provider values; service account is `StartName`, not a discovered credential |
| `ProcessId` | `integer?`; retain zero when returned |
| `RawCommandLine` | `string?`; exact configured command, restricted JSON only |
| `RawCommandLineState` | `Collected`, `Empty`, or `Unavailable`; preserve an actual empty string, not a guessed value |
| `ExecutablePath` | `string?`; resolved configured executable, no arguments; null if unresolved |
| `PathResolution` | `Resolved`, `Unresolved`, or `Unavailable` |
| `ProcessRecordId`, `FileRecordId` | `string?`; references only to retained records, otherwise null |
| `ProcessAssociationStatus` | `UnconfirmedPidMatch`, `PossiblePidReuse`, `NotReturned`, `Unavailable`, or `NotApplicable` (no running-service target) |

Successful source collection does not become a failure merely because a configured
path cannot safely be resolved. Keep the raw command and explicit resolution state.
Unreadable expected provider fields produce a partial record/collection; a null
derived file reference does not itself downgrade service enumeration.

### InstalledSoftware

| Fields | Type / meaning |
| --- | --- |
| `Id` | String `software:<RegistryView>:<SubkeyName>` |
| `Name`, `Version`, `Publisher` | `string?`; respectively `DisplayName`, `DisplayVersion`, `Publisher`; no inferred vendor/version |
| `RegistryHive` | String `HKLM` |
| `RegistryView` | `Registry64` or `Registry32` |
| `RegistryKey`, `SubkeyName` | Strings; full source key and original immediate subkey name |
| `MissingValueNames` | String array of absent approved values, not failed value reads |

Absent registration values are recorded absence, not query failures. A denied or
failed value read yields a partial retained registration if its key identity is
known, null affected values, and a structured issue; do not label it merely absent.
Identical names/versions in two views remain two records.

### NetworkEndpoints

| Fields | Type / meaning |
| --- | --- |
| `Id` | String `endpoint:<sequence>`; sequential within the run after sorting protocol/address/port/PID |
| `Protocol`, `EndpointType` | `TCP`/`Listening` or `UDP`/`Bound` |
| `LocalAddress`, `LocalPort`, `ProcessId` | `string?`, `integer?` (0–65535), `integer?`; preserve unavailable fields as null |
| `RelatedServiceIds` | String array; all matching running-service IDs, not port owners |
| `ProcessRecordId` | `string?`; retained process record if available |
| `AssociationBasis` | String `PID-only, non-atomic` |
| `ServiceAssociationStatus` | `UnconfirmedPidMatch`, `NoObservedMatch` (complete service enumeration), or `Unknown` |
| `ProcessAssociationStatus` | `UnconfirmedPidMatch`, `PossiblePidReuse`, `NotReturned`, `Unavailable`, or `Skipped` |

Preserve every returned endpoint, including repeated tuples; do not call UDP a TCP
listener. Missing required endpoint fields produce a partial record, not guessed data.

### Processes

| Fields | Type / meaning |
| --- | --- |
| `Id`, `ProcessId` | String `process:<PID>` and positive integer; PID identity is run-local, not durable |
| `Name`, `ExecutablePath`, `RawCommandLine`, `CreatedAt` | `string?`; observed process metadata; command line is JSON only |
| `RawCommandLineState` | `Collected`, `Empty`, or `Unavailable` |
| `RequiredForCollection` | Boolean; true for an observed running-service PID, false for an additional endpoint-derived PID |
| `SourceKinds` | String array from `RunningService`, `TCPListener`, `UDPEndpoint` |
| `RelatedServiceIds`, `EndpointIds` | String arrays referencing source records; include all PID matches |
| `FileRecordId` | `string?`; retained executable-file record if available |
| `AssociationStatus` | `UnconfirmedPidMatch` or `PossiblePidReuse`; missing creation time never proves PID identity |

`Processes.TargetOutcomes` separately preserves each observed target's `TargetId`
(`process:<PID>`), integer `ProcessId`, boolean `RequiredForCollection`, nullable
`ProcessRecordId`, and `Outcome`: `Returned`, `PartialMetadata`, `NotReturned`,
`Unavailable`, `Failed`, or `Skipped`. This diagnostic array is not counted as Items
or duplicated in processes.csv. It distinguishes a disappeared/inaccessible target
from a returned process with null fields; issues give specific skip/failure reasons.
Keep all observed source PIDs, even targets omitted by a budget. Where required
service selection is unknown, do not label unmatched endpoints definitively optional;
retain them only in NetworkEndpoints until that prerequisite is available.

Record targeted-but-exited/inaccessible PIDs in issues using `RecordId: process:<PID>`.
Do not retry indefinitely, infer missing paths/arguments, or substitute a different
process. A retained PID/name with inaccessible requested metadata is partial.
If required PID queries succeed but expected targets are not returned, use `Partial`
(possibly zero retained required records) and `ProcessNotReturned` issues. An exit
is a possible cause, not a fact inferred from a missing row. Access-denied queries
are `Unavailable`, not confirmed exits. No required targets plus complete service
enumeration is required-scope `Success`/zero, regardless of endpoint availability.
If optional rows are retained, Count includes those items; their scope is explicit.

IDs and references are scoped by `(RunId, DatasetId, Id)`, not durable cross-run
identifiers. Preserve source key/name strings exactly. Assign endpoint sequence IDs
once with original source ordinal breaking equal-tuple ties; do not collapse repeats.
Assign file IDs from the full observed sorted candidate list before applying budgets.
Null references indicate no retained target row, not proof that no process/file exists.
All non-null references must resolve within this report; never join runs by PID alone.

### ExecutableFiles (optional enrichment)

| Fields | Type / meaning |
| --- | --- |
| `Id`, `Path` | Strings; `file:<sequence>` after path sorting, absolute local path |
| `SourceRefs` | Array of `{DatasetId, RecordId}` for all contributing services/processes |
| `FileState` | `Present` or `Missing`, when known |
| `LengthBytes`, `LastWriteTimeUtc` | `integer?` (64-bit byte count), `string?` |
| `FileVersion`, `ProductVersion`, `CompanyName`, `ProductName` | `string?`; version-resource strings, not verified publisher identities |
| `MetadataStatus`, `HashStatus` | `Collected`, `Unavailable`, `Failed`, or `Skipped`; operation outcomes, not dataset statuses |
| `SHA256` | `string?`; 64 uppercase hex characters only after a complete successful hash |
| `SignatureMode` | `NotInvoked` or `WindowsNative`; never claim offline verification without an enforced mechanism |
| `SignatureStatus` | `Unsigned`, `Valid`, `Failed`, `Unavailable`, or `Skipped`; mapping below |
| `NativeSignatureStatus`, `NativeSignatureType` | `string?`; preserve native results/type when exposed; null when absent or no invocation |
| `SignerSubject`, `SignerThumbprint` | `string?`; public certificate metadata only; no certificates/private keys exported |

No version resource is a valid absence, represented by null fields. A missing
executable is a collected negative fact, not evidence that a service is malicious.
Do not export file contents or hash a truncated prefix. When files change during
collection, preserve usable metadata, clear the hash, and report `FileChanged`.
Disk metadata/hashes do not attest to the bytes already loaded in process memory.

### Native Windows signatures and the unresolved network-policy gate

Use **`Get-AuthenticodeSignature -LiteralPath`**, delegating verification to Windows.
Account for embedded and Windows catalog signatures through that native behavior;
when both exist, the cmdlet prefers the catalog signature. Do not manually build
certificate chains, parse signatures, implement a trust engine, enumerate catalogs,
or introduce a custom native wrapper. Do not treat missing signer/type metadata
alone as proof that a file is unsigned.

| Native result | `SignatureStatus` | Meaning |
| --- | --- | --- |
| `Valid` | `Valid` | Windows accepted the checked signature under current trust policy, not a safety/malware finding |
| `NotSigned` | `Unsigned` | Native verification reported no signature; not inferred from null certificate fields |
| `HashMismatch`, `NotTrusted`, `NotSupportedFileFormat`, `Incompatible` | `Failed` | Verification did not validate; preserve native reason, not a malicious label |
| `UnknownError`, missing capability, access denied, or unresolved trust availability | `Unavailable` | No reliable verification conclusion |
| Unexpected invocation/processing error | `Failed` | Operation failed; native result may be null |
| Not invoked because of policy, limits, missing file, or unsupported path | `Skipped` | Reason required; `SignatureMode = NotInvoked` |

**Implicit network requests are possible:** Windows trust evaluation may retrieve
certificate-chain/revocation data. PowerShell 5.1 exposes no offline-only parameter.
Being native, running without internet, or observing a warm-cache test does not
guarantee that the same call cannot attempt network retrieval later.

This conflicts with the current no-network collector boundary. **Fail-closed proposal:
do not invoke signature verification under that boundary; report `Skipped` with
`SignatureNetworkPolicy`, preserve other file metadata/hashes, and expose incomplete
optional enrichment.** Before implementation, approve either that reduced signature
coverage or a narrowly defined permission for native trust retrieval. This draft
does not grant that exception. Do not alter firewall, revocation settings, certificate
stores, or machine networking to make verification work. No offline trust wrapper
or substitute certificate-extraction implementation is proposed.

If native retrieval is explicitly permitted later, signature acceptance testing must
record that policy and observe cold/warm-cache behavior on an isolated test host.
Signature invocation limits below still apply; native calls have no hard timeout
parameter, and failure to conclude trust must remain visible.

## 4. Exact proposed budgets and their semantics

Enumerate service records, direct uninstall registrations, and optional endpoint
tables once, without a record cap or retries. This preserves all returned source
rows, not an assurance of bounded provider runtime. Remove the prior **512-PID cap**
on required service processes: it would arbitrarily omit core DC coverage.

| Budget | What it limits / deterministic selection | Omissions and status effect |
| --- | --- | --- |
| All distinct running-service PIDs; **no count cap** | Required process collection; numeric PID order, one query attempt per PID | No count-based omissions; unavailable fields/queries affect required Processes status |
| **128 additional PIDs** | Optional process enrichment only; endpoint PIDs not already in the observed service set, ascending numeric order | Remaining PIDs are Skipped outcomes with `LimitReached`; optional AdditionalEndpointTargets is Partial, not required Processes status |
| **32 PIDs per CIM query** | Batch size/WQL length only; consecutive ordered PIDs, required and optional batches kept separate | No omitted PIDs from batching; a failed batch affects only its required/optional scope |
| **30 seconds per CIM operation** | Requested `-OperationTimeoutSec` for CIM calls supporting it, increased from 10 seconds to reduce premature failure on loaded DCs | Not a run deadline or a timeout for NetTCPIP cmdlets; timeout without results is Failed, some usable query coverage is Partial; no retries |
| **256 distinct executable paths** | Optional metadata candidates; running-service paths first, other configured-service paths second, additional-network paths last; ordinal case-insensitive path order within groups | Unselected paths counted in Files.SkippedCount; null file references and issues retain source identity; optional ExecutableFiles is Partial if any usable coverage |
| **64 MiB per file** (67,108,864 bytes) | Hash eligibility and, if allowed, signature eligibility; use known length, not prefix hashing | Oversize/unknown-size candidates are Skipped with reason; no hash/signature value fabricated; optional file coverage incomplete |
| **512 MiB total hash reads** (536,870,912 bytes) | Bytes actually consumed by streamed SHA256 attempts, including failed attempts; same selected-file order | Skip a file larger than remaining bytes and continue with smaller eligible files; count skipped hashes; optional file coverage incomplete |
| **16 signature invocations** | Optional native verification, only if network-policy gate is resolved; eligible selected files in the same order | Further eligible files Skipped; count policy/budget skips separately; optional file coverage incomplete |
| **60 seconds file-phase scheduling budget** | Shared optional metadata/hash/signature phase, measured monotonically; metadata pass first, then hashes, then signatures | Stop starting work/check between hash chunks; unfinished hash is discarded; unattempted operations counted as skipped, optional file coverage incomplete |
| **10 process preview rows; 10 issue preview messages** | Terminal presentation only; processes sorted required-first/PID, issues by dataset/stage/code/record ID | Show omitted-preview counts; JSON/CSV/TXT records/statuses are not truncated by these presentation limits |

MiB means 1,048,576 bytes. Eligibility/cap/time skips are mutually assigned one
primary reason in each operation's accounting; later limits do not double-count
the same skipped attempt. Record every observed candidate's omission in TargetOutcomes
or file issues, including its source reference. Limits do not delete service,
software, or endpoint source rows. Network candidate totals are unknown, not zero,
when endpoint coverage is unavailable; only known returned targets can be counted.

`BudgetUsage` plus issues/Limitations must expose candidates, attempted/completed/
unusable/skipped counts, skip reasons, actual hash bytes, and elapsed file-phase
time. A process that was queried but not returned is unusable, not budget-skipped.
Paths excluded by locality/resolution are separately counted and never stat/read
remotely. No total is inferred for unenumerated sources.

Stream hashes without loading entire files, exclusive locks, or blocking writers.
Recheck size/modification time before/after hashing and signature verification;
invalidate results if change is observed. These checks cannot prove atomic file
identity or detect every change. No truncated hash is ever a SHA256 result.

The **512 MiB budget covers hash reads only**, not PE/version metadata or Windows
signature/catalog I/O. Native trust may reread/hash files; its 16-call/size/scheduling
limits do not impose an exact byte or duration limit on that native work. A blocking
file/provider/trust call can exceed 60 seconds; there is no hard end-to-end timeout
or worker/cancellation framework. No broad fallback, parallelization, recursive
dependency scanning, cross-run cache, or additional hash algorithm is proposed.

If a started hash is stopped by the scheduling/byte limit, count it as attempted
and unusable, with HashStatus Skipped and a limit issue; it is not an unattempted
skip. An unsigned or definitively invalid native signature is a completed native
result, not an unusable query. Unavailable/errored verification has no reliable
conclusion. Keep result status separate from these operation counters.

### Domain Controller reliability/overhead review

Large DC endpoint tables and many unique service PIDs can make full enumeration
and required CIM batching slow; this is preferable to silently dropping required
services. Thirty seconds is a timeout request, not a throughput promise. Signature
cache misses may be especially slow; signature work runs last and is policy-gated.
The file/path/byte/time limits will often make optional enrichment Partial on a DC;
operators must not interpret exit `0` as complete hashes or signatures. Skipping
svchost-hosted service DLLs remains intentional: hashing the host executable does
not identify every service implementation. Tune budgets only after measured client/
DC trials, not by adding retries or broad all-process scans.
File enrichment must use a 64-bit PowerShell process on these 64-bit targets;
otherwise mark that optional capability unavailable rather than hash a silently
redirected System32 path. Do not auto-relaunch. Required registry-view/CIM facts
can still be retained, with the unsupported file-host limitation visible.

## 5. Status, failures, and data protection

- Apply the approved four collection statuses. Successful empty enumeration is
  `Success`/zero, never a fifth `Empty` status. `Unavailable` identifies missing
  capabilities/access; `Failed` is a collection failure with no usable results.
- Per registry/protocol source, preserve usable records despite later errors as
  `Partial`. Missing keys/values and definitive no-match endpoint queries must not
  be misclassified as access failures; use reliable error identities, not message text.
- Missing executable/hash/signature data affects optional `ExecutableFiles`, not
  otherwise complete required service/software collection. Endpoint failures affect
  optional discovery/correlation only. Missing requested fields on a required service
  process affect required Processes; the same failure on an additional endpoint
  process affects its optional coverage only. Record non-elevated limitations.
- A file dataset with usable metadata/negative facts and incomplete enrichment is
  `Partial`. If no facts can be obtained because access is unavailable, it is
  `Unavailable`/null count; unexpected failures without usable facts are `Failed`.
  All work skipped with no usable file facts is `Unavailable`, with explicit missing
  access/eligible-path/policy coverage; do not claim success. Genuine absence of file
  candidates with complete input coverage is `Success`/zero. Unresolved/excluded
  paths and unknown source scope are not proof that there are no candidate files.
- Overall collection status and exits follow the standards: required datasets only;
  optional failures cannot rescue or downgrade required coverage. Reports saved:
  `Success` → `0`, `Failed` → `1`, `Partial`/`Unavailable` → `2`. Required report
  generation failure overrides these as `3`, including failure to write files.csv.
- Every issue has `DatasetId`, `Stage`, `Code`, sanitized `Message`; use optional
  `RecordId` for targets and null `DatasetId` for bundle-wide output failures.
  Collection and output issues remain in separate arrays. Proposed stable codes:
  `CapabilityMissing`, `AccessDenied`, `QueryFailed`, `RecordReadFailed`,
  `ProcessNotReturned`, `PossiblePidReuse`, `PrerequisiteUnavailable`, `QueryTimeout`,
  `PathUnresolved`, `RemotePathSkipped`, `ReparsePointSkipped`, `FileMissing`,
  `FileChanged`, `LimitReached`, `HashFileTooLarge`, `SignatureNetworkPolicy`,
  `SignatureVerificationFailed`, `SignatureUnavailable`, `OutputProtectionUnverified`,
  `ReportWriteFailed`, `ReportVerifyFailed`, `CleanupFailed`.
- Full raw command lines belong in restricted JSON **only**, because they may
  contain secrets. Never repeat them in TXT, CSV, console, exception text, or issues.
  Do not intentionally retrieve passwords, registry credential values, process
  environment blocks, or memory. Redaction cannot be guaranteed by simplistic
  argument-name matching; do not claim sanitized command lines are still raw.
- Keep reports local until explicit removal; no uploads, commits, or automatic
  retention deletion. Require an appropriately restricted destination, including
  fallback, without changing ACLs or system policy. Sanitize separate sharing copies.

### Fail-closed command-line/report protection

Verify report protection **before collecting raw command lines or writing report
content**, including temporary publication files. The destination must be local and
non-reparse. Use native ACL inspection with SID values, not network name resolution.
Proposed conservative allowlist: the executing user's SID, Local System, and BUILTIN
Administrators. Verify directory owner/DACL and the inherited DACL of empty, newly
created temporary files. Reject a null/unreadable DACL, an unexpected owner, or an
Allow entry granting another principal read/write/control access. Do not try to
prove broad Allow entries safe through deny-rule/group-membership analysis: uncertain
access fails verification. This is conservative inspection, not a new ACL evaluator.

If the requested destination cannot be positively verified, record the sanitized
`OutputProtectionUnverified` output issue and try a fresh temporary fallback with
the same checks. Do not infer protection from a TEMP path or from successful writes.
Do not modify ACLs, elevate, or silently publish redacted/metadata-only reports in
the unverified location. If neither location is verifiably restricted, publish no
reports/raw strings and return **`3`** with a concise protection error. The operator
can separately prepare a private destination and rerun; this module does not do so.

Recheck directory/file protection at publication; loss of verification stops writes,
triggers cleanup of invocation-owned incomplete files, and permits only a freshly
verified fallback. Never touch existing reports. Cleanup failure must be reported
without echoing source values. A published JSON includes module-specific
`Output.ProtectionStatus: VerifiedRestricted`, describing the check at publication,
not a promise against privileged attackers or subsequent ACL changes. Command-line
fields are never repurposed to store error messages: use null plus
`RawCommandLineState: Unavailable`; actual empty strings use `Empty`.

This may force fallback for a normally readable `C:\CCDC` installation or cause a
report failure on an inherited shared directory. False negatives are safer than
leaking raw arguments. Support for additional authorized team SIDs is a separate
policy decision; there is no automatic AD-group lookup or new parameter here.

## 6. Output files and presentation

Default: `Output/<Hostname>/ServiceSoftwareInventory_<yyyyMMdd-HHmmssfff>/` using
standard repository/standalone detection and collision handling. `-OutputDir`
overrides the root; fallback root is `<system temp>/CCDC-ServiceSoftwareInventory`.

Required report set (even when a collection is unavailable):

| Filename | Exact CSV columns, or purpose |
| --- | --- |
| `summary.txt` | Detailed human-readable inventory, coverage, sanitized issues, and report directory |
| `service-software.json` | Canonical full structured report, published last |
| `services.csv` | `Id,Name,DisplayName,State,StartMode,ServiceAccount,ProcessId,RawCommandLineState,ExecutablePath,PathResolution,ProcessRecordId,ProcessAssociationStatus,FileRecordId,RecordStatus` |
| `software.csv` | `Id,Name,Version,Publisher,RegistryHive,RegistryView,RegistryKey,SubkeyName,MissingValueNames,RecordStatus` |
| `network-endpoints.csv` | `Id,Protocol,EndpointType,LocalAddress,LocalPort,ProcessId,RelatedServiceIds,ServiceAssociationStatus,ProcessRecordId,ProcessAssociationStatus,AssociationBasis,RecordStatus` |
| `processes.csv` | `Id,ProcessId,Name,ExecutablePath,RawCommandLineState,CreatedAt,RequiredForCollection,SourceKinds,RelatedServiceIds,EndpointIds,AssociationStatus,FileRecordId,RecordStatus` |
| `files.csv` | `Id,Path,SourceRefs,FileState,LengthBytes,LastWriteTimeUtc,FileVersion,ProductVersion,CompanyName,ProductName,MetadataStatus,HashStatus,SHA256,SignatureMode,SignatureStatus,NativeSignatureStatus,NativeSignatureType,SignerSubject,SignerThumbprint,RecordStatus` |

One CSV row per retained JSON item in the corresponding dataset; array cells use
compressed JSON strings inside normal CSV escaping. No items means headers only;
read JSON status to distinguish an empty collection from unavailable data. Processes
Count equals all retained Items; `RequiredForCollection` and Coverage distinguish
required service rows from optional additional rows. Required scope can be empty
while optional rows exist; never describe that as an empty overall process inventory.

TXT lists all retained service/software/process/file records with clear sections;
endpoint details remain complete in JSON/CSV with an aggregate TXT overview. Do not
print raw arguments. Console shows host/run identity, all dataset statuses/counts,
running/stopped/disabled service counts, target/enrichment coverage, a maximum of
ten process preview rows (PID/name only), limitations/issues, save outcome, directory,
and the PID-association disclaimer. Limit console issue previews to ten sanitized
messages, with total issue counts and references to complete JSON/TXT issue lists.
Display required versus optional process coverage separately, plus candidate/skip
counts and native-signature policy status. Counts under incomplete coverage are
retained observations, not inferred totals; never print unavailable counts as zero.

Write supporting reports through invocation-owned temporary files, canonical JSON
last, then verify publication as specified in the standards. Use fresh fallback,
cleanup only invocation-owned incomplete files, and verify output independently of
the JSON success field. No new manifest, launcher, schema framework, or installer
mapping is introduced here; final machine-readable discovery remains deferred.

## 7. Testable acceptance criteria

### Synthetic/static tests required before acceptance

1. PS 5.1 parser and `git diff --check` pass. Source checks reject `Win32_Product`,
   remote queries, command execution, service/registry setters, automatic elevation,
   and network-download helpers. Mocks assert only approved sources/fields queried.
2. Fixtures containing running/stopped/disabled services retain every record and
   zero PID correctly; shared PIDs relate to multiple services without ownership
   claims. Endpoint-only processes retain empty service arrays only as a no-match
   under completed service coverage; otherwise association is Unknown. UDP is Bound.
3. Registry fixtures span both views, duplicates, missing parent keys, absent values,
   denied keys/values, malformed records, Unicode, and CSV-special characters. Source
   provenance and record counts remain correct; neither view silently disappears.
4. Path fixtures include quoted paths, simple unquoted paths, ambiguous spaces,
   relative/user-dependent paths, and UNC/reparse cases. Unsupported paths are not
   guessed or read. Configured command lines never overwrite observed process data.
5. PID fixtures cover duplicate targets, exits, inaccessible fields, missing CIM
   capability, unexpected query failures, creation-time mismatches, and cap boundaries.
   More than 512 running-service PIDs must not be truncated. Only selected PIDs
   receive command-line queries; repeat PIDs are queried once; source PID/zero and
   creation-time values survive serialization. TargetOutcomes distinguish not-returned
   (possible exit), denied, failed, and skipped targets; references resolve or are null.
6. File fixtures cover known hashes, zero-byte files, no version resource, missing/
   denied files, shared paths, budget boundaries, changes during hashing, and skipped
   operations. No partial hash is published. Test exactly-at/one-over 128 additional
   PIDs, 32-sized batches, 256 file candidates, 64 MiB file eligibility, 512 MiB actual
   hash reads, 16 native calls, 60-second scheduling, and 10-row/message previews.
   Assert deterministic order, accounting identities, skip reasons, and status scope.
   Mock native Valid/NotSigned/verification failure/unknown error/access-denied results;
   a policy skip must never call Get-AuthenticodeSignature. No custom trust fallback.
7. Status matrix: complete empty sources → required `Success`, known zero counts,
   exit `0`; usable required results plus a failed source → `Partial`, exit `2`;
   all required prerequisites missing → `Unavailable`, null counts, exit `2`;
   all required collection attempts fail without usable results → `Failed`, exit `1`.
   Optional endpoint/file failure alone leaves required success/exit `0` but remains
   visible. Services success plus both endpoint queries failed must still permit
   required Processes success after all running-service targets complete.
8. A successful empty required dataset plus failed required datasets is overall
   `Partial`, not wholly failed. Unknown required service-target selection cannot
   be Success; complete zero service targets is Success even if endpoints fail.
   Additional-process failures/caps cannot downgrade required Processes, and their
   successes cannot rescue wholly unavailable/failed required process coverage.
9. JSON/CSV counts and all exact column orders match at zero/one/many records.
   Raw command lines appear only in protected JSON; synthetic secret markers never
   appear in summaries, CSVs, console, or issues. Array cells round-trip correctly.
10. Output tests cover repository/standalone paths, arbitrary working directory,
    relative/custom roots, collisions, fallback, failures at each publication stage,
    cleanup failure, canonical JSON written last, and total report failure → `3`.
    Checks verify run identity and all required files, not JSON existence alone.
    ACL fixtures cover inherited broad access, unknown owner/SIDs, unreadable/null
    DACLs, permitted principals, unverified TEMP, and changes before publication.
    Verify fallback before raw queries/content writes; two unverified destinations
    yield no reports and exit 3. Assert no ACL setters, broad-access publication, or
    raw markers in file/cleanup errors. Actual empty strings differ from null fields.

### Real Windows validation required before acceptance

- At least one 64-bit Windows 10/11 client and one Server 2016+ DC, in standard-user
  and elevated Windows PowerShell 5.1 sessions. Record exact versions; other supported
  versions remain untested until exercised. Do not change live services to manufacture
  states; use existing observations and synthetic fixtures for destructive scenarios.
- Compare service and both registry-view inventories with independent read-only
  snapshots; reconcile timing differences. Verify stopped/disabled services and both
  service/network-only process selection where present, plus limited-access outcomes.
- Compare selected file hashes with a separate built-in hash calculation on stable
  files. With the current no-network policy, verify signature checks are Skipped and
  native verification is never invoked. If a native-retrieval exception is approved,
  separately validate signed/unsigned/tampered/catalog-only files and observe cold/
  warm-cache requests under that policy. No inference of globally unsigned from
  absent metadata, or of safety from Valid. No trust-policy changes during testing.
- Confirm raw argument confinement, CSV/JSON consistency, readable TXT, output
  publication, and standalone/custom-root fallback. Observe counts and elapsed time;
  validate enforced limits without claiming a hard end-to-end runtime guarantee.
- Verify a deliberately readable output directory is refused before sensitive
  collection/writes, that verified fallback succeeds, and that an unverifiable
  fallback produces no reports/exit 3. Inspect inherited ACL behavior without
  changing system ACLs automatically. Use a preprovisioned controlled test directory.
- On the DC, record source-query duration, required/optional target counts, batch
  counts, file/hash/native-call counts, hash bytes, elapsed file phase, and skips.
  Review latency and resource impact using existing read-only observations; neither
  the proposed 30-second operation hint nor 60-second scheduling budget is a run SLA.
- Confirm existing scripts/approved hashes and installer mappings remain unchanged.
  No remediation or automatic service/software installation is part of validation.

Tests must use synthetic/sanitized data; real reports stay outside Git. Native
parser/.NET tests need no third-party runtime. Test tooling selection still needs
approval; no Windows tests have been performed for this unimplemented module.

## 8. Decisions required before development

1. **Resolve native signature network policy before implementation:** approve skipped
   signatures under the existing no-network rule, or explicitly authorize possible
   Windows trust retrieval. Native Get-AuthenticodeSignature is the proposed verifier;
   no custom trust engine or offline wrapper is an alternative in this scope.
2. Approve the exact budgets, measurements, and required service-target/optional
   endpoint-target split. Optional coverage may be incomplete despite exit 0. Required
   process work is not count-capped and may run longer on a busy DC.
3. Approve the conservative destination SID/owner policy and fail-closed exit 3
   behavior. Decide separately if extra authorized team SIDs must be supported;
   no broad effective-access evaluator, ACL edits, or new parameters are proposed.
4. Approve the updated item IDs/references, counts/nulls, Coverage/BudgetUsage/
   TargetOutcomes extensions, CSV columns, and initial released schema version.
   The service boundary remains Win32_Service, with no inferred software ownership.
5. Shared helpers, orchestration/discovery, vulnerability enrichment, full cross-
   version infrastructure, and installer distribution remain separate deferred tasks.

## Reference checks

- [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
  and [Win32_Process](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)
  document the selected service/process properties and process-lifetime limitations.
- [Win32_Product](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/msiprov/win32-product)
  documents Windows Installer consistency/repair side effects; it is excluded.
- [Get-AuthenticodeSignature, PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-5.1)
  describes embedded/catalog behavior;
  [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
  documents explicit cache-only network-retrieval controls, which the cmdlet does
  not expose. Native verification is not an offline guarantee. These references do
  not authorize retrieval or claim network/runtime testing of this future module.
