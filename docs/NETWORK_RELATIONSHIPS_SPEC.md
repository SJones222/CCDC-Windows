# Network Relationships — Module Specification

Status: **Approved for implementation — Milestone 1.3; Windows validation pending.**

Baseline: [Assessment Development Standards](ASSESSMENT_STANDARDS.md). Reuse the
design conventions in [Service and Software Inventory](SERVICE_SOFTWARE_INVENTORY_SPEC.md)
and its current implementation; preserve existing scripts, schemas, and installer mappings.
This document specifies one local snapshot collector, not a dependency assessment engine.
CyberForce includes Windows and Linux machines. This Windows collector is one evidence
source for a future environment-wide correlation component. Numeric endpoint addresses,
ports, protocol/state, UTC observation windows, and explicit uncertainty remain portable
core evidence; Windows PIDs, scope IDs, interfaces, and service names remain source-local.
Linux collection, cross-host correlation, and dependency assessment are deferred.

## 1. Identity, execution, and boundaries

- Script: `Inventory/Get-NetworkRelationships.ps1`; `ModuleId`:
  `network-relationships`; initial `Version` and `SchemaVersion`: `0.1.0`.
  During development use `ReleaseReady: false` and an explicit stage.
- Standalone Windows PowerShell 5.1, initially 64-bit Windows 10/11 and Server 2016+.
  Built-in NetTCPIP, DnsClient, local CIM, and .NET Framework only; probe capabilities
  without installing them. Standard users can run it; denied access remains visible.
- Only proposed parameter: optional `[string]$OutputDir`, an output root with the
  approved relative-path semantics. No host targets, credentials, sampling loop,
  duration switch, or automatic elevation.
- Read local tables only. No scans, probes, DNS/reverse-DNS lookups, neighbor queries,
  packet capture, remote CIM sessions, remote connections, downloads, or configuration
  changes. Never execute collected values. No UDP, listeners, firewall rules, software,
  executable paths, command lines, hashes, signatures, or broad process inventory.
- An observed connection is evidence of a local TCP endpoint and its reported peer
  during the query window. It is not proof of an architectural dependency, application
  protocol, traffic volume, authenticated user, remote process, or remote machine identity.
  Absence means only "not observed in this snapshot," never "no dependency."
- Local/remote identify endpoint perspective, not initiator/responder. Established
  connections alone do not reliably identify who initiated them; v0.1 reports
  `Initiator: Unknown` for every row. No direction guesses from port numbers.
- No cross-machine joining, graph building, expected-architecture comparison, risk
  scoring, vulnerability checks, or remediation. `Assessment.Status: NotPerformed`,
  `Findings: []`. Later correlation must be separately designed and approved.

## 2. Sources and collection sequence

Verify protected output first. Take one connection query, then independent IPv4/IPv6
configuration queries, followed by bounded optional context. Each source has its own
UTC start/completion window; record receipt time on each connection. No retry or
second connection snapshot. Configuration can change between queries.

| Dataset | Required | Local source and scope |
| --- | --- | --- |
| `TCPConnections` | Yes | One `Get-NetTCPConnection -State Established`; preserve every returned observation, including repeated tuples and same-host pairs. Preserve returned state even if it changed during enumeration. |
| `LocalAddresses` | Yes | `Get-NetIPAddress` once per family; all returned addresses/prefixes, including loopback and disconnected interface assignments. Required because incomplete local-address knowledge weakens relationship interpretation. |
| `Interfaces` | No | `Get-NetIPInterface` once per family; IP-interface alias, index, connection state, and interface metric. Include loopback/virtual/disconnected entries returned; no separate hardware inventory. |
| `DnsServers` | No | `Get-DnsClientServerAddress` once per family; ordered configured server lists per interface. Configuration only, not evidence of DNS use or resolver reachability. |
| `Routes` | No | `Get-NetRoute -PolicyStore ActiveStore` once per family; preserve full returned current routing table, including default/on-link routes and metrics. No persistent-store duplication. |
| `Processes` | No | Targeted `Win32_Process` queries for selected positive connection PIDs; request only `ProcessId,Name,CreationDate`. |
| `Services` | No | Targeted `Win32_Service` queries for the same selected PIDs, filtered to currently running services; request only `Name,DisplayName,State,ProcessId`. Preserve every match, including shared PIDs. |

IP configuration covers the default network compartment; do not use
`-IncludeAllCompartments`. TCP scope is the local provider view, without an assumed
compartment ID. Containers, nondefault compartments, NAT, proxies, VPNs, and virtual
networking can make endpoint/address comparisons incomplete. No attempt to inventory
those environments or map an address to a durable machine identity is included.

Keep connection rows even if any supporting source fails. Process and service queries
are independent: a denied process lookup does not prevent the bounded service lookup.
No service or process facts are copied from a previous report or another collector.

## 3. Address interpretation and communication evidence

Preserve original address strings. Parse numeric literals with built-in .NET APIs,
without name resolution. Compare address bytes, not display strings; IPv6 case and
compression differences must not create peers. For comparison only, map IPv4-mapped
IPv6 literals to IPv4. Preserve the provider address family and original spelling.
Normalized strings omit the zone suffix; separate nullable numeric scope IDs preserve
an explicit `%<number>`. Missing zones remain null, not an invented `%0` or interface.

IPv6 link-local identity includes its zone. A zone is local to this host and must
never become a cross-host identity key. Resolve a missing link-local zone only if
the observed local endpoint and address table establish one unique interface;
conflicting, named/unsupported, or ambiguous zones remain unknown. Do not compare
link-local bytes after simply stripping `%...`. Other scoped/unsupported cases
remain unknown unless the comparison is unambiguous; no custom scope engine.

Apply these rules in order, retaining the reason on every connection:

| `Relationship` | Evidence / `RelationshipReason` |
| --- | --- |
| `Unknown` | Unparseable, unspecified, multicast/broadcast, or inconsistent endpoints: `InvalidEndpoint` or `UnsupportedEndpoint`. Preserve available raw fields, issue parsing failures, and never create a peer from them. |
| `SameHostObserved` | Numeric remote loopback, including mapped IPv4 loopback: `LoopbackRemote`. This does not require complete interface enumeration. |
| `SameHostObserved` | Equal normalized local/remote endpoint addresses with compatible, established zones where needed: `EqualEndpointAddresses`. |
| `SameHostObserved` | Remote address matches an observed local assignment, with compatible interface/zone context: `RemoteMatchesLocalAddress`. This also handles traffic between different addresses on this host. |
| `Unknown` | A required zone is missing/conflicting or multiple interfaces cannot be distinguished: `AmbiguousScope`; insufficient local-address coverage: `LocalCoverageIncomplete`; no supported local-interface context: `LocalContextUnknown`. Positive loopback/equality/membership evidence can still be retained under partial coverage. |
| `CrossMachineObserved` | Parsed unicast peer is not loopback or any observed local address; address coverage is complete and the local endpoint maps to the supported local context: `RemoteOutsideObservedLocalSet`. This is qualified snapshot evidence of a nonlocal peer, not confirmed physical-machine identity. |

`LocalAddressIds` preserves the matching address evidence; `LocalInterfaceIds`
lists all matching retained IP-interface records. Never choose
one arbitrarily when an address appears on several interfaces. Missing optional
Interfaces alone need not prevent classification if the required address records
provide an unambiguous interface index. Incomplete address parsing/coverage never
supports a negative membership claim. Scope uncertainty must not become CrossMachineObserved.

These are transparent interpretation outcomes, not collection status values or
security findings. `Unknown` is an acceptable explicit outcome, not a fabricated
empty collection. It does not by itself change a successful TCP source query into
a failed query; source/field failures still affect the appropriate dataset status.
Summaries distinguish observed cross-machine, same-host, and unknown counts.

Routes provide configuration evidence only: retain prefixes, next hops, indices,
route metrics, and interface metrics for review. Do not implement a route-selection
engine, call a per-peer route probe, or assert that a recorded route/gateway carried
an observed connection. Do not associate a configured DNS server with an application
merely because its address or a familiar port appears.

## 4. Process/service context and timing

Deduplicate positive PIDs from retained connections and assign each PID its highest
applicable priority: CrossMachineObserved first, Unknown second, and PIDs appearing
only in SameHostObserved last. Sort numerically within each tier, then apply the
128-PID cap. Both context sources use this same ordered selection. PID zero is retained on its source connection
but is not queried. Missing PID stays null. A connection never disappears because
context was denied, exited, malformed, or budget-skipped.

Retain process creation time where available. Compare it against the connection
query completion and service query windows: a process created after a source window
ended triggers `PossiblePidReuse` for that source association. Otherwise use
`UnconfirmedPidMatch`, even when timestamps overlap or appear compatible. Unknown
creation time cannot exclude reuse. Preserve all original PIDs and query windows.

All connection-to-service associations are `PID-only, non-atomic`, never per-service
socket ownership. A service list may contain several names or none. A complete
successful service lookup with no match means `NoObservedMatch`, not "not a service."
If service coverage is incomplete, an empty association means `Unknown`. Processes
can have no service. Do not infer installed-software ownership or application identity.

`Processes.TargetOutcomes` records every observed positive PID, including omitted
targets: `{TargetId,ProcessId,ProcessRecordId,Outcome,QueryStartedAt,QueryCompletedAt}`.
`TargetId` is `process:<PID>`; outcomes are `Returned`, `PartialMetadata`, `NotReturned`,
`Unavailable`, `Failed`, or `Skipped`. NotReturned means the query completed without
that PID; an exit is possible, not confirmed. Unstarted targets have null query times.
`Services.TargetOutcomes` uses `{ProcessId,Outcome,QueryStartedAt,QueryCompletedAt}`;
outcomes are `MatchesReturned`, `NoObservedMatch`, `Partial`, `Unavailable`, `Failed`,
or `Skipped`. Never store an exception in place of a provider field.

## 5. JSON contract and item schemas

Use the approved envelope: `SchemaVersion,ModuleId,Version,RunId,Hostname,StartedAt,
CompletedAt,Collection,Assessment,Output`, plus development stage/readiness fields.
GUID RunId and UTC ISO 8601 `Z` timestamps bracket observation, not an atomic instant.
Each dataset has `Id,Required,Status,Count,Items,Limitations,Coverage`. Coverage entries
are `{SourceId,Required,Status,QueryStartedAt,QueryCompletedAt}`; source IDs are
`EstablishedTCP`, `IPv4`, `IPv6`, or `ConnectionPidTargets` within their dataset.
The two family sources are required within each configuration dataset, even when
the dataset is optional to the module. Target coverage uses the same status rules.

All item fields below are present. `?` means nullable; arrays remain arrays at
zero/one/many items; `/` separates enum choices in the table. Null means
unavailable/unknown, not zero or false. Valid PID
zero and numeric port zero remain distinct from null. Ports are integers 0–65535;
PIDs/indices are UInt32-compatible numbers. No native objects enter JSON.
Prefix lengths are 0–32 for IPv4 and 0–128 for IPv6; invalid provider values are
reported, not coerced into a plausible prefix or scalar type.
Every item also has `RecordStatus: Success|Partial`. A record needs its minimum
identity (an endpoint pair for connections, interface/address key for configuration,
positive PID for processes, service name and PID for services); entirely unusable
rows become issues. Known endpoint addresses with missing port/PID can be retained
as Partial. Missing requested fields produce nulls and sanitized issues, not defaults.

| Dataset | Exact item fields other than `RecordStatus` |
| --- | --- |
| `TCPConnections` | `Id:string,Protocol:TCP,LocalAddress:string?,LocalPort:integer?,RemoteAddress:string?,RemotePort:integer?,State:string?,ProcessId:integer?,ObservedAt:UTC,ConnectionCreatedAt:UTC?,AddressFamily:IPv4/IPv6/Unknown,LocalAddressNormalized:string?,RemoteAddressNormalized:string?,LocalScopeId:integer?,RemoteScopeId:integer?,Relationship:SameHostObserved/CrossMachineObserved/Unknown,RelationshipReason:string,Initiator:Unknown,LocalAddressIds:string[],LocalInterfaceIds:string[],ProcessRecordId:string?,ProcessAssociationStatus:string,RelatedServiceIds:string[],ServiceAssociationStatus:string,AssociationBasis:PID-only, non-atomic` |
| `LocalAddresses` | `Id:string,InterfaceIndex:integer,InterfaceAlias:string?,AddressFamily:IPv4/IPv6,IPAddress:string,AddressNormalized:string?,ScopeId:integer?,PrefixLength:integer?,AddressState:string?,InterfaceIds:string[]` |
| `Interfaces` | `Id:string,InterfaceIndex:integer,InterfaceAlias:string?,AddressFamily:IPv4/IPv6,ConnectionState:string?,InterfaceMetric:integer?` |
| `DnsServers` | `Id:string,InterfaceIndex:integer,InterfaceAlias:string?,AddressFamily:IPv4/IPv6,ServerAddresses:string[],ServerAddressesState:Collected/Unavailable,InterfaceIds:string[]` |
| `Routes` | `Id:string,AddressFamily:IPv4/IPv6,DestinationPrefix:string,NextHop:string?,InterfaceIndex:integer?,RouteMetric:integer?,InterfaceIds:string[],PolicyStore:ActiveStore` |
| `Processes` | `Id:string,ProcessId:integer,Name:string?,CreatedAt:UTC?,ConnectionIds:string[],RelatedServiceIds:string[]` |
| `Services` | `Id:string,Name:string,DisplayName:string?,State:string?,ProcessId:integer,ConnectionIds:string[],ProcessRecordId:string?,ProcessAssociationStatus:string` |

Process association statuses: `UnconfirmedPidMatch,PossiblePidReuse,NotReturned,
Unavailable,Skipped,NotApplicable` (PID zero). A missing PID uses Unavailable.
Service association statuses: `UnconfirmedPidMatch,PossiblePidReuse,NoObservedMatch,
Unknown,Skipped,NotApplicable`. Apply source-specific reuse evidence consistently.
References only point to retained records; otherwise null/empty arrays with explicit
association status. TargetOutcomes are diagnostics, not extra items or CSV rows.

ConnectionCreatedAt is optional provider creation metadata, never a substituted
observation timestamp. A legitimately absent creation timestamp is null without
failing collection; an unreadable property records an issue. Process CreatedAt is
requested context: inaccessible/null metadata makes that process record Partial.
A collected empty DNS list is `[]`/Collected; a failed list read is `[]`/Unavailable.
Missing optional references or Unknown interpretation do not alone mean a partial
source record. Address normalization failures do, and make local membership coverage
incomplete. Preserve repeated source rows; do not collapse TCP observations into flows.

IDs: `connection:<sequence>`, `address:<sequence>`, `interface:<sequence>`,
`dns:<sequence>`, `route:<sequence>`, `process:<PID>`, `service:<sequence>`.
Sort configuration by family/index/address or prefix/next-hop/metric; connections
by family/normalized local address/local port/normalized remote address/remote port/PID.
Use ordinal string ordering, numeric ports/PIDs, and source ordinal as the last tie
breaker. Assign sequence IDs once, after sorting; they are not cross-run identities.
Sort service observations by name/PID/source ordinal; sequential IDs preserve a
service observed under different PIDs across separate batches without collisions.
All references are scoped by `(RunId,DatasetId,Id)`. Do not join hosts/runs by PID,
interface index, IPv6 scope ID, hostname, or peer address alone.

## 6. Bounded work, status, and issues

| Limit | Selection/accounting and status effect |
| --- | --- |
| One TCP query; two queries per configuration dataset | Nine source calls total, no polling/retries or per-peer calls. Preserve every returned source row; no hidden record cap. Provider time, memory, and report size depend on table size, not a hard run limit. |
| 128 distinct positive connection PIDs | Optional process/service context only; deduplicate, assign highest relationship priority (CrossMachineObserved, Unknown, SameHostObserved), then ascending numeric PID within each tier. Shared PIDs are queried once per context source. Preserve all connection rows and record every omitted PID as Skipped/LimitReached. |
| 32 PIDs per CIM batch; 30-second operation-timeout request | At most four process and four service queries, numeric WQL filters, whitelisted properties. Batching omits no selected PIDs; timeout/failure is not an empty table. NetTCPIP/DnsClient calls have no claimed equivalent deadline. |
| 60-second optional context scheduling budget | Monotonic clock, starts after base tables. For each ordered batch attempt process then service queries; check before starting each call. No further calls after expiry, no cancellation/retry framework. A blocking call may exceed the budget. |
| 20 connection rows in console; 50 in TXT; 10 issue messages in console | Presentation only, cross-machine observations first, then unknown, then same-host; deterministic endpoint order within groups. Show total and omitted-preview counts; JSON/CSV preserve all retained data, TXT retains all sanitized issues. |

`Collection.BudgetUsage.Processes` and `.Services` have nullable `CandidateCount`
and integer `AttemptedCount,CompletedCount,UnusableCount,SkippedCount`, counted per
distinct observed positive PID, not per connection or matched service. CandidateCount
is the distinct target count before the 128 cap only when connection coverage is
complete; otherwise null, even though known targets can be enriched. For a known
scope: candidate = attempted + skipped; attempted = completed + unusable. No double
counting cap/time omissions. Process NotReturned is attempted/unusable; a completed
zero-service match is completed usable coverage. Record `ContextElapsedSeconds` and
limits in Limitations. Unknown source totals are never inferred from retained rows.

Dataset status: Success for completed scope, including genuine zero; Partial for
usable but incomplete source/target/field coverage; Unavailable for missing capability
or access with no usable coverage; Failed for unexpected failure without usable
coverage. Preserve rows emitted before failure. Successful empty subqueries are usable
coverage; both family sources required within their dataset use standard aggregation.
A complete empty TCP source permits Processes/Services Success/zero with no CIM calls;
an unavailable/failed TCP source gives those datasets the same unavailable/failed
prerequisite status and null counts. Partial TCP scope makes target coverage Partial
even if all known PIDs return. Complete queries with only missing process targets
give Processes Partial/zero, not fabricated process records. If all optional work is
skipped before any usable query, use Unavailable; otherwise incomplete usable context
is Partial. Partial/Success counts are retained items; Failed/Unavailable count is
null and Items is []. TargetOutcomes still retain observed target identities.

Overall status aggregates only TCPConnections and LocalAddresses using the approved
algorithm. Optional failures cannot rescue or downgrade core collection. This choice
means successful TCP observations plus unavailable addresses produce overall Partial,
while preserving those observations and qualified positive same-host evidence.
Use standard exit codes 0/1/2 for saved Success/Failed/(Partial or Unavailable);
required report failure takes precedence as 3. Exit 0 does not certify every optional
context source, remote-machine identity, or architectural completeness.

Issues require `DatasetId,Stage,Code,Message`, with optional `RecordId`/source identity.
Use separate Collection.Issues and Output.Issues. Stable codes include CapabilityMissing,
AccessDenied, QueryFailed, QueryTimeout, RecordReadFailed, InvalidAddress, AmbiguousScope,
PrerequisiteUnavailable, ProcessNotReturned, PossiblePidReuse, LimitReached,
OutputProtectionUnverified, ReportWriteFailed, ReportVerifyFailed, CleanupFailed.
Identify genuine no-match errors by validated PowerShell error IDs/category, not
English text or every ObjectNotFound. Do not suppress real errors or serialize raw
exceptions, stacks, account information, or command lines into diagnostics.

## 7. Reports, privacy, and publication

Default: `Output/<Hostname>/NetworkRelationships_<yyyyMMdd-HHmmssfff>/`, collision
suffixes without overwrite. Detect standard Inventory layout using repository markers;
otherwise Output is alongside the script, including installed-root copies. Resolve
relative overrides against caller working directory. Fallback root:
`<system temp>/CCDC-NetworkRelationships`, with host/script-labeled unique run folders.

All nine files are required even for unavailable datasets; empty CSVs retain headers.
CSV columns below are exact and ordered; one row per retained dataset item. Array
cells use compressed JSON within normal CSV escaping. Blank nullable CSV cells are
interpreted with JSON/status fields, not as numeric zeros.

| Filename | Purpose / exact columns |
| --- | --- |
| `summary.txt` | Concise host/run identity, observation windows, AT A GLANCE statuses and counts, up to 50 connections with interpretation/process/service references, interface/address/DNS/default-route overview, limitations and all sanitized issues. Label previews and refer to complete JSON/CSV inventories. |
| `network-relationships.json` | Canonical full envelope and all datasets/coverage/targets/issues, published last. |
| `connections.csv` | `Id,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ObservedAt,ConnectionCreatedAt,AddressFamily,LocalAddressNormalized,RemoteAddressNormalized,LocalScopeId,RemoteScopeId,Relationship,RelationshipReason,Initiator,LocalAddressIds,LocalInterfaceIds,ProcessRecordId,ProcessAssociationStatus,RelatedServiceIds,ServiceAssociationStatus,AssociationBasis,RecordStatus` |
| `addresses.csv` | `Id,InterfaceIndex,InterfaceAlias,AddressFamily,IPAddress,AddressNormalized,ScopeId,PrefixLength,AddressState,InterfaceIds,RecordStatus` |
| `interfaces.csv` | `Id,InterfaceIndex,InterfaceAlias,AddressFamily,ConnectionState,InterfaceMetric,RecordStatus` |
| `dns-servers.csv` | `Id,InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses,ServerAddressesState,InterfaceIds,RecordStatus` |
| `routes.csv` | `Id,AddressFamily,DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,InterfaceIds,PolicyStore,RecordStatus` |
| `processes.csv` | `Id,ProcessId,Name,CreatedAt,ConnectionIds,RelatedServiceIds,RecordStatus` |
| `services.csv` | `Id,Name,DisplayName,State,ProcessId,ConnectionIds,ProcessRecordId,ProcessAssociationStatus,RecordStatus` |

Console stays concise: hostname/run/time window; dataset statuses/known or unknown
counts; three relationship counts; bounded connection/issue previews; context skips;
PID/dependency/initiator caveats; externally verified save status and actual directory.
Do not count remote addresses or connection rows as distinct machines or dependencies.

Protect all reports as sensitive topology/process inventory. Reuse the current
collector's practical policy, including its reviewed ancestor distinction:

- Before collection, verify local non-reparse destination and empty temporary files.
  Report owner/DACL allow only executing-user SID, SYSTEM, and BUILTIN Administrators;
  reject unknown/broad effective allows, null/unreadable DACLs, or uncertain protection.
- Ordinary ancestors may have legitimate Windows servicing ownership (including
  TrustedInstaller) and normal read/traverse access. Still reject meaningful
  untrusted replacement/control risks. TrustedInstaller is not added to the report
  reader allowlist. No general ACL evaluator, name lookup, ACL edit, or elevation.
- If requested root fails, record a sanitized output issue and try protected TEMP.
  If both fail, collect nothing, publish nothing, and exit 3. TEMP is not implicitly safe.
- Write UTF-8 TXT/CSV to owned temporary files first; canonical JSON last through a
  same-directory temporary file and nonoverwriting rename. Recheck protection and
  readability, parse JSON, and verify module/run identity and every required file.
  Live Output.Status remains Failed until verification. Supporting TXT describes
  publication as pending; surviving artifacts must not claim complete successful save.
- `Output.ProtectionStatus: VerifiedRestricted` describes checked protection, not
  immunity to privileged attackers or later changes. JSON's candidate Success alone
  cannot attest to its own publication. Announce final success externally only after
  verification. Clean only invocation-owned incomplete files; preserve cleanup issues.
  Retry publication using retained data in one fresh protected fallback, without
  re-querying sources; final failure exits 3. No atomic multi-file/power-loss guarantee.
- Retain completed reports locally until explicit removal. No upload, automatic
  staging/commit, retention deletion, or sharing. Sanitize a separate labeled copy
  before authorized sharing; no credentials or command lines are requested at all.

## 8. Worked interpretation: AD observation

**User-supplied observation, not a new test result:** AD at `10.0.26.141` had an
established local TCP endpoint on port `3389` with remote address `10.0.26.157`.
Preserve the actual remote port/PID/timestamps if collected; do not invent them.
With complete local-address coverage showing `.141` local and `.157` nonlocal,
report CrossMachineObserved/RemoteOutsideObservedLocalSet. Display the locally
observed PID, queried process, and every matching service name with uncertainty.

This supports "AD observed TCP communication between these endpoints." The user's
additional knowledge describes AD receiving the connection; the snapshot itself
still reports Initiator Unknown. Port 3389 is not independent proof of RDP, a
specific service, legitimacy, or a required dependency. No remote name lookup occurs.

**Synthetic IPv6 illustration of the reported same-host pattern:** local and remote
addresses both `fe80::abcd%12`, or an equivalent compressed spelling, are one scoped
address on this host. Different ports/PIDs remain separate TCP observations but
classify SameHostObserved/EqualEndpointAddresses; they are not additional machines.
Remote addresses matching another observed local assignment are also same-host
evidence. Reusing only the local address across rows with genuinely different remote
addresses is not sufficient: inspect each remote endpoint. `fe80::abcd%7` versus
`fe80::abcd%12` must not be merged by dropping zones; unclear scope remains Unknown.
The illustration does not supply missing IPv6 values from the actual AD report.

## 9. Tests and Windows acceptance

Before implementation acceptance, define dependency-free synthetic PowerShell tests
using function AST loading/mocked sources, plus Python source/contract checks as in
`Tests/Test-ServiceSoftwareInventory.ps1` and its static companion. Do not dot-source
the production entry point or alter live connections/configuration to manufacture tests.

1. Success/zero/partial-stream/failure/denied/missing-capability fixtures for every
   source, genuine no-match identity versus unexpected ObjectNotFound, independent
   family failures, required/optional aggregation, null versus zero, all exit codes.
2. IPv4 loopback range, ::1, mapped loopback, equivalent IPv6 strings, equal scoped
   endpoints, different local NIC addresses, missing/conflicting zones, duplicate
   link-local bytes on different interfaces, invalid/wildcard/multicast endpoints,
   partial address coverage, and unsupported local/compartment context. Assert no
   false cross-machine outcome from scope stripping or missing coverage.
3. Repeated TCP tuples, same-host reciprocal rows, zero/missing PID, no service,
   shared-service PID, process exits, denied fields, missing creation times, and
   possible PID reuse. Assert all source rows/PIDs survive and references resolve.
4. Exactly 128/129 PID targets, 32/33 batch boundaries, deterministic selection,
   pre-first-call/mid-phase scheduling expiry, disjoint cap/time skips, unknown
   candidate totals under partial upstream coverage, and both budget identities.
   High-PID cross-machine targets precede lower-PID same-host targets, including
   more than 128 distinct PIDs; a multi-tier PID receives its highest priority once.
   No full process enumeration, command lines, per-peer calls, or retries.
5. Exact schemas/CSV order and zero/one/many array round trips; all retained rows and
   complete values preserved in JSON/CSV; TXT/console previews identify omitted rows
   and never truncate source data. Synthetic secret markers never enter diagnostics.
6. Repository/standalone/installed-root/custom/relative output, collisions, restricted
   and broad inherited ACLs, legitimate ancestor owners, reparse/network rejection,
   fallback preflight, publication-stage failure, incomplete cleanup, JSON-last
   identity verification, and final failure exit 3. No completed reports deleted.
7. Native Windows PowerShell 5.1 parse/static compatibility, explicit integer enum
   bitwise operations, scalar property types, and correct deserialized array counts.
   Mocked query assertions prohibit DNS resolution, remote sessions, network probes,
   state changes, and imports of external/shared runtime dependencies.

Real validation: record actual OS/architecture/privilege and run on native x64
Windows client and Server/DC, non-elevated and elevated; ARM64 is a separately
recorded additional target. Compare with independent read-only local TCP/configuration
queries, explaining observation-window differences rather than demanding identical
live counts. Verify IPv6 scope behavior, optional denied process context, nine-file
publication, privacy, counts/references, and bounded query/preview behavior. On a busy
DC measure rows, elapsed time, report size, selected/omitted PIDs, batch count, and
resource impact before approving budgets; there is no hard runtime/memory SLA.

**Two-host success criterion:** using an existing, separately authorized application
session, run independent snapshots on both hosts during overlapping recorded windows.
Review the two reports manually for observed reversed endpoint tuples, process context
where accessible, CrossMachineObserved classification, and explicit uncertainties.
Do not create the session from this collector, perform automated report correlation,
or require a match when timing/NAT prevents it. If no qualifying session exists,
record this acceptance test as not demonstrated, not passed. One-sided evidence remains
an observation, not a confirmed dependency. No current Windows execution is claimed.

## 10. Approved decisions and deferred boundaries

1. Approved: the descriptive script name (an explicit standards naming exception),
   module/version/schema identity, seven datasets, nine files, and exact field/null rules.
2. Approved: TCPConnections + LocalAddresses required; process/service/DNS/route/
   interface context optional. Future changes to required scope need separate approval.
3. Approved: snapshot-only evidence, Initiator Unknown, address/zone rules, default-
   compartment limitation, and routing context without route-selection claims.
   Stronger initiation/direction or nondefault-compartment coverage needs new scope.
4. Approved: relationship-prioritized 128 contextual PIDs, 32-PID batches, 30-second CIM hints, 60-second
   optional scheduling, uncapped source tables, and console limits, subject to DC
   validation. A hard source-row/memory/time ceiling requires a separately specified
   truncation/cancellation policy; none is silently introduced here.
5. Approved: the existing restricted SID/ancestor policy without extra team SIDs or
   ACL changes. Distribution/installer integration, shared runtime helpers, output
   discovery, Linux collection, cross-host correlation, dependency assessment, and
   expected-architecture checks remain deferred.

No AGENTS.md rule needs relaxation: all approved collection is standalone, built-in,
local and read-only. Reusing design patterns does not authorize a shared module or
retrofit legacy schemas. Architectural approval authorizes only this Windows module.

## Reference checks

- [Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
  documents current endpoint/state/PID queries, not connection-initiator proof.
- [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress)
  and [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface)
  describe default-compartment coverage unless explicitly expanded.
- [Get-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute)
  documents ActiveStore prefixes/next hops/metrics;
  [Get-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress)
  returns configured server addresses, without requiring a DNS lookup.
- [.NET IPAddress.ScopeId](https://learn.microsoft.com/en-us/dotnet/api/system.net.ipaddress.scopeid)
  explains that link-local zones distinguish interfaces and are part of address context.
  Validate the selected APIs against Windows PowerShell 5.1 during implementation;
  current documentation alone is not a runtime compatibility test.
