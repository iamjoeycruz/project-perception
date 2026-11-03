# Project Perception

Experimental tools, automation, samples, and documentation for Project Perception.
This repository is intended to grow beyond a single script. The currently
available automation sample is listed below.

> **EXPERIMENTAL - evaluation and testing only.** This sample is provided
> **"AS IS"**, without warranties or conditions of any kind, express or implied,
> including merchantability, fitness for a particular purpose, and
> non-infringement, to the extent permitted by applicable law.
> It is not a production-ready solution, a supported Microsoft product, a
> security certification, or a guarantee of complete agent exclusion.

## Currently available automation

[Exclude-AgentUsersFromDynamicGroups.ps1](automation/Exclude-AgentUsersFromDynamicGroups.ps1)
discovers dynamic groups and previews this rule transformation:

```text
(<entire existing membership rule>) -and (user.agentIdentityBlueprintId -eq null)
```

The intent is to prevent agent over-permissioning through unintended membership
in groups designed for human users. Preserve explicitly approved agent access
and group-based security protections: this is not a blanket exclusion policy.
The original rule's logical grouping is preserved.

This concerns **agent user accounts**, not agent identities that are service
principals. The blueprint ID identifies an associated blueprint, not an
individual agent user. A null blueprint ID alone is not proof that an account
is human.

## Support boundary and release gates

[Microsoft's dynamic membership documentation](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership)
describes the need to explicitly exclude agent user accounts. That does not
establish support for this exact property or coverage when a parent identity
or blueprint has been deleted. Confirm those details with Entra.

These requirements are informational and are not enforced by the script.
Technical validation is required before production deployment. Publication
and licensing approval apply to experimental distribution as well.

| Release gate | Required evidence |
| --- | --- |
| Exclusion support | Entra confirmation of the exact property and coverage, including deleted-parent/blueprint cases. |
| Throttling/recovery | Explicit retry configuration and tests for throttling, exhausted retries, and lost PATCH responses. SDK retry support alone is not validation. Live tenant-scale validation remains required. |
| Live pilot | Evidence that intended humans remain, agents are excluded, membership processing completes, and rollback works. |
| Publication approval | Microsoft-approved licensing, disclaimer wording, and applicable release approvals where required. Current disclaimers do not grant distribution rights. |

Explicit bounded retries and lost-response reconciliation are implemented.
Simulated failure tests validate script behavior, not live tenant-scale
throughput, service behavior, or an SLA.

## Prerequisites

- PowerShell 7.2 or later.
- `Microsoft.Graph.Authentication`.
- Microsoft Graph public cloud (`Global`); other clouds are not supported.
- Appropriate Graph consent and effective Entra authorization.

Preview requires `Group.Read.All`; Apply requires `Group.ReadWrite.All`.
Existing broader read/write directory permissions are accepted where
appropriate, but do not request broader permissions just to run the sample.
Scope checks do not establish effective role assignments, consent, ownership,
administrative-unit restrictions, or PIM activation. Graph enforces actual
authorization.

## Start with read-only preview

Run these commands from the repository root. Replace ID placeholders with
actual tenant/group GUIDs before running.

```powershell
# Install the prerequisite only if it is not already installed.
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Read-only preview; starts process-scoped interactive sign-in if disconnected.
.\automation\Exclude-AgentUsersFromDynamicGroups.ps1 -TenantId '<tenant-id>' -NoMenu

# Expand full group results, rules, manual-review reasons, and next steps.
.\automation\Exclude-AgentUsersFromDynamicGroups.ps1 -TenantId '<tenant-id>' -Details -NoMenu

# Full parameter documentation and disclaimers.
Get-Help .\automation\Exclude-AgentUsersFromDynamicGroups.ps1 -Full
```

Existing Graph connections are validated, not silently switched or upgraded.
Admin consent, MFA, Conditional Access, or explicit write-permission sign-in
may be required.

## Apply only to approved test groups

Use an isolated test tenant or explicitly approved pilot groups. Validate
representative human and agent accounts, including orphaned-account cases,
and obtain change approval first. Apply changes actual group rules and can
affect access, licensing, and security/compliance policy coverage.

```powershell
# Establish the intended tenant and write scope explicitly.
Connect-MgGraph -TenantId '<tenant-id>' -Scopes 'Group.ReadWrite.All' -ContextScope Process

# Preview an approved test-group update without group or backup/audit writes.
.\automation\Exclude-AgentUsersFromDynamicGroups.ps1 `
    -TenantId '<tenant-id>' -GroupId '<pilot-group-id>' -Apply -WhatIf -NoMenu

# Remove -WhatIf only after validation and approval.
.\automation\Exclude-AgentUsersFromDynamicGroups.ps1 `
    -TenantId '<tenant-id>' -GroupId '<pilot-group-id>' -Apply -NoMenu
```

Without `-GroupId`, every eligible discovered dynamic group is in scope.
Each approved update is preceded by a new original-rule backup and durable
audit entry. Paused processing stays paused. Concurrent edits can stop the
run; there is no atomic compare-and-swap. Failures stop processing and do not
automatically undo earlier verified changes.

## Parameters and reporting

| Parameter | Purpose |
| --- | --- |
| None | Read-only summary with manual-review groups and explanations. |
| `-Details` / `-Detailed` | All group results, complete rules, and explanations. |
| `-NoMenu` | Disable the interactive next-action menu. |
| `-TenantId` | Target sign-in and guard against a connection to the wrong tenant. |
| `-GroupId` | Restrict discovery/application to approved group GUIDs. |
| `-Apply` | Apply approved changes after backup and per-group confirmation. |
| `-WhatIf` | Preview Apply without group or backup/audit writes; sign-in may prompt. |
| `-BackupPath` | New original-rule JSON file in an existing restricted directory. |
| `-AuditPath` | New JSONL audit file in an existing restricted directory. |
| `-MaxRetry` | Additional attempts per request, 0-10; default 5. |
| `-RetryDelay` | Initial exponential backoff in seconds, 1-180; default 3. `Retry-After` takes precedence. |
| `-RetryTimeLimit` | Per-request retry window in seconds, 1-3600; default 300. Not an overall run timeout or cancellation of an in-flight request. |
| `-PassThru` | Return structured objects instead of the report; also disables the menu. |
| `-Confirm` | Request confirmation. Use `-Confirm:$false` only after explicit approval. |

Reruns recognize current stored exclusions without appending them again.
**A saved/read-back rule does not prove membership processing has completed
or that all agent accounts are excluded.** The sample uses Graph v1.0 and
does not use beta completion APIs. Verify actual membership and processing
status in Entra. Timing guidance is not an ETA or SLA.

For throttling, the script honors `Retry-After`. Transient GET failures can
retry; PATCH retries automatically only on 429, after a concurrency recheck.
Uncertain PATCH responses are reconciled by exact read-back rather than blind
write replay. SDK retries are temporarily disabled and restored in `finally`.
Do not run other Graph operations concurrently in the same PowerShell process.
`-WhatIf` still adjusts/restores this local retry setting.

## Protect runtime data

**Do not commit or publicly share generated backups, audits, exports,
transcripts, or tenant-bearing screenshots.** They can contain tenant/group
identifiers, caller metadata, membership rules, local paths, and errors.
The audit defaults to the Desktop, which may be redirected or synchronized.
Use approved restricted storage via `-BackupPath` and `-AuditPath`.

The included `.gitignore` excludes common runtime and credential files,
including JSON/JSONL outputs. It is not a security control and does not cover
every custom filename. Review every file before committing.

Backups contain original rules, not membership snapshots or an automatic
undo. Restore only after checking that no subsequent authorized changes will
be overwritten, then validate resulting membership.

## License and responsibility

The code in this repository is distributed under the [MIT License](LICENSE).
The experimental disclaimer is not itself a license and does not expand
Microsoft support commitments or modify applicable service agreements.
You are responsible for reviewing, testing, approving, and monitoring changes
in your environment. Publishing through a personal account does not itself
establish product support or waive applicable publication approvals.
