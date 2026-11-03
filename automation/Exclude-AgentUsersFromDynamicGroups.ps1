#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Experimental sample that previews or applies an agent-user exclusion to dynamic user group rules.
.DESCRIPTION
EXPERIMENTAL STATUS
For evaluation and testing only; not production-ready. Provided "AS IS",
without warranties, as detailed in the customer sample disclaimer below.
Use an isolated test tenant or explicitly approved pilot groups. Although
preview is read-only, -Apply modifies actual group rules and can change access,
licensing, and security/compliance policy coverage. Experimental status does
not make these changes harmless or establish Entra support for the property.

WHY RUN THIS SCRIPT
The core intent is to prevent agent over-permissioning through unintended
membership in groups designed to grant access to human users. Agent access
should be explicitly approved and scoped to the work the agent needs to do,
not inherited merely because its user attributes match an employee rule.
Agent user accounts can satisfy existing user-based dynamic membership rules.
Review these rules before provisioning agents to help prevent unintended
group-based access, licensing, or policy assignment. This script discovers
candidate groups and proposes an explicit exclusion while preserving the
original rule's logical grouping. It does not determine your access policy or
prove that a group currently contains agents.
An exclusion is a least-privilege guardrail, not proof that excess permissions
existed or that all access paths have been removed. Preserve intentional agent
access and group-based protections; this is not a blanket exclusion policy.

PREREQUISITES AND AUTHORIZATION
If no Graph connection exists, the script starts interactive sign-in with
Connect-MgGraph using process-scoped authentication in the Global environment.
The interactive menu requests Group.ReadWrite.All at the first sign-in so
preview and a later approved Apply can reuse the same connection. Preview
remains read-only; no changes occur until Apply is selected and confirmed.
Preview-only runs using -NoMenu, -PassThru, or -WhatIf request Group.Read.All.
-Apply requires write permission unless -WhatIf is set.
Supply -TenantId to target a specific tenant; otherwise select the intended
account during sign-in and review the connected tenant in the output.
Existing connections are reused, not silently switched or upgraded. Explicitly
choosing apply in the menu can request a write-permission connection.
Initial sign-in calls Connect-MgGraph only when no connection exists.
Microsoft sign-in can display multiple screens for account
selection, consent, MFA, or Conditional Access. An existing read-only connection
can still require another sign-in when Apply requests write permission. These
requirements cannot be bypassed by this script.
Preview requires
Group.Read.All; applying requires Group.ReadWrite.All. Existing broader
Directory.Read.All or Directory.ReadWrite.All grants are accepted for preview;
Directory.ReadWrite.All is also accepted for apply. Do not request broader
permissions just to run this script. Admin consent is required.

After sign-in, preflight checks permissions reported by Get-MgContext before
any group request or backup. -Apply -WhatIf requires only preview permissions.
Missing or
unverifiable permissions cause a terminating error with reconnection guidance.
Supported connections must expose named Graph permissions in context.Scopes;
sessions exposing only .default or no scopes cannot pass this preflight.
Only the Global (public cloud) Graph environment is supported.

For delegated updates, the signed-in user also needs authorization to manage
the target group's membership rule, for example an active Groups Administrator
role. Activate eligible PIM roles before applying. Scope metadata alone does
not verify token validity, effective consent, directory roles, ownership,
administrative-unit restrictions, licensing, or group-specific authorization.
The script does not read role assignments or request role-reading permissions.
Graph is the authority for actual read/write authorization; a successful GET
does not prove PATCH authorization. Sign-in may display a consent prompt;
the script cannot bypass required admin consent and does not assign roles.

SAFETY AND LIMITATIONS
Defaults to read-only preview. -Apply saves original rules to a new JSON backup
before updating and requests confirmation for each group. -WhatIf performs no
writes, including no backup or audit file creation.
Only membershipRule is updated; paused processing remains paused.
Apply writes an append-only JSON Lines audit file to the current user's Desktop
before the first approved update. Each attempt and outcome is flushed to disk.
Audit failures stop processing; an update may already have reached Graph.
The local log is not tamper-proof and does not replace Entra audit logs.

Device rules, memberOf rules, empty/unknown rules, and rules exceeding 3,072
characters after modification are skipped with warnings. Review every skip.
The exact top-level exclusion produced by this script is not appended twice.
Other rules referencing agentIdentityBlueprintId are skipped for manual review
to avoid changing intentional agent-specific membership.
Concurrent rule/state changes detected before a write stop processing. Graph
does not provide an atomic compare-and-swap here; avoid concurrent editing.
Failures stop the run; earlier successful changes are not automatically undone.
One explicit retry layer handles 429 responses using Retry-After, or exponential
backoff if absent. Transient GET errors can also retry. PATCH is automatically
retried only for 429, after rechecking the original rule and processing state.
SDK retries are disabled temporarily to avoid stacked retries; the prior SDK
MaxRetry setting is restored on exit. Nested menu actions reuse an already
disabled retry setting without resetting the SDK's cached HTTP client.
Apply displays per-group progress through approval, update, and read-back;
the progress display is not evidence of membership-processing completion.
Do not share this process concurrently
with other Graph operations while running the script.
Requests use relative SDK URIs to avoid the SDK's temporary cloud override.
A known stale public-cloud override is repaired before changing retry settings;
the connected tenant, authentication context, and permissions are unchanged.
If a PATCH response is lost or returns a transient server error, read-back
reconciles the outcome instead of blindly repeating the write. Only an exact
dynamic-group rule/state match is considered verified; otherwise the run stops.

Membership recalculation is asynchronous. A successful read-back verifies the
stored rule, not completed membership processing or tenant support for the
attribute. Validate the condition on a pilot group before bulk application.
The script does not call the beta dynamic membership evaluation API.
Reruns inspect current stored rules, not just this run's changes. Saved
exclusions are counted separately from membership completion, which cannot be
verified through the v1.0 properties used here. "On" does not mean complete.
Typical processing is minutes to 24 hours after a rule change, depending on
tenant size/load; this is guidance, not an ETA or SLA. Paused groups need
administrator action. Verify completion and actual membership in Entra.

Run discovery BEFORE provisioning agent user accounts. Preview lists candidate
groups, not proven agent membership. The condition appended is:
(<entire existing membership rule>) -and (user.agentIdentityBlueprintId -eq null)
The blueprint ID identifies an associated blueprint, not an individual user.
No blueprint ID list is required. This targets agent USER accounts, not agent
identities that are service principals.

Exclusions can remove intended access or group-based licenses and can change
security/compliance policy coverage. Do not exclude agents from groups where
their membership is intentional, including groups used to protect agents.
Review group dependencies and obtain change approval before applying.
Backups and exported reports contain tenant configuration; store them securely.
Backups contain original rules, not membership snapshots or an automatic undo.

Microsoft documents that agent user accounts can match dynamic user rules:
https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership
Do not treat that general guidance as confirmation of this property's support
or coverage for accounts whose parent identity or blueprint has been deleted.
Confirm those details with Entra before production rollout. Before applying,
validate representative human and agent accounts (including orphaned accounts)
in Entra's dynamic membership rule validation experience. After applying, wait
for processing and verify actual membership. A null value alone is not proof
that an account is human.
.PARAMETER Apply
Updates eligible rules after backup and per-group confirmation. Without this
switch, returns a read-only preview. Use -WhatIf to preview the apply operation.
.PARAMETER GroupId
Limits discovery and application to these group IDs. Use to restrict testing
to explicitly approved pilot groups. If omitted, discovers all dynamic groups.
.PARAMETER TenantId
Optional tenant ID for automatic sign-in and expected tenant for an existing
connection. Stops before group requests if the connected tenant differs.
Recommended for every experiment to guard against wrong-tenant access.
.PARAMETER BackupPath
New JSON file to hold original rules before any update. Its parent directory
must already exist. Existing files are never overwritten.
.PARAMETER AuditPath
Optional new JSON Lines audit file. Defaults to a timestamped file on the
current user's Desktop, including redirected Desktops. Parent must exist.
If Desktop is unavailable, supply this parameter. Existing files are never
overwritten. No file is created unless an eligible update is approved.
.PARAMETER PassThru
Returns detailed group objects for pipelines instead of displaying the default
summary report. Use with Export-Csv or Format-List for detailed rule review.
Takes precedence over -Detailed.
.PARAMETER Detailed
Expands the summary with every group's result, processing state, original and
proposed rules, the result legend, and reasons/next steps for all skipped groups.
Without this switch, only totals and manual-review groups with their reasons
and next steps are displayed. Alias: -Details.
.PARAMETER NoMenu
Skips the interactive Read-Host menu. Use for unattended execution.
-PassThru also skips the menu. Menu options view all groups in the connected
tenant, apply to explicitly entered group IDs, refresh the current scope, or
exit. Choosing apply may request write permission after read-only sign-in;
required consent and per-group confirmation are not bypassed.
.PARAMETER MaxRetry
Maximum additional attempts per request. Default 5; allowed 0-10.
.PARAMETER RetryDelay
Initial backoff in seconds when Retry-After is absent. Default 3; allowed 1-180.
.PARAMETER RetryTimeLimit
Maximum elapsed retry window per request in seconds. Default 300; allowed
1-3600. This is not an overall run timeout and does not cancel an in-flight
request. If Retry-After would exceed the remaining window, stop rather than
retry sooner than Graph requested.
.OUTPUTS
By default, displays a color-coded summary with manual-review explanations.
Use -Detailed for all group details. Color is supplemental; every result also
has a text label. With -PassThru, returns
objects with Id, DisplayName, OriginalRule, ProposedRule, ProcessingState,
Status, Reason, ReviewCategory, NextStep, RuleSaved, MembershipCompletion,
TimingGuidance, and ResponseRecovered. Skips are classified as
NotApplicable or ManualReview; unchanged rules are AlreadyExcluded.
Preview is a rule-change plan, not a membership evaluation.
.NOTES
CUSTOMER SAMPLE DISCLAIMER
This is an experimental sample for evaluation and testing only, not a
production-ready solution. It is provided "AS IS", without warranties or conditions of any kind,
express or implied, including merchantability, fitness for a particular purpose,
and non-infringement, to the extent permitted by applicable law.
You are responsible for reviewing, testing, approving, and monitoring changes
in your environment. Use a pilot and an approved change/rollback process.
This sample is not a supported Microsoft product, a security certification,
or a guarantee of feature support or complete exclusion of agent user accounts.
This notice does not grant license rights, modify existing agreements, or
expand Microsoft support commitments. Applicable license and agreement terms
continue to govern. External publication requires the publisher's applicable
Microsoft legal, licensing, and release approvals.

RELEASE GATES - STILL NEEDED
This checklist records outstanding release requirements, not completed
validation or approval. It is informational and is not enforced at runtime.
Technical gates apply before production deployment. Publication approval also
applies to experimental distribution through GitHub; an "AS IS" disclaimer
does not establish distribution rights or replace an applicable license.

Exclusion support:
Entra confirmation of the exact property and coverage, including
deleted-parent/blueprint cases.

Throttling/recovery:
Required evidence: Explicit retry configuration and tests for throttling,
exhausted retries, and lost PATCH responses. SDK retry support alone is not
validation.
Explicit bounded retries and lost-response reconciliation are implemented.
Simulated failure tests validate script behavior, not tenant-scale throughput.
Live throttling/recovery validation remains required before production release.

Live pilot:
Evidence that intended humans remain, agents are excluded, membership
processing completes, and rollback works.

Publication approval:
Microsoft-approved licensing, disclaimer wording, and applicable release
approvals. Current disclaimers do not grant distribution rights.
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1 -Details
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1 -TenantId '<tenant-id>'
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1 -Apply -TenantId '<tenant-id>' -GroupId '<pilot-group-id>'
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1 -Apply -WhatIf
.EXAMPLE
.\Exclude-AgentUsersFromDynamicGroups.ps1 -Apply -BackupPath '.\original-rules.json'
Bulk apply example for an isolated test tenant only. Without -GroupId, every
eligible discovered group is in scope.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch] $Apply,
    [switch] $PassThru,
    [Alias('Details')]
    [switch] $Detailed,
    [switch] $NoMenu,
    [ValidateRange(0, 10)]
    [int] $MaxRetry = 5,
    [ValidateRange(1, 180)]
    [int] $RetryDelay = 3,
    [ValidateRange(1, 3600)]
    [int] $RetryTimeLimit = 300,
    [ValidateNotNullOrEmpty()]
    [guid[]] $GroupId,
    [guid] $TenantId,
    [ValidateNotNullOrEmpty()]
    [string] $AuditPath,
    [ValidateNotNullOrEmpty()]
    [string] $BackupPath = (Join-Path (Get-Location) (
        'AgentGroupRules-{0}-{1}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N')
    ))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Write-Host 'EXPERIMENTAL SAMPLE - evaluation/testing only. AS IS; no warranties. Not production-ready.' -ForegroundColor Yellow
$requiresWrite = $Apply -and -not $WhatIfPreference
$requiredScope = if ($requiresWrite) { 'Group.ReadWrite.All' } else { 'Group.Read.All' }
$interactiveApply = -not $NoMenu -and -not $PassThru -and -not $WhatIfPreference
$signInScope = if ($requiresWrite -or $interactiveApply) { 'Group.ReadWrite.All' } else { 'Group.Read.All' }
$context = Get-MgContext
if (-not $context -or -not $context.TenantId) {
    $connectParameters = @{
        Scopes = @($signInScope)
        ContextScope = 'Process'
        Environment = 'Global'
        NoWelcome = $true
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('TenantId')) {
        $connectParameters.TenantId = $TenantId.ToString()
    }
    Write-Host "No Microsoft Graph connection found. Starting sign-in requesting '$signInScope'. Admin consent may be required."
    if ($interactiveApply) {
        Write-Host 'The interactive menu requests write permission now so preview and approved Apply can reuse one connection. Preview remains read-only; Apply still requires confirmation.' -ForegroundColor Yellow
    }
    Write-Host 'Microsoft may display account selection, consent, and MFA screens. The script cannot bypass authentication policy.'
    try {
        $null = Connect-MgGraph @connectParameters
    } catch {
        throw [System.InvalidOperationException]::new(
            "Microsoft Graph sign-in failed or was cancelled. No group reads or changes were attempted. $($_.Exception.Message)",
            $_.Exception)
    }
    $context = Get-MgContext
    if (-not $context -or -not $context.TenantId) {
        throw 'Microsoft Graph sign-in did not establish a tenant context. No group reads or changes were attempted. Retry sign-in with Connect-MgGraph and verify Get-MgContext.'
    }
}
if ($PSBoundParameters.ContainsKey('TenantId') -and [string] $context.TenantId -ne $TenantId.ToString()) {
    throw "Connected tenant '$($context.TenantId)' does not match expected tenant '$TenantId'. Disconnect-MgGraph and reconnect to the intended tenant."
}
if (-not $context.PSObject.Properties['Environment'] -or $context.Environment -ne 'Global') {
    throw 'Only the Global Microsoft Graph environment is supported. Reconnect using Connect-MgGraph -Environment Global for a public-cloud tenant; do not use this script for sovereign-cloud tenants.'
}
$acceptedScopes = if ($requiresWrite) {
    @('Group.ReadWrite.All', 'Directory.ReadWrite.All')
} else {
    @('Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
}
$scopeProperty = $context.PSObject.Properties['Scopes']
$grantedScopes = if ($scopeProperty) { @($scopeProperty.Value) } else { @() }
$matchedScopes = @($grantedScopes | Where-Object { $_ -in $acceptedScopes })
if ($matchedScopes.Count -eq 0) {
    throw "Cannot verify required Microsoft Graph permission '$requiredScope' in Get-MgContext.Scopes. No changes were made. Obtain admin consent, then reconnect, for example: Disconnect-MgGraph; Connect-MgGraph -TenantId '$($context.TenantId)' -Scopes '$requiredScope' -ContextScope Process. Sessions reporting only .default or no named permissions are not supported. For delegated apply, also verify an active authorized Entra role or group ownership; this check does not verify effective write authorization."
}
Write-Host "Tenant: $($context.TenantId). Apply: $Apply. Review skipped groups in the output."
Write-Host "Permission preflight: session reports $($matchedScopes -join ', '). Effective authorization is enforced by Microsoft Graph."
if ($requiresWrite) {
    Write-Warning 'Apply can change access, group-based licensing, and security/compliance policy coverage. Verify active Entra authorization (including PIM where applicable), group dependencies, and change approval. Directory roles and group-specific write access have not been prevalidated.'
}
Write-Warning 'Confirm Entra support and validate representative human and agent accounts before applying. Coverage after parent identity or blueprint deletion is not established by this script.'

$graphSession = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance
$sdkEnvironment = $graphSession.Environment
if ($sdkEnvironment -and $sdkEnvironment.Name -eq 'MSGraphInvokeGraphRequest') {
    if (([string] $sdkEnvironment.GraphEndpoint).TrimEnd('/') -ine 'https://graph.microsoft.com') {
        throw 'The SDK temporary environment does not match the public Graph endpoint. Reconnect explicitly to the intended Global tenant before running this script.'
    }
    $globalEnvironment = Get-MgEnvironment -Name Global
    if (([string] $globalEnvironment.GraphEndpoint).TrimEnd('/') -ine 'https://graph.microsoft.com' -or
        [string]::IsNullOrWhiteSpace($globalEnvironment.AzureADEndpoint)) {
        throw 'Canonical Global SDK cloud metadata is unavailable. Repair the Graph SDK environment before running this script.'
    }
    # Absolute SDK requests can leave an override without an authentication endpoint.
    $graphSession.Environment = $globalEnvironment
    Write-Warning 'Repaired stale Graph SDK public-cloud metadata. The connected tenant, authentication context, and permissions are unchanged.'
}

$auditStream = $null
$retryStatistics = [pscustomobject]@{ Count = 0 }
function Invoke-GroupGraphRequest {
    param(
        [ValidateSet('GET', 'PATCH')]
        [string] $Method,
        [ValidateNotNullOrEmpty()]
        [string] $Uri,
        [string] $Body,
        [object] $Item
    )
    $absoluteUri = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref] $absoluteUri) -or
        $absoluteUri.Scheme -ne 'https' -or $absoluteUri.Host -ine 'graph.microsoft.com' -or
        -not $absoluteUri.IsDefaultPort -or $absoluteUri.UserInfo -or $absoluteUri.Fragment -or
        $absoluteUri.AbsolutePath -notmatch '^/v1\.0/groups(?:/|$)') {
        throw 'Unexpected Graph request URI. Only HTTPS requests to public Graph v1.0 groups are permitted. No request was sent.'
    }
    $relativeUri = [Uri]::new($absoluteUri.PathAndQuery.TrimStart('/'), [UriKind]::Relative)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $attempt = 0
    while ($true) {
        try {
            $arguments = @{ Method = $Method; Uri = $relativeUri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($Method -eq 'PATCH') {
                $arguments.Body = $Body
                $arguments.ContentType = 'application/json'
            }
            return Invoke-MgGraphRequest @arguments
        } catch {
            $failure = $_.Exception
            $cause = $failure
            $response = $null
            $statusCode = 0
            $transportError = $false
            while ($cause) {
                $responseProperty = $cause.PSObject.Properties['Response']
                if ($responseProperty -and $responseProperty.Value -is [System.Net.Http.HttpResponseMessage]) {
                    $response = $responseProperty.Value
                    $statusCode = [int] $response.StatusCode
                    break
                }
                $statusProperty = $cause.PSObject.Properties['StatusCode']
                if ($statusProperty -and $null -ne $statusProperty.Value) {
                    $statusCode = [int] $statusProperty.Value
                    break
                }
                if ($cause -is [System.Net.Http.HttpRequestException] -or
                    $cause -is [System.TimeoutException] -or
                    $cause -is [System.Threading.Tasks.TaskCanceledException]) {
                    $transportError = $true
                }
                $cause = $cause.InnerException
            }
            $requestId = $null
            if ($response) {
                $values = $null
                if ($response.Headers.TryGetValues('request-id', [ref] $values)) {
                    $requestId = ($values -join ',')
                }
            }
            $failure.Data['HttpStatusCode'] = $statusCode
            $failure.Data['RequestId'] = $requestId
            $transient = $statusCode -in @(408, 500, 502, 503, 504) -or ($statusCode -eq 0 -and $transportError)
            $failure.Data['OutcomeUncertain'] = ($Method -eq 'PATCH' -and $transient)
            $retryable = $statusCode -eq 429 -or ($Method -eq 'GET' -and $transient)
            if (-not $retryable) { throw }
            if ($attempt -ge $MaxRetry) {
                throw [System.InvalidOperationException]::new(
                    "Retry limit exhausted for $Method $Uri (HTTP $statusCode; request-id '$requestId'). $($failure.Message)", $failure)
            }
            $delay = [Math]::Min(180, $RetryDelay * [Math]::Pow(2, $attempt))
            if ($response -and $response.Headers.RetryAfter) {
                $retryAfter = $response.Headers.RetryAfter
                if ($null -ne $retryAfter.Delta) {
                    $delay = [Math]::Ceiling($retryAfter.Delta.TotalSeconds)
                } elseif ($null -ne $retryAfter.Date) {
                    $delay = [Math]::Max(0, [Math]::Ceiling(($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds))
                }
            }
            if ($timer.Elapsed.TotalSeconds + $delay -ge $RetryTimeLimit) {
                throw [System.InvalidOperationException]::new(
                    "Retry time limit reached for $Method $Uri. Required wait is $delay seconds (HTTP $statusCode; request-id '$requestId'). No early retry was made.", $failure)
            }
            $attempt++
            $retryStatistics.Count++
            Write-Warning "Retry $attempt/$MaxRetry for $Method $Uri in $delay seconds (HTTP $statusCode; request-id '$requestId')."
            if ($Item -and $auditStream) {
                Write-GroupAuditRecord -Status 'Retrying' -Item $Item -HttpStatusCode $statusCode -RequestId $requestId -RetryAttempt $attempt -DelaySeconds $delay -ErrorMessage $failure.Message
            }
            Start-Sleep -Seconds $delay
            if ($Method -eq 'PATCH') {
                $current = Invoke-GroupGraphRequest -Method GET -Uri "${Uri}?`$select=$select" -Item $Item
                if ($current.groupTypes -notcontains 'DynamicMembership' -or
                    [string] $current.membershipRule -cne $Item.OriginalRule -or
                    [string] $current.membershipRuleProcessingState -cne [string] $Item.ProcessingState) {
                    throw 'Group rule or processing state changed during throttling. No retry write was made; rerun preview.'
                }
            }
            if ($timer.Elapsed.TotalSeconds -ge $RetryTimeLimit) {
                throw 'Retry time limit reached before the next request. No further request was made.'
            }
        }
    }
}

$originalRequestContext = Get-MgRequestContext
$originalMaxRetry = $originalRequestContext.MaxRetry
try {
if ($originalMaxRetry -ne 0) {
    $null = Set-MgRequestContext -MaxRetry 0 -WhatIf:$false -Confirm:$false
}
$baseUri = 'https://graph.microsoft.com/v1.0/groups'
$select = 'id,displayName,groupTypes,membershipRule,membershipRuleProcessingState'
$discoveredGroups = [System.Collections.Generic.List[object]]::new()
if ($GroupId) {
    foreach ($id in ($GroupId | Select-Object -Unique)) {
        $discoveredGroups.Add((Invoke-GroupGraphRequest -Method GET -Uri "$baseUri/${id}?`$select=$select"))
    }
} else {
    $uri = "${baseUri}?`$filter=groupTypes/any(c:c%20eq%20'DynamicMembership')&`$select=$select"
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    while ($uri) {
        if (-not $uri.StartsWith("${baseUri}?", [StringComparison]::Ordinal) -or -not $seen.Add($uri)) {
            throw 'Unexpected or repeated Graph continuation URL.'
        }
        $page = Invoke-GroupGraphRequest -Method GET -Uri $uri
        foreach ($group in $page.value) { $discoveredGroups.Add($group) }
        $next = $page.PSObject.Properties['@odata.nextLink']
        $uri = if ($next) { [string] $next.Value } else { $null }
    }
}

$condition = '(user.agentIdentityBlueprintId -eq null)'
$plan = @(
    foreach ($group in $discoveredGroups) {
        $rule = [string] $group.membershipRule
        $status = 'Planned'
        $reason = ''
        $reviewCategory = 'Candidate'
        $nextStep = 'Review the full proposed rule and validate representative human and agent accounts before approving a pilot update.'
        $newRule = $null
        if ($group.groupTypes -notcontains 'DynamicMembership') {
            $status = 'Skipped'; $reason = 'Not a dynamic membership group.'
            $reviewCategory = 'NotApplicable'
            $nextStep = 'No rule change applies. This script only changes dynamic user group rules; review assigned membership separately if needed.'
        } elseif ([string]::IsNullOrWhiteSpace($rule)) {
            $status = 'Skipped'; $reason = 'Empty rule.'
            $reviewCategory = 'ManualReview'
            $nextStep = 'Ask the group owner to inspect the missing rule in Entra. Resolve it before attempting an exclusion.'
        } else {
            # Ignore quoted literals when classifying rule properties and parentheses.
            $structure = [regex]::Replace($rule.Trim(), '"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''', '""')
            if ($structure -match '(?i)\bdevice\s*\.') {
                $status = 'Skipped'; $reason = 'Device membership rule; agent users are not applicable.'
                $reviewCategory = 'NotApplicable'
                $nextStep = 'No agent-user exclusion is needed here: this group evaluates devices, not user accounts.'
            } elseif ($structure -match '(?i)\buser\s*\.\s*memberOf\b') {
                $status = 'Skipped'; $reason = 'memberOf rules cannot be combined with this condition; manual review required.'
                $reviewCategory = 'ManualReview'
                $nextStep = 'Review the referenced source groups with their owners and confirm an Entra-supported exclusion strategy. Do not append this condition to a memberOf rule.'
            } elseif ($structure -notmatch '(?i)\buser\s*\.') {
                $status = 'Skipped'; $reason = 'Unrecognized rule type; manual review required.'
                $reviewCategory = 'ManualReview'
                $nextStep = 'Inspect the full rule with the group owner in Entra. The script cannot safely identify it as a user membership rule.'
            } else {
                $alreadyExcluded = $structure -match '^\s*\(\s*user\.agentIdentityBlueprintId\s+-eq\s+null\s*\)\s*$'
                if ($structure -match '(?is)^(?<prefix>\(.*\))\s+-and\s+\(\s*user\.agentIdentityBlueprintId\s+-eq\s+null\s*\)$') {
                    $prefix = $Matches.prefix
                    $depth = 0
                    $enclosed = $true
                    for ($i = 0; $i -lt $prefix.Length; $i++) {
                        if ($prefix[$i] -eq '(') { $depth++ }
                        if ($prefix[$i] -eq ')') { $depth-- }
                        if ($depth -lt 0 -or ($depth -eq 0 -and $i -lt $prefix.Length - 1)) {
                            $enclosed = $false
                            break
                        }
                    }
                    $alreadyExcluded = $enclosed -and $depth -eq 0
                }
                if ($alreadyExcluded) {
                    $status = 'Unchanged'; $reason = 'Top-level agent exclusion is already present.'
                    $reviewCategory = 'AlreadyExcluded'
                    $nextStep = 'No additional rule edit is needed. This recognizes the stored condition, not verified account coverage or completed membership processing.'
                } elseif ($structure -match '(?i)\buser\s*\.\s*agentIdentityBlueprintId\b') {
                    $status = 'Skipped'; $reason = 'Existing blueprint-specific logic requires manual review to preserve intended membership.'
                    $reviewCategory = 'ManualReview'
                    $nextStep = 'Confirm with the group owner whether agents are intentionally included. Review the existing blueprint condition; automatic editing could change intended membership.'
                } else {
                    $newRule = "($rule) -and $condition"
                    if ($newRule.Length -gt 3072) {
                        $status = 'Skipped'; $reason = "Proposed rule is $($newRule.Length) characters; limit is 3072."
                        $reviewCategory = 'ManualReview'
                        $nextStep = 'Have the group owner simplify or redesign the rule and revalidate membership. The exclusion cannot be appended within the supported rule length.'
                    }
                }
            }
        }
        if ($status -eq 'Skipped' -and ($Detailed -or $PassThru)) {
            Write-Warning "$($group.displayName) [$($group.id)]: $reason"
        }
        [pscustomobject]@{
            Id = $group.id
            DisplayName = $group.displayName
            OriginalRule = $rule
            ProposedRule = $newRule
            ProcessingState = $group.membershipRuleProcessingState
            Status = $status
            Reason = $reason
            ReviewCategory = $reviewCategory
            NextStep = $nextStep
            ResponseRecovered = $false
        }
    }
)

if ($plan.Count -eq 0) {
    Write-Warning 'No dynamic groups were found in the selected scope. No changes were made.'
}

$backupWritten = $false
$auditStream = $null
$resolvedAudit = $null
$runId = [guid]::NewGuid().ToString()
function Write-GroupAuditRecord {
    param(
        [string] $Status,
        [object] $Item,
        [bool] $PatchAccepted = $false,
        [string] $ErrorMessage,
        [int] $HttpStatusCode = 0,
        [string] $RequestId,
        [int] $RetryAttempt = 0,
        [double] $DelaySeconds = 0,
        [bool] $RuleReadBackVerified = $false
    )
    $record = [ordered]@{
        RunId = $runId
        TimestampUtc = [datetime]::UtcNow.ToString('o')
        TenantId = $context.TenantId
        BackupPath = $resolvedBackup
        GroupId = $Item.Id
        DisplayName = $Item.DisplayName
        OriginalRule = $Item.OriginalRule
        ProposedRule = $Item.ProposedRule
        ProcessingState = $Item.ProcessingState
        Status = $Status
        PatchAccepted = $PatchAccepted
        Error = $ErrorMessage
        HttpStatusCode = $HttpStatusCode
        RequestId = $RequestId
        RetryAttempt = $RetryAttempt
        DelaySeconds = $DelaySeconds
        RuleReadBackVerified = $RuleReadBackVerified
        ResponseRecovered = $Item.ResponseRecovered
    }
    foreach ($name in @('Account', 'ClientId', 'AuthType')) {
        $property = $context.PSObject.Properties[$name]
        $record[$name] = if ($property) { $property.Value } else { $null }
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($record | ConvertTo-Json -Depth 5 -Compress) + [Environment]::NewLine)
    $auditStream.Write($bytes, 0, $bytes.Length)
    $auditStream.Flush($true)
}

$applyCount = @($plan | Where-Object Status -eq 'Planned').Count
$applyIndex = 0
try {
foreach ($item in $plan) {
    if ($item.Status -ne 'Planned') { continue }
    if (-not $Apply) {
        $item.Status = 'Preview'
        continue
    }
    $applyIndex++
    $applyProgress = @{
        Id = 1
        Activity = 'Applying agent-user exclusions'
        Status = "Group $applyIndex of ${applyCount}: $($item.DisplayName)"
        PercentComplete = [int] (($applyIndex - 1) * 100 / $applyCount)
    }
    if ($requiresWrite) { Write-Progress @applyProgress -CurrentOperation 'Awaiting approval' }
    if (-not $PSCmdlet.ShouldProcess("$($item.DisplayName) [$($item.Id)]", 'Append agent-user exclusion to membershipRule')) {
        $item.Status = 'NotApplied'
        continue
    }
    if (-not $backupWritten) {
        $backupJson = @{
            TenantId = $context.TenantId
            CreatedUtc = [datetime]::UtcNow.ToString('o')
            Groups = $plan
        } | ConvertTo-Json -Depth 8
        $resolvedBackup = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupPath)
        $stream = [System.IO.File]::Open($resolvedBackup, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try {
            $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($backupJson)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        $backupWritten = $true
        Write-Host "Original rules backed up to: $resolvedBackup"
    }

    if (-not $auditStream) {
        if (-not $AuditPath) {
            $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
            if ([string]::IsNullOrWhiteSpace($desktop)) {
                throw 'Desktop is unavailable. Supply -AuditPath with a new file in an existing writable directory. No group updates were attempted.'
            }
            $AuditPath = Join-Path $desktop ("AgentGroupAudit-{0}-{1}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $runId)
        }
        $resolvedAudit = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AuditPath)
        $auditStream = [System.IO.File]::Open($resolvedAudit, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        Write-Host "Change audit log: $resolvedAudit"
    }

    $uri = "$baseUri/$($item.Id)"
    $patchAccepted = $false
    try {
        Write-GroupAuditRecord -Status 'Attempting' -Item $item
        Write-Progress @applyProgress -CurrentOperation 'Checking the current rule and processing state'
        $current = Invoke-GroupGraphRequest -Method GET -Uri "${uri}?`$select=$select" -Item $item
        if ($current.groupTypes -notcontains 'DynamicMembership' -or
            [string] $current.membershipRule -cne $item.OriginalRule -or
            [string] $current.membershipRuleProcessingState -cne [string] $item.ProcessingState) {
            throw 'Group rule or processing state changed since discovery. Rerun preview.'
        }
        $body = @{ membershipRule = $item.ProposedRule } | ConvertTo-Json -Compress
        $patchFailure = $null
        try {
            Write-Progress @applyProgress -CurrentOperation 'Submitting the rule update'
            $null = Invoke-GroupGraphRequest -Method PATCH -Uri $uri -Body $body -Item $item
            $patchAccepted = $true
        } catch {
            $patchFailure = $_.Exception
            if (-not $patchFailure.Data['OutcomeUncertain']) { throw }
            Write-Warning "PATCH outcome uncertain for [$($item.Id)]. Reading current state before any further write."
            Write-GroupAuditRecord -Status 'Reconciling' -Item $item -HttpStatusCode $patchFailure.Data['HttpStatusCode'] -RequestId $patchFailure.Data['RequestId'] -ErrorMessage $patchFailure.Message
        }
        Write-Progress @applyProgress -CurrentOperation 'Reading back and verifying the stored rule'
        $verified = Invoke-GroupGraphRequest -Method GET -Uri "${uri}?`$select=$select" -Item $item
        if ($verified.groupTypes -notcontains 'DynamicMembership' -or
            [string] $verified.membershipRule -cne $item.ProposedRule -or
            [string] $verified.membershipRuleProcessingState -cne [string] $item.ProcessingState) {
            if ($patchFailure) {
                throw [System.InvalidOperationException]::new(
                    'PATCH outcome could not be reconciled to the proposed rule/state. No blind retry was made. Inspect Graph state and the backup before retrying.', $patchFailure)
            }
            throw 'Read-back did not match the proposed rule and original processing state.'
        }
        $item.ResponseRecovered = $null -ne $patchFailure
        $item.Status = 'Updated'
        Write-GroupAuditRecord -Status 'Updated' -Item $item -PatchAccepted $patchAccepted -RuleReadBackVerified $true
        if ($Detailed) {
            Write-Host "Updated and verified: $($item.DisplayName) [$($item.Id)]" -ForegroundColor Green
        }
    } catch {
        $failure = $_.Exception
        try {
            $auditFailure = $failure
            while ($auditFailure.InnerException -and -not $auditFailure.Data.Contains('HttpStatusCode')) {
                $auditFailure = $auditFailure.InnerException
            }
            Write-GroupAuditRecord -Status 'Failed' -Item $item -PatchAccepted $patchAccepted -ErrorMessage $failure.Message -HttpStatusCode $auditFailure.Data['HttpStatusCode'] -RequestId $auditFailure.Data['RequestId']
        } catch {
            throw [System.InvalidOperationException]::new(
                "Audit logging failed at '$resolvedAudit'. Group [$($item.Id)] may have changed; stop and reconcile Graph state with backup '$resolvedBackup'. Operation error: $($failure.Message). Audit error: $($_.Exception.Message)",
                $_.Exception)
        }
        throw [System.InvalidOperationException]::new(
            "Stopped at $($item.DisplayName) [$($item.Id)]. Earlier updates or this attempt may have succeeded. Review audit '$resolvedAudit', backup '$resolvedBackup', and current Graph state before retrying. $($failure.Message)",
            $failure)
    }
}
} finally {
    if ($auditStream) { $auditStream.Dispose() }
    if ($requiresWrite -and $applyCount -gt 0) {
        Write-Progress -Id 1 -Activity 'Applying agent-user exclusions' -Completed
    }
}
foreach ($result in $plan) {
    $saved = $result.Status -in @('Updated', 'Unchanged')
    if ($saved) {
        $completion = if ($result.ProcessingState -eq 'Paused') { 'Paused' } else { 'Unverified' }
        $timing = if ($completion -eq 'Paused') {
            'No processing estimate until an administrator resumes membership processing.'
        } else {
            'Usually minutes to 24 hours after a rule change; not an ETA or SLA. Verify completion and actual membership in Entra.'
        }
    } else {
        $completion = 'NotVerified'
        $timing = if ($result.ReviewCategory -eq 'ManualReview') {
            'No ETA: administrator review is required; no exclusion was applied.'
        } elseif ($result.ReviewCategory -eq 'NotApplicable') {
            'This agent-user rule change does not apply.'
        } else {
            'No change was applied; membership processing is not scheduled by this run.'
        }
    }
    $result | Add-Member -NotePropertyName RuleSaved -NotePropertyValue $saved
    $result | Add-Member -NotePropertyName MembershipCompletion -NotePropertyValue $completion
    $result | Add-Member -NotePropertyName TimingGuidance -NotePropertyValue $timing
}
if ($PassThru) {
    $plan
} else {
    $consoleWidth = $Host.UI.RawUI.WindowSize.Width
    $reportWidth = if ($consoleWidth -gt 0) { [Math]::Min(120, $consoleWidth) } else { 100 }
    function Write-ReportTable {
        param(
            [object[]] $Rows,
            [object[]] $Columns,
            [ConsoleColor] $Color = 'Gray'
        )
        $text = $Rows | Format-Table -Property $Columns -Wrap |
            Out-String -Width $reportWidth
        Write-Host $text.TrimEnd() -ForegroundColor $Color
    }

    $previewCount = @($plan | Where-Object Status -eq 'Preview').Count
    $updatedCount = @($plan | Where-Object Status -eq 'Updated').Count
    $unchangedCount = @($plan | Where-Object Status -eq 'Unchanged').Count
    $skippedCount = @($plan | Where-Object Status -eq 'Skipped').Count
    $notApplicableCount = @($plan | Where-Object ReviewCategory -eq 'NotApplicable').Count
    $manualReviewCount = @($plan | Where-Object ReviewCategory -eq 'ManualReview').Count
    $notAppliedCount = @($plan | Where-Object Status -eq 'NotApplied').Count
    $pausedCount = @($plan | Where-Object ProcessingState -eq 'Paused').Count
    $mode = if ($WhatIfPreference) { 'WHATIF - no changes made' } elseif ($Apply) { 'APPLY' } else { 'PREVIEW - no changes made' }
    Write-Host ''
    Write-Host ('=' * [Math]::Min(68, $reportWidth)) -ForegroundColor Cyan
    Write-Host 'AGENT USER EXCLUSION - SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor Cyan
    Write-Host 'Purpose: prevent agent over-permissioning through unintended human-group access.' -ForegroundColor Cyan
    Write-Host 'Preserve approved agent access and security protections; group eligibility is not proof of excess permissions.'
    Write-Host "Tenant: $($context.TenantId)"
    Write-Host "Mode: $mode" -ForegroundColor Cyan
    Write-Host "Groups reviewed: $($plan.Count)"
    Write-Host "Request retries: $($retryStatistics.Count) (limit $MaxRetry per request; retry window $RetryTimeLimit seconds)" -ForegroundColor Gray
    $recoveredCount = @($plan | Where-Object ResponseRecovered).Count
    Write-Host "Lost/error PATCH responses reconciled by read-back: $recoveredCount" -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Result               Count' -ForegroundColor Cyan
    Write-Host '  ------------------   -----' -ForegroundColor Cyan
    Write-Host "  Proposed only    : $previewCount" -ForegroundColor Cyan
    Write-Host "  Rule updated     : $updatedCount" -ForegroundColor Green
    Write-Host "  Already excluded : $unchangedCount" -ForegroundColor Cyan
    Write-Host "  Not applicable   : $notApplicableCount" -ForegroundColor Gray
    Write-Host "  Manual review    : $manualReviewCount" -ForegroundColor Yellow
    Write-Host "  Not applied      : $notAppliedCount" -ForegroundColor Yellow
    if ($skippedCount -gt 0) {
        Write-Host ''
        Write-Host "Of the skipped groups: $notApplicableCount not applicable | $manualReviewCount need manual review. None of these groups were changed."
    }
    $pausedColor = if ($pausedCount -gt 0) { 'Yellow' } else { 'Gray' }
    Write-Host "Paused groups: $pausedCount (processing state preserved)" -ForegroundColor $pausedColor
    $savedCount = $updatedCount + $unchangedCount
    $savedPausedCount = @($plan | Where-Object MembershipCompletion -eq 'Paused').Count
    $unverifiedCount = @($plan | Where-Object MembershipCompletion -eq 'Unverified').Count
    Write-Host ''
    Write-Host 'RULE SAVED VS. MEMBERSHIP COMPLETION' -ForegroundColor Cyan
    Write-Host "  Exclusions saved          : $savedCount (new + already present)" -ForegroundColor Cyan
    Write-Host "  Completion unverified     : $unverifiedCount" -ForegroundColor Yellow
    Write-Host "  Saved but processing paused: $savedPausedCount" -ForegroundColor Yellow
    Write-Host 'Unverified does not mean confirmed pending or fixed. Graph v1.0 does not expose completion through the properties used here.' -ForegroundColor Yellow
    Write-Host 'Expected processing: minutes to 24 hours after a rule change (not an ETA/SLA). Paused groups need administrator action.'
    Write-Host 'Verify Dynamic rule processing status and actual membership on the group Overview page in Entra.'
    Write-Host ''
    Write-Host "Change: append $condition to the entire parenthesized original rule."
    $statusLabels = @{
        Preview = 'Proposed only'
        Updated = 'Rule updated'
        Unchanged = 'Already excluded'
        NotApplied = 'Not applied'
    }
    $statusColors = @{
        Preview = 'Cyan'
        Updated = 'Green'
        Unchanged = 'Cyan'
        NotApplied = 'Yellow'
    }
    if ($Detailed -and $plan.Count -gt 0) {
        Write-Host ''
        Write-Host 'GROUP RESULTS' -ForegroundColor Cyan
        Write-Host ('-' * 68) -ForegroundColor Cyan
        foreach ($groupResult in $plan) {
            if ($groupResult.Status -eq 'Skipped') {
                if ($groupResult.ReviewCategory -eq 'NotApplicable') {
                    $label = 'Not applicable'; $color = 'Gray'
                } else {
                    $label = 'Manual review'; $color = 'Yellow'
                }
            } else {
                $label = $statusLabels[$groupResult.Status]
                $color = $statusColors[$groupResult.Status]
            }
            Write-Host "  [$label] $($groupResult.DisplayName)" -ForegroundColor $color
            Write-Host "    Group ID: $($groupResult.Id)" -ForegroundColor Gray
            $stateColor = if ($groupResult.ProcessingState -eq 'Paused') { 'Yellow' } else { 'Gray' }
            Write-Host "    Processing: $($groupResult.ProcessingState)" -ForegroundColor $stateColor
            Write-Host "    Membership completion: $($groupResult.MembershipCompletion)" -ForegroundColor Yellow
            Write-Host "    Timing: $($groupResult.TimingGuidance)"
            Write-Host "    Original rule: $($groupResult.OriginalRule)"
            if ($groupResult.ProposedRule) {
                Write-Host "    Proposed rule: $($groupResult.ProposedRule)"
            }
            Write-Host ''
        }
        Write-Host ''
        Write-Host 'WHAT THE RESULTS MEAN' -ForegroundColor Cyan
        Write-Host ('-' * 68) -ForegroundColor Cyan
        $explanations = [ordered]@{
            Preview = 'Proposed only: an eligible rule change was identified; nothing was applied. Validate and obtain approval first.'
            Updated = 'Rule updated: the new rule was saved and read back. Membership recalculation may still be pending.'
            Unchanged = 'Already excluded: the top-level exclusion is already in the stored rule. No edit was needed; account coverage still needs validation.'
            NotApplied = 'Not applied: the update was not executed because of -WhatIf or declined confirmation. This is not a failed update.'
        }
        foreach ($status in $explanations.Keys) {
            if (@($plan | Where-Object Status -eq $status).Count -gt 0) {
                Write-Host $explanations[$status] -ForegroundColor $statusColors[$status]
            }
        }
        if ($notApplicableCount -gt 0) {
            Write-Host 'Not applicable: a device or non-dynamic group; this agent-user rule change does not apply.' -ForegroundColor Gray
        }
        if ($manualReviewCount -gt 0) {
            Write-Host 'Manual review: the script cannot safely append the exclusion. This does NOT mean agent users are excluded; review the reason and next step below.' -ForegroundColor Yellow
        }
        Write-Host 'State: On means membership processing is enabled; Paused means it will not recalculate until an administrator resumes it.'
    }
    $reviewGroups = @($plan | Where-Object {
        $_.ReviewCategory -eq 'ManualReview' -or ($Detailed -and $_.Status -eq 'Skipped')
    })
    if ($reviewGroups.Count -gt 0) {
        Write-Host ''
        if ($Detailed) {
            Write-Host 'WHY GROUPS WERE SKIPPED - REASONS AND NEXT STEPS' -ForegroundColor Yellow
        } else {
            Write-Host 'MANUAL REVIEW - FLAGGED GROUPS AND WHY' -ForegroundColor Yellow
        }
        Write-Host ('-' * 68) -ForegroundColor Yellow
        Write-Host 'Manual review means the script could not safely append the exclusion. These groups were NOT changed; this does NOT mean agent users are excluded.' -ForegroundColor Yellow
        $groupWidth = [Math]::Max(12, [int][Math]::Floor(($reportWidth - 3) * 0.35))
        $whyWidth = [Math]::Max(12, [int][Math]::Floor(($reportWidth - 3) * 0.30))
        $actionWidth = [Math]::Max(12, $reportWidth - $groupWidth - $whyWidth - 3)
        $reviewRows = @(
            foreach ($skipped in $reviewGroups) {
                [pscustomobject]@{
                    Group = "$($skipped.DisplayName)`n$($skipped.Id)"
                    Why = $skipped.Reason
                    Action = $skipped.NextStep
                }
            }
        )
        Write-ReportTable -Rows $reviewRows -Columns @(
            @{ Label = 'Group / ID'; Expression = 'Group'; Width = $groupWidth }
            @{ Label = 'Why flagged'; Expression = 'Why'; Width = $whyWidth }
            @{ Label = 'Next step'; Expression = 'Action'; Width = $actionWidth }
        ) -Color Yellow
    }
    if ($backupWritten -or $resolvedAudit) {
        Write-Host ''
        Write-Host 'AUDIT AND RECOVERY FILES' -ForegroundColor Cyan
        Write-Host ('-' * 68) -ForegroundColor Cyan
        if ($backupWritten) { Write-Host "Original-rule backup: $resolvedBackup" }
        if ($resolvedAudit) { Write-Host "Detailed change audit: $resolvedAudit" }
    }
    Write-Host ''
    Write-Host 'Preview identifies candidate rules, not confirmed agent membership. Updated means rule read-back verified, not completed membership processing.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'NEXT STEPS - COMMANDS AND PARAMETERS' -ForegroundColor Cyan
    Write-Host ('-' * 68) -ForegroundColor Cyan
    Write-Host '1. Inspect all group results and full rules (read-only):'
    Write-Host '   .\Exclude-AgentUsersFromDynamicGroups.ps1 -Details' -ForegroundColor Cyan
    if ($Apply -and -not $WhatIfPreference) {
        Write-Host '2. Verify actual membership after processing completes; review the audit and resolve manual-review groups before any further rollout.'
    } else {
        Write-Host '2. Resolve manual-review flags, validate human/agent accounts, and obtain change approval before applying.'
    }
    Write-Host '3. Preview an approved pilot, then apply only after validation (replace the ID placeholders):'
    Write-Host '   .\Exclude-AgentUsersFromDynamicGroups.ps1 `' -ForegroundColor Cyan
    Write-Host '       -TenantId ''<tenant-id>'' -GroupId ''<pilot-group-id>'' `' -ForegroundColor Cyan
    Write-Host '       -Apply -WhatIf' -ForegroundColor Cyan
    Write-Host '   Remove -WhatIf from the same command to apply after approval.' -ForegroundColor Yellow
    Write-Host '   Apply needs Group.ReadWrite.All and effective Entra authorization. If your existing connection is read-only, reconnect explicitly with that scope before applying.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'PARAMETER QUICK GUIDE' -ForegroundColor Cyan
    $parameterGuide = [ordered]@{
        '(none)' = 'Read-only summary plus manual-review groups and reasons.'
        '-Details' = 'Show all groups, full rules, and explanations. Alias of -Detailed.'
        '-NoMenu' = 'Skip interactive prompts for next actions. Use for unattended runs; -PassThru also skips the menu.'
        '-MaxRetry' = 'Additional request attempts, 0-10; default 5. PATCH retries only on throttling after a concurrency check.'
        '-RetryDelay' = 'Initial exponential backoff, 1-180 seconds; default 3. Retry-After takes precedence.'
        '-RetryTimeLimit' = 'Per-request retry window, 1-3600 seconds; default 300. Does not cancel an in-flight request.'
        '-Apply' = 'Save approved changes after backup and per-group confirmation. Without -GroupId, targets all eligible discovered groups.'
        '-WhatIf' = 'With -Apply, preview without group updates or backup/audit writes. Sign-in may still prompt.'
        '-GroupId' = 'Limit to one or more group GUIDs, separated by commas. Use for pilots and approved batches.'
        '-TenantId' = 'Target sign-in and reject a connection for a different tenant GUID.'
        '-BackupPath' = 'New original-rule JSON file; default: unique file in current directory. Parent folder must exist.'
        '-AuditPath' = 'New change-audit JSONL file; default: unique Desktop file. Parent folder must exist.'
        '-PassThru' = 'Return objects for Format-List or Export-Csv instead of the report; overrides -Details.'
        '-Confirm' = 'Request confirmation. -Confirm:$false suppresses prompts; use only after approval.'
    }
    $parameterRows = @(
        foreach ($entry in $parameterGuide.GetEnumerator()) {
            [pscustomobject]@{ Parameter = $entry.Key; Purpose = $entry.Value }
        }
    )
    Write-ReportTable -Rows $parameterRows -Columns @(
        @{ Expression = 'Parameter'; Width = 16 }
        @{ Expression = 'Purpose'; Width = [Math]::Max(12, $reportWidth - 18) }
    )
    Write-Host '  Full help: Get-Help .\Exclude-AgentUsersFromDynamicGroups.ps1 -Full' -ForegroundColor Gray
}

if (-not $NoMenu -and -not $PassThru) {
    $menuTenant = [string] $context.TenantId
    while ($true) {
        Write-Host ''
        Write-Host 'WHAT WOULD YOU LIKE TO DO NEXT?' -ForegroundColor Cyan
        Write-Host '  1  View all dynamic groups and full details (this tenant)'
        Write-Host '  2  Apply all eligible groups or select from a numbered list'
        Write-Host '  3  Refresh saved-rule counts and completion guidance (current scope)'
        Write-Host '  4  Exit'
        $choice = Read-Host 'Enter 1, 2, 3, or 4'
        if ($choice -eq '4') { break }
        if ($choice -notin @('1', '2', '3')) {
            Write-Warning 'Invalid menu choice. Enter 1, 2, 3, or 4.'
            continue
        }
        $runParameters = @{
            TenantId = $menuTenant
            NoMenu = $true
            PassThru = $false
            Detailed = ($choice -eq '1')
            WhatIf = [bool] $WhatIfPreference
            MaxRetry = $MaxRetry
            RetryDelay = $RetryDelay
            RetryTimeLimit = $RetryTimeLimit
        }
        if ($choice -eq '3' -and $GroupId) { $runParameters.GroupId = $GroupId }
        if ($choice -eq '2') {
            $reviewParameters = $runParameters.Clone()
            $reviewParameters.PassThru = $true
            if ($GroupId) { $reviewParameters.GroupId = $GroupId }
            $currentReview = @(& $PSCommandPath @reviewParameters)
            $eligibleGroups = @($currentReview | Where-Object Status -eq 'Preview' | Sort-Object DisplayName, Id)
            Write-Host "Current scope: $($currentReview.Count) groups reviewed; $($eligibleGroups.Count) eligible rule changes." -ForegroundColor Cyan
            Write-Host 'Already-excluded, not-applicable, and manual-review groups are not included. Eligibility is checked again before applying.' -ForegroundColor Yellow
            if ($eligibleGroups.Count -eq 0) {
                Write-Host 'No eligible rule changes remain in this scope. No changes requested.' -ForegroundColor Gray
                continue
            }
            Write-Host 'Enter ALL to apply to every eligible group in this scope, or LIST to choose groups by number. Group GUIDs are also accepted for groups in this review.' -ForegroundColor Cyan
            $inputIds = Read-Host 'Enter ALL, LIST, or group GUIDs separated by commas (blank cancels)'
            $numberSelection = $false
            if ($inputIds -and $inputIds.Trim() -ieq 'LIST') {
                $numberWidth = [Math]::Max(6, $eligibleGroups.Count.ToString().Length)
                $selectionRows = @(
                    for ($index = 0; $index -lt $eligibleGroups.Count; $index++) {
                        [pscustomobject]@{
                            Number = $index + 1
                            Group = "$($eligibleGroups[$index].DisplayName)`n$($eligibleGroups[$index].Id)"
                            Processing = $eligibleGroups[$index].ProcessingState
                        }
                    }
                )
                Write-ReportTable -Rows $selectionRows -Columns @(
                    @{ Expression = 'Number'; Width = $numberWidth }
                    @{ Expression = 'Group'; Width = [Math]::Max(12, $reportWidth - $numberWidth - 13) }
                    @{ Expression = 'Processing'; Width = 10 }
                )
                $inputIds = Read-Host 'Enter numbers or ranges (for example 1,3-5), ALL, or blank to cancel'
                $numberSelection = $true
            }
            if ([string]::IsNullOrWhiteSpace($inputIds)) {
                Write-Host 'Cancelled. No changes requested.' -ForegroundColor Gray
                continue
            }
            $selectedIds = [System.Collections.Generic.HashSet[guid]]::new()
            $eligibleIds = [System.Collections.Generic.HashSet[guid]]::new()
            foreach ($group in $eligibleGroups) { $null = $eligibleIds.Add([guid] $group.Id) }
            $validIds = $true
            if ($inputIds.Trim() -ieq 'ALL') {
                foreach ($id in $eligibleIds) { $null = $selectedIds.Add($id) }
            } elseif ($numberSelection) {
                foreach ($value in ($inputIds -split ',')) {
                    if ($value.Trim() -notmatch '^(?<first>\d+)(?:\s*-\s*(?<last>\d+))?$') {
                        $validIds = $false
                        break
                    }
                    $first = 0
                    $last = 0
                    $lastText = if ($Matches.ContainsKey('last')) { $Matches.last } else { $Matches.first }
                    if (-not [int]::TryParse($Matches.first, [ref] $first) -or
                        -not [int]::TryParse($lastText, [ref] $last) -or
                        $first -lt 1 -or $last -lt $first -or $last -gt $eligibleGroups.Count) {
                        $validIds = $false
                        break
                    }
                    for ($index = $first - 1; $index -lt $last; $index++) {
                        $null = $selectedIds.Add([guid] $eligibleGroups[$index].Id)
                    }
                }
            } else {
                foreach ($value in ($inputIds -split ',')) {
                    $parsedId = [guid]::Empty
                    if (-not [guid]::TryParse($value.Trim(), [ref] $parsedId) -or
                        -not $eligibleIds.Contains($parsedId)) {
                        $validIds = $false
                        break
                    }
                    $null = $selectedIds.Add($parsedId)
                }
            }
            if (-not $validIds -or $selectedIds.Count -eq 0) {
                Write-Warning 'Invalid group selection. Use only numbers/ranges from the displayed list or GUIDs of eligible groups in this scope. No changes were requested.'
                continue
            }
            $runParameters.Apply = $true
            $runParameters.GroupId = [guid[]] @($selectedIds)
            Write-Host "Selected $($selectedIds.Count) eligible groups. Apply still requires approval/confirmation and uses a new backup and audit file." -ForegroundColor Yellow
            foreach ($pathName in @('BackupPath', 'AuditPath')) {
                if ($PSBoundParameters.ContainsKey($pathName)) {
                    $originalPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PSBoundParameters[$pathName])
                    $directory = [System.IO.Path]::GetDirectoryName($originalPath)
                    $stem = [System.IO.Path]::GetFileNameWithoutExtension($originalPath)
                    $extension = [System.IO.Path]::GetExtension($originalPath)
                    $runParameters[$pathName] = Join-Path $directory ("{0}-{1}{2}" -f $stem, [guid]::NewGuid().ToString('N'), $extension)
                }
            }
            $menuContext = Get-MgContext
            if (-not $WhatIfPreference -and $menuContext -and
                [string] $menuContext.TenantId -eq $menuTenant -and $menuContext.Environment -eq 'Global') {
                $menuScopes = $menuContext.PSObject.Properties['Scopes']
                $canWrite = $menuScopes -and @($menuScopes.Value | Where-Object {
                    $_ -in @('Group.ReadWrite.All', 'Directory.ReadWrite.All')
                }).Count -gt 0
                if (-not $canWrite) {
                    Write-Host 'You selected apply. Requesting Group.ReadWrite.All for this tenant; sign-in/admin consent may prompt again.' -ForegroundColor Yellow
                    $null = Connect-MgGraph -TenantId $menuTenant -Scopes 'Group.ReadWrite.All' -ContextScope Process -Environment Global -NoWelcome -ErrorAction Stop
                }
            }
        }
        & $PSCommandPath @runParameters
    }
}
} finally {
    if ($originalMaxRetry -ne 0) {
        $null = Set-MgRequestContext -MaxRetry $originalMaxRetry -WhatIf:$false -Confirm:$false
    }
}
