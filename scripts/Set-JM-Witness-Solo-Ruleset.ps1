# Solo-operator migration, strictly bounded. PR/CI/linear/no-bypass remain mandatory.
# Changes ONLY impossible second-person approval settings in existing Ruleset.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'olivesoup/jm-gate-witness'
$id = 26785842
$context = 'jm-witness-policy'
$app = 15368

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'gh CLI missing; install GitHub.cli' }
$beforeRaw = & gh api "repos/$repo/rulesets/$id"
if ($LASTEXITCODE -ne 0) { throw 'GitHub ruleset admin GET failed' }
$rs = ($beforeRaw -join [Environment]::NewLine) | ConvertFrom-Json
if ($rs.id -ne $id -or $rs.name -cne 'JM-Witness-Master-Protection' -or $rs.enforcement -cne 'active' -or $rs.target -cne 'branch') { throw 'RULESET_ID_OR_ENFORCEMENT_CHANGED' }
if (@($rs.bypass_actors).Count -ne 0 -or
    @($rs.conditions.ref_name.include).Count -ne 1 -or
    $rs.conditions.ref_name.include[0] -cne '~DEFAULT_BRANCH' -or
    @($rs.conditions.ref_name.exclude).Count -ne 0) { throw 'RULESET_BOUNDARY_CHANGED' }

$types = @($rs.rules | ForEach-Object { $_.type } | Sort-Object)
$expected = @(@('deletion','non_fast_forward','pull_request','required_linear_history','required_status_checks') | Sort-Object)
if (($types -join '|') -cne ($expected -join '|')) { throw 'RULE_TYPE_DRIFT' }
$pr = @($rs.rules | Where-Object { $_.type -ceq 'pull_request' })
$checks = @($rs.rules | Where-Object { $_.type -ceq 'required_status_checks' })
if ($pr.Count -ne 1 -or $checks.Count -ne 1) { throw 'RULE_DUPLICATION' }
$required = @($checks[0].parameters.required_status_checks)
if ($checks[0].parameters.strict_required_status_checks_policy -ne $true -or
    $checks[0].parameters.do_not_enforce_on_create -eq $true -or
    $required.Count -ne 1 -or $required[0].context -cne $context -or
    $required[0].integration_id -ne $app) { throw 'STRICT_CI_CHECK_CHANGED' }
if ($pr[0].parameters.required_review_thread_resolution -ne $true -or
    $pr[0].parameters.require_code_owner_review -ne $false -or
    @($pr[0].parameters.required_reviewers).Count -ne 0) { throw 'REVIEW_THREAD_OR_OWNER_POLICY_CHANGED' }

if ($pr[0].parameters.required_approving_review_count -eq 0 -and
    $pr[0].parameters.require_last_push_approval -eq $false -and
    $pr[0].parameters.require_extra_approval_for_unattributed_changes -eq $false) {
    Write-Host 'SOLO_POLICY_READY: already configured; strict CI/PR and no bypass verified'
    exit 0
}

if ($pr[0].parameters.required_approving_review_count -ne 1 -or
    $pr[0].parameters.require_last_push_approval -ne $true -or
    $pr[0].parameters.dismiss_stale_reviews_on_push -ne $true) {
    throw 'UNEXPECTED_APPROVAL_POLICY_REFUSE_UPDATE'
}

$pr[0].parameters.required_approving_review_count = 0
$pr[0].parameters.require_last_push_approval = $false
$pr[0].parameters.require_extra_approval_for_unattributed_changes = $false
# Preserve PR-only, stale-dismissal, thread resolution, strict required CI,
# linear history, force push/deletion prohibition and no-bypass.

$body = [pscustomobject]@{
    name = $rs.name
    target = $rs.target
    enforcement = $rs.enforcement
    bypass_actors = @()
    conditions = $rs.conditions
    rules = @($rs.rules)
}
$tmp = [System.IO.Path]::GetTempFileName()
try {
    $json = ConvertTo-Json -InputObject $body -Depth 32 -Compress
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    & gh api --method PUT "repos/$repo/rulesets/$id" --input $tmp | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'GITHUB_RULESET_UPDATE_FAILED' }
}
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

$afterRaw = & gh api "repos/$repo/rulesets/$id"
if ($LASTEXITCODE -ne 0) { throw 'RULESET_READBACK_FAILED' }
$after = ($afterRaw -join [Environment]::NewLine) | ConvertFrom-Json
$afterTypes = @($after.rules | ForEach-Object { $_.type } | Sort-Object)
$afterPr = @($after.rules | Where-Object { $_.type -ceq 'pull_request' })
$afterChecks = @($after.rules | Where-Object { $_.type -ceq 'required_status_checks' })
$afterRequired = @($afterChecks[0].parameters.required_status_checks)
if ($after.id -ne $id -or $after.enforcement -cne 'active' -or
    @($after.bypass_actors).Count -ne 0 -or
    ($afterTypes -join '|') -cne ($expected -join '|') -or
    @($after.conditions.ref_name.include).Count -ne 1 -or
    $after.conditions.ref_name.include[0] -cne '~DEFAULT_BRANCH' -or
    $afterPr.Count -ne 1 -or
    $afterPr[0].parameters.required_approving_review_count -ne 0 -or
    $afterPr[0].parameters.require_last_push_approval -ne $false -or
    $afterPr[0].parameters.require_extra_approval_for_unattributed_changes -ne $false -or
    $afterPr[0].parameters.required_review_thread_resolution -ne $true -or
    $afterChecks.Count -ne 1 -or
    $afterChecks[0].parameters.strict_required_status_checks_policy -ne $true -or
    $afterRequired.Count -ne 1 -or
    $afterRequired[0].context -cne $context -or
    $afterRequired[0].integration_id -ne $app) { throw 'SOLO_POLICY_READBACK_MISMATCH' }

Write-Host 'SOLO_POLICY_READY: PR-only, GitHub Actions strict required check, no bypass, 0 additional human reviewers'
Write-Host 'AI reviews and exact-head human MERGE / later ACTIVATE remain separate project gates; no merge or signer dispatch executed'
