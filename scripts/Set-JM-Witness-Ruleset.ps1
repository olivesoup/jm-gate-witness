# One-time admin update; no PR merge, no signer activation. Requires 'gh auth login' as repo admin.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'olivesoup/jm-gate-witness'
$id = 26785842
$context = 'jm-witness-policy'
$app = 15368 # GitHub Actions app, observed native run 42447026404
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'gh CLI not installed' }
$raw = & gh api "repos/$repo/rulesets/$id"
if ($LASTEXITCODE -ne 0) { throw 'Ruleset read requires repo admin permission' }
$rs = ($raw -join [Environment]::NewLine) | ConvertFrom-Json
if ($rs.id -ne $id -or $rs.enforcement -cne 'active' -or $rs.name -cne 'JM-Witness-Master-Protection' -or $rs.target -cne 'branch') { throw 'Unexpected ruleset; REFUSE' }
if (@($rs.bypass_actors).Count -ne 0 -or @($rs.conditions.ref_name.include).Count -ne 1 -or $rs.conditions.ref_name.include[0] -cne '~DEFAULT_BRANCH' -or @($rs.conditions.ref_name.exclude).Count -ne 0) { throw 'Ruleset boundaries changed; REFUSE' }
$types = @($rs.rules | ForEach-Object { $_.type } | Sort-Object)
$initial = @('deletion','non_fast_forward','pull_request','required_linear_history' | Sort-Object)
$review = @($rs.rules | Where-Object { $_.type -eq 'pull_request' })[0]
if (($types -join ',') -cne ($initial -join ',')) {
    $status = @($rs.rules | Where-Object { $_.type -eq 'required_status_checks' })
    if ($status.Count -eq 1 -and $review.parameters.required_approving_review_count -ge 1 -and $review.parameters.require_last_push_approval -eq $true -and $status[0].parameters.strict_required_status_checks_policy -eq $true -and @($status[0].parameters.required_status_checks).Count -eq 1 -and $status[0].parameters.required_status_checks[0].context -ceq $context -and $status[0].parameters.required_status_checks[0].integration_id -eq $app) {
        Write-Host 'POLICY_READY: already configured'; exit 0
    }
    throw 'Unexpected rules; REFUSE to override'
}
if ($review.parameters.required_approving_review_count -ne 0 -or $review.parameters.require_last_push_approval -eq $true) { throw 'Unexpected review state; REFUSE' }
$review.parameters.required_approving_review_count = 1
$review.parameters.dismiss_stale_reviews_on_push = $true
$review.parameters.require_last_push_approval = $true
$review.parameters.required_review_thread_resolution = $true
$rules = @($rs.rules)
$rules += [pscustomobject]@{ type = 'required_status_checks'; parameters = [pscustomobject]@{ strict_required_status_checks_policy = $true; required_status_checks = @([pscustomobject]@{ context = $context; integration_id = $app }) } }
$body = [pscustomobject]@{ name = $rs.name; target = 'branch'; enforcement = 'active'; bypass_actors = @(); conditions = $rs.conditions; rules = $rules }
$temp = [System.IO.Path]::GetTempFileName()
try {
    $json = ConvertTo-Json -InputObject $body -Depth 32 -Compress
    [System.IO.File]::WriteAllText($temp, $json, [System.Text.UTF8Encoding]::new($false))
    & gh api --method PUT "repos/$repo/rulesets/$id" --input $temp | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'GitHub ruleset update FAILED' }
}
finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
$raw = & gh api "repos/$repo/rulesets/$id"
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify ruleset' }
$check = ($raw -join [Environment]::NewLine) | ConvertFrom-Json
$review = @($check.rules | Where-Object { $_.type -eq 'pull_request' })[0]
$status = @($check.rules | Where-Object { $_.type -eq 'required_status_checks' })[0]
$required = @($status.parameters.required_status_checks)
if ($check.enforcement -cne 'active' -or @($check.bypass_actors).Count -ne 0 -or $review.parameters.required_approving_review_count -ne 1 -or $review.parameters.dismiss_stale_reviews_on_push -ne $true -or $review.parameters.require_last_push_approval -ne $true -or $review.parameters.required_review_thread_resolution -ne $true -or $status.parameters.strict_required_status_checks_policy -ne $true -or $required.Count -ne 1 -or $required[0].context -cne $context -or $required[0].integration_id -ne $app) { throw 'POLICY_READBACK_MISMATCH' }
Write-Host 'POLICY_READY: independent approval 1, last-push approval, strict GitHub Actions required check, no bypass'
Write-Host 'No merge, signer, Host or CAS authorization was issued'
