# Creates exactly ONE additional public tag-protection ruleset.
# Does NOT touch protected master policy, merge, dispatch signer, execute VM or publish product checks.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'olivesoup/jm-gate-witness'
$ruleName = 'JM-Public-Nonce-CAS-Append-Only'
$pattern = 'refs/tags/jm-cas/v1/*'
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GH_CLI_MISSING' }

function Read-Ruleset([int]$id) {
  $raw = & gh api "repos/$repo/rulesets/$id"
  if ($LASTEXITCODE -ne 0) { throw 'CAS_RULESET_READBACK_UNAVAILABLE' }
  return (($raw -join [Environment]::NewLine) | ConvertFrom-Json)
}
function Assert-Rule($rs) {
  if ($null -eq $rs -or $rs.name -cne $ruleName -or $rs.target -cne 'tag' -or
    $rs.enforcement -cne 'active' -or
    @($rs.bypass_actors).Count -ne 0 -or
    @($rs.conditions.ref_name.include).Count -ne 1 -or
    $rs.conditions.ref_name.include[0] -cne $pattern -or
    @($rs.conditions.ref_name.exclude).Count -ne 0) { throw 'CAS_TAG_RULESET_SECURITY_MISMATCH' }
  $types = @($rs.rules | ForEach-Object { $_.type } | Sort-Object)
  if (($types -join '|') -cne 'deletion|update') { throw 'CAS_TAG_UPDATE_DELETE_PROTECTION_MISSING' }
  $update = @($rs.rules | Where-Object { $_.type -ceq 'update' })
  if ($update.Count -ne 1 -or
      $null -eq $update[0].parameters -or
      $update[0].parameters.update_allows_fetch_and_merge -ne $false) {
    throw 'CAS_TAG_UPDATE_RULE_PARAMETERS_MISSING_OR_PERMISSIVE'
  }
}

$raw = & gh api "repos/$repo/rulesets?per_page=100"
if ($LASTEXITCODE -ne 0) { throw 'CAS_RULESET_DISCOVERY_FAILED' }
$all = @(($raw -join [Environment]::NewLine) | ConvertFrom-Json)
$matched = @($all | Where-Object { $_.name -ceq $ruleName })
if ($matched.Count -gt 1) { throw 'CAS_TAG_RULESET_DUPLICATE' }
if ($matched.Count -eq 1) {
  Assert-Rule (Read-Ruleset -id ([int]$matched[0].id))
  Write-Output 'CAS_TAG_POLICY_READY: protected update/deletion, creation permitted, no bypass'
  exit 0
}

# Preserve existing branch master Ruleset id 26785842 entirely.
$body = [ordered]@{
  name = $ruleName
  target = 'tag'
  enforcement = 'active'
  bypass_actors = @()
  conditions = @{
    ref_name = @{ include = @($pattern); exclude = @() }
  }
  rules = @(@{type='update';parameters=@{update_allows_fetch_and_merge=$false}}, @{type='deletion'})
}
$tmp = [System.IO.Path]::GetTempFileName()
try {
  $json = ConvertTo-Json -InputObject $body -Depth 20 -Compress
  [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
  $createdRaw = & gh api --method POST "repos/$repo/rulesets" --input $tmp
  if ($LASTEXITCODE -ne 0) { throw 'CAS_TAG_RULESET_CREATE_FAILED_API_REJECTED_REVIEW_NATIVE_GITHUB_ERROR' }
} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
$created = ($createdRaw -join [Environment]::NewLine) | ConvertFrom-Json
if ($created.name -cne $ruleName -or $created.id -le 0) { throw 'CAS_TAG_RULESET_CREATE_RESPONSE_INVALID' }
Assert-Rule (Read-Ruleset -id ([int]$created.id))
Write-Output ('CAS_TAG_POLICY_READY: id=' + [string]$created.id + '; protected update/deletion, creation permitted, no bypass')
Write-Output 'CAS_REGISTER=BLOCK_UNTIL_SIGNED_SYNTHETIC_EXECUTION; PRODUCT_CAS_GATE=BLOCK'
