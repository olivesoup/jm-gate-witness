# Owner-only PUBLIC SYNTHETIC CAS nonce collision experiment. Not a product gate.
[CmdletBinding()]
param([switch]$ExecuteSyntheticRace,[string]$ExpectedScriptGitBlob='')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo='olivesoup/jm-gate-witness'
$ruleId=26789418
$ruleName='JM-Public-Nonce-CAS-Append-Only'
$pattern='refs/tags/jm-cas/v1/*'
if (-not $ExecuteSyntheticRace) { Write-Output 'CAS_RACE_NOT_ACTIVATED'; return }
if ($ExpectedScriptGitBlob -cnotmatch '^[a-f0-9]{40}$' -or [string]::IsNullOrEmpty($PSCommandPath)) { throw 'CAS_RACE_EXACT_SCRIPT_PIN_REQUIRED' }
$blob=@(& git hash-object --no-filters -- $PSCommandPath)
if ($LASTEXITCODE -ne 0 -or $blob.Count -ne 1 -or $blob[0] -cne $ExpectedScriptGitBlob) { throw 'CAS_RACE_SCRIPT_PIN_DRIFT' }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'CAS_RACE_GH_CLI_MISSING' }
function Read-Gh([string]$path) {
  $raw=& gh api $path
  if ($LASTEXITCODE -ne 0) { throw 'CAS_RACE_READ_ONLY_GET_FAILED' }
  return (($raw -join [Environment]::NewLine) | ConvertFrom-Json)
}
function Assert-Policy {
  $list=@(Read-Gh "repos/$repo/rulesets?per_page=100")
  $matching=@($list | Where-Object { $_.name -ceq $ruleName })
  if ($matching.Count -ne 1 -or $matching[0].id -ne $ruleId) { throw 'CAS_RACE_RULESET_DISCOVERY_MISMATCH' }
  $p=Read-Gh "repos/$repo/rulesets/$ruleId"
  if ($p.name -cne $ruleName -or $p.target -cne 'tag' -or $p.enforcement -cne 'active' -or
      @($p.bypass_actors).Count -ne 0 -or @($p.conditions.ref_name.include).Count -ne 1 -or
      $p.conditions.ref_name.include[0] -cne $pattern -or @($p.conditions.ref_name.exclude).Count -ne 0) {
    throw 'CAS_RACE_RULESET_UNTRUSTED'
  }
  $types=@($p.rules | ForEach-Object {$_.type} | Sort-Object)
  if (($types -join '|') -cne 'deletion|update') { throw 'CAS_RACE_RULES_NOT_EXACT' }
}
function Read-Master {
  $b=Read-Gh "repos/$repo/branches/master"
  if ($b.protected -ne $true -or $b.commit.sha -cnotmatch '^[a-f0-9]{40}$') { throw 'CAS_RACE_MASTER_UNPROTECTED' }
  return [string]$b.commit.sha
}
function Assert-Tag([string]$sha,[string]$name,[string]$message,[string]$master) {
  $t=Read-Gh "repos/$repo/git/tags/$sha"
  if ($t.sha -cne $sha -or $t.tag -cne $name -or
      $t.message -cne $message -or $t.object.sha -cne $master -or
      $t.object.type -cne 'commit') { throw 'CAS_RACE_TAG_OBJECT_MISMATCH' }
}
Assert-Policy
$master=Read-Master
$nonce=[guid]::NewGuid().ToString('N').ToLowerInvariant()
$name='jm-cas/v1/'+$nonce
$ref='refs/tags/'+$name
$plain='JM_PUBLIC_SYNTHETIC_CAS_RACE_V1|'+$nonce+'|'+$master+'|EVIDENCE_ONLY_NOT_GATE'
$hash=[Security.Cryptography.SHA256]::Create()
try {
  $digest=-join ($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($plain)) | ForEach-Object {$_.ToString('x2')})
} finally {$hash.Dispose()}
$message='{"schema":"JM_PUBLIC_SYNTHETIC_CAS_RACE_V1","nonce":"'+$nonce+'","claim_sha256":"'+$digest+'","protected_master_sha":"'+$master+'","product_gate":false}'+[Environment]::NewLine
$createdRaw=& gh api --method POST "repos/$repo/git/tags" -f "tag=$name" -f "message=$message" -f "object=$master" -f 'type=commit'
if ($LASTEXITCODE -ne 0) { throw 'CAS_RACE_TAG_OBJECT_CREATE_FAILED' }
$created=($createdRaw -join [Environment]::NewLine) | ConvertFrom-Json
if ($created.sha -cnotmatch '^[a-f0-9]{40}$') { throw 'CAS_RACE_TAG_SHA_INVALID' }
$tagSha=[string]$created.sha
Assert-Tag $tagSha $name $message $master
Assert-Policy
if ((Read-Master) -cne $master) { throw 'CAS_RACE_MASTER_MOVED_BEFORE_COMPETE' }
$barrier=Join-Path $env:TEMP ('JM-CAS-GO-'+$nonce)
$ready1=Join-Path $env:TEMP ('JM-CAS-R1-'+$nonce)
$ready2=Join-Path $env:TEMP ('JM-CAS-R2-'+$nonce)
$jobs=@()
try {
  $writer={
    param($repository,$theRef,$theSha,$go,$ready)
    $ErrorActionPreference='Continue'
    [IO.File]::WriteAllText($ready,'READY')
    $until=[DateTime]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath $go -PathType Leaf)) {
      if ([DateTime]::UtcNow -gt $until) { return [pscustomobject]@{ code=99; conflict=$false; ok=$false } }
      Start-Sleep -Milliseconds 30
    }
    $startedUtc=[DateTime]::UtcNow.ToString('o')
    $output=@(& gh api --method POST "repos/$repository/git/refs" -f "ref=$theRef" -f "sha=$theSha" 2>&1)
    $code=[int]$LASTEXITCODE
    $finishedUtc=[DateTime]::UtcNow.ToString('o')
    $msg=$output -join [Environment]::NewLine
    $verified=$false
    if ($code -eq 0) {
      try {
        $parsed=$msg | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $parsed -and
            $parsed -is [pscustomobject] -and
            $parsed.ref -ceq $theRef -and
            $parsed.object.sha -ceq $theSha -and
            $parsed.object.type -ceq 'tag') { $verified=$true }
      } catch { $verified=$false }
    }
    $conflictStatus=0
    if ($code -ne 0) {
      $m=[regex]::Match($msg,'HTTP (409|422)(?![0-9])')
      if ($m.Success) { $conflictStatus=[int]$m.Groups[1].Value }
    }
    return [pscustomobject]@{
      code=$code
      conflict=[bool]($conflictStatus -eq 409 -or $conflictStatus -eq 422)
      httpConflictStatus=$conflictStatus
      ok=[bool]$verified
      startedUtc=$startedUtc
      finishedUtc=$finishedUtc
    }
  }
  $jobs+=Start-Job -ScriptBlock $writer -ArgumentList $repo,$ref,$tagSha,$barrier,$ready1
  $jobs+=Start-Job -ScriptBlock $writer -ArgumentList $repo,$ref,$tagSha,$barrier,$ready2
  $deadline=[DateTime]::UtcNow.AddSeconds(20)
  while (-not ((Test-Path -LiteralPath $ready1) -and (Test-Path -LiteralPath $ready2))) {
    if ([DateTime]::UtcNow -gt $deadline) { throw 'CAS_RACE_WRITERS_NEVER_READY' }
    Start-Sleep -Milliseconds 50
  }
  [IO.File]::WriteAllText($barrier,'GO')
  $finished=@(Wait-Job -Job $jobs -Timeout 45)
  if ($finished.Count -ne 2) { throw 'CAS_RACE_WRITER_TIMEOUT' }
  $results=@($jobs | ForEach-Object {Receive-Job -Job $_ -ErrorAction Stop})
  if ($results.Count -ne 2 -or
      @($results | Where-Object {$_.ok -eq $true -and $_.code -eq 0}).Count -ne 1 -or
      @($results | Where-Object {$_.conflict -eq $true -and $_.code -ne 0}).Count -ne 1) {
    throw 'CAS_RACE_ONE_WINNER_ONE_CONFLICT_NOT_PROVEN'
  }
  Assert-Policy
  if ((Read-Master) -cne $master) { throw 'CAS_RACE_MASTER_MOVED_AFTER_COMPETE' }
  $observed=Read-Gh "repos/$repo/git/ref/tags/$name"
  if ($observed.ref -cne $ref -or $observed.object.sha -cne $tagSha -or
      $observed.object.type -cne 'tag') { throw 'CAS_RACE_PROTECTED_REF_READBACK_MISMATCH' }
  Assert-Tag $tagSha $name $message $master
  $receipt=[ordered]@{
    schema='JM_PUBLIC_SYNTHETIC_LIVE_CAS_RACE_V1'
    status='CAS_SYNTHETIC_ONE_WINNER_NOT_PRODUCT_GATE'
    nonce=$nonce
    tag_ref=$ref
    tag_sha=$tagSha
    master_sha=$master
    script_blob=$blob[0]
    writer_codes=@($results | ForEach-Object {[int]$_.code})
    writer_conflict_http_status=@($results | ForEach-Object {[int]$_.httpConflictStatus})
    writer_started_utc=@($results | ForEach-Object { [string]$_.startedUtc })
    writer_finished_utc=@($results | ForEach-Object { [string]$_.finishedUtc })
    barrier_note='Ready-barrier is not proof of simultaneous GitHub API ingress'
    protected_ruleset=$ruleId
    exactly_one_winner=$true
    second_writer_conflicted=$true
    globally_nonrollback_proven=$false
    product_real_gate=$false
  }
  $receiptPath=Join-Path 'D:\JavaModernization\Testing' ('JM-CAS-Synthetic-Race-'+$nonce+'.json')
  [IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json -Compress -Depth 8),[Text.UTF8Encoding]::new($false))
  Write-Output ('CAS_SYNTHETIC_LIVE_RACE_PASS_ONE_WINNER_ONE_CONFLICT_NONCE='+$nonce)
  Write-Output 'CAS_PRODUCT_GLOBAL_NONROLLBACK_AND_VM_GATE_BLOCK'
} finally {
  foreach ($job in $jobs) {
    if ($job.State -notin @('Completed','Failed','Stopped')) { Stop-Job -Job $job -ErrorAction SilentlyContinue }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
  }
  foreach ($path in @($barrier,$ready1,$ready2)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}
