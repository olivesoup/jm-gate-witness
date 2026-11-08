# Native PowerShell negative tests of the REAL writer scriptblock; no GitHub API calls.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$source=Join-Path $root 'scripts/Test-JM-Public-CAS-SyntheticRace.ps1'
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'CAS_RACE_SOURCE_PARSE_FAILED' }
$writers=@($ast.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
  $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
  $node.Left.VariablePath.UserPath -ceq 'writer'
},$true))
if ($writers.Count -ne 1) { throw 'CAS_RACE_WRITER_BLOCK_NOT_UNIQUE' }
$writer=[ScriptBlock]::Create($writers[0].Right.Extent.Text)
$theRef='refs/tags/jm-cas/v1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$sha='b' * 40
$go=Join-Path $env:TEMP ('cas-unit-go-'+[guid]::NewGuid().ToString('N'))
$ready=Join-Path $env:TEMP ('cas-unit-ready-'+[guid]::NewGuid().ToString('N'))
$script:mockMessage=''
$script:mockCode=0
function gh {
  $global:LASTEXITCODE=[int]$script:mockCode
  Write-Output $script:mockMessage
}
try {
  [IO.File]::WriteAllText($go,'GO')
  $script:mockMessage='{"ref":"'+$theRef+'","object":{"sha":"'+$sha+'","type":"tag"}}'
  $script:mockCode=0
  $valid= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if (-not $valid.ok -or $valid.conflict -or $valid.code -ne 0) { throw 'CAS_JSON_VALID_RESPONSE_REJECTED' }

  # This is the exact previous defect: two substrings in text must NOT pass.
  $script:mockMessage='DIAGNOSTIC MESSAGE: '+$theRef+' / '+$sha
  $fake= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if ($fake.ok -or $fake.conflict) { throw 'CAS_SUBSTRING_SPOOF_ACCEPTED' }

  $script:mockMessage='{"ref":"'+$theRef+'","object":{"sha":"'+$sha+'","type":"commit"}}'
  $wrongType= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if ($wrongType.ok) { throw 'CAS_WRONG_OBJECT_TYPE_ACCEPTED' }

  $script:mockMessage='{"ref":"refs/tags/other","object":{"sha":"'+$sha+'","type":"tag"}}'
  $wrongRef= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if ($wrongRef.ok) { throw 'CAS_WRONG_REF_ACCEPTED' }

  $script:mockCode=1
  $script:mockMessage='gh: Validation Failed (HTTP 422)'
  $loser= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if ($loser.ok -or -not $loser.conflict -or $loser.httpConflictStatus -ne 422) {
    throw 'CAS_REAL_HTTP_CONFLICT_NOT_CAPTURED'
  }
  $script:mockMessage='gh: Bad credentials (HTTP 401)'
  $badCredential= & $writer 'olivesoup/jm-gate-witness' $theRef $sha $go $ready
  if ($badCredential.ok -or $badCredential.conflict) { throw 'CAS_401_MASQUERADING_CONFLICT' }

  # Simulate two successful writer objects; production count guard must reject.
  $results=@($valid,$valid)
  $wins=@($results | Where-Object { $_.ok -eq $true -and $_.code -eq 0 }).Count
  if ($wins -ne 2) { throw 'CAS_DUPLICATE_WINNER_FIXTURE_INVALID' }
  $text=[IO.File]::ReadAllText($source)
  if ($text -notmatch 'CAS_RACE_ONE_WINNER_ONE_CONFLICT_NOT_PROVEN' -or
      $text -match '\.Contains\(\$theRef\)' -or
      $text -match '\.Contains\(\$theSha\)') {
    throw 'CAS_PRODUCTION_EXCLUSIVITY_GUARD_OR_PARSER_MISSING'
  }
  Write-Output 'CAS_RACE_REAL_WORKER_NEGATIVE_POWERSHELL_PASS_NO_GITHUB_API'
} finally {
  Remove-Item -LiteralPath $go,$ready -Force -ErrorAction SilentlyContinue
}
