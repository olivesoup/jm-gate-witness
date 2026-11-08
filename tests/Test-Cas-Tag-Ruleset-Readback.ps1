# Native PowerShell STRICTMODE negative readback regression.
# Extracts ONLY the Assert-Rule function AST from reviewed script; never calls gh.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'scripts/Set-JM-Public-Nonce-CAS-Tag-Ruleset.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw 'CAS_ADMIN_SOURCE_SYNTAX_INVALID' }
$defs = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq 'Assert-Rule'
}, $true))
if ($defs.Count -ne 1) { throw 'CAS_ASSERT_FUNCTION_NOT_UNIQUE' }
$ruleName = 'JM-Public-Nonce-CAS-Append-Only'
$pattern = 'refs/tags/jm-cas/v1/*'
. ([ScriptBlock]::Create($defs[0].Extent.Text))
$fixture = @'
{"name":"JM-Public-Nonce-CAS-Append-Only","target":"tag","enforcement":"active","bypass_actors":[],"conditions":{"ref_name":{"include":["refs/tags/jm-cas/v1/*"],"exclude":[]}},"rules":[{"type":"update"},{"type":"deletion"}]}
'@
# Actual GitHub GET serialization omits update.parameters. Must not throw.
Assert-Rule ($fixture | ConvertFrom-Json)
$explicit = $fixture.Replace('{"type":"update"}', '{"type":"update","parameters":{"update_allows_fetch_and_merge":false}}')
Assert-Rule ($explicit | ConvertFrom-Json)
function Assert-Denied([string]$json, [string]$code) {
    $denied = $false
    try { Assert-Rule ($json | ConvertFrom-Json) }
    catch {
        if ($_.Exception.Message -cne $code) { throw }
        $denied = $true
    }
    if (-not $denied) { throw ('EXPECTED_DENIAL_MISSING_' + $code) }
}
Assert-Denied ($fixture.Replace('"enforcement":"active"', '"enforcement":"disabled"')) 'CAS_TAG_RULESET_SECURITY_MISMATCH'
Assert-Denied ($fixture.Replace('"bypass_actors":[]', '"bypass_actors":[{"actor_type":"User","actor_id":1}]')) 'CAS_TAG_RULESET_SECURITY_MISMATCH'
Assert-Denied ($fixture.Replace('refs/tags/jm-cas/v1/*', 'refs/tags/*')) 'CAS_TAG_RULESET_SECURITY_MISMATCH'
Assert-Denied ($fixture.Replace('{"type":"update"}', '{"type":"update","parameters":{"update_allows_fetch_and_merge":true}}')) 'CAS_TAG_UPDATE_RULE_PARAMETERS_PERMISSIVE_OR_UNEXPECTED'
Assert-Denied ($fixture.Replace('{"type":"update"}', '{"type":"update","parameters":{"unexpected":false}}')) 'CAS_TAG_UPDATE_RULE_PARAMETERS_PERMISSIVE_OR_UNEXPECTED'
Assert-Denied ($fixture.Replace('{"type":"update"},', '')) 'CAS_TAG_UPDATE_DELETE_PROTECTION_MISSING'
Write-Output 'CAS_NATIVE_STRICTMODE_READBACK_PASS_NO_ADMIN_MUTATION'
