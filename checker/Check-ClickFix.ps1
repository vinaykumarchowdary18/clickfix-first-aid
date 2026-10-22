<#
.SYNOPSIS
    ClickFix First Aid - PC check. Looks for signs that a ClickFix or fake
    CAPTCHA command was run on this Windows PC.

.DESCRIPTION
    READ-ONLY. This script changes nothing on your PC and sends nothing
    anywhere. It reads:
      - the Run box history (what was pasted into Win+R)
      - the File Explorer address bar history (the "FileFix" trick)
      - PowerShell command history
      - programs created recently in temporary and app-data folders
      - programs installed recently (Windows Installer log)
      - things set to start automatically (Run keys, Startup folders, scheduled tasks)
    Each command is checked with the same rules as the ClickFix First Aid
    browser extension.

    HOW TO RUN IT: right-click this file and choose "Run with PowerShell".
    Never paste commands from a website to run it. That is exactly the trick
    this project protects you from.

.PARAMETER Days
    How many days back to look for new programs and installs. Default 30.

.PARAMETER Json
    Print the results as JSON instead of a readable report.

.PARAMETER NoPause
    Do not wait for Enter before closing.

.NOTES
    ClickFix First Aid v0.1.0 - free and open source (MIT license).
    Exit codes: 0 = nothing found, 1 = things to review, 2 = signs of an attack.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$Days = 30,
    [switch]$Json,
    [switch]$NoPause
)

Set-StrictMode -Version 2.0

$CfaVersion = '0.1.0'
$CfaGuideUrl = 'docs/recovery.html in the ClickFix First Aid download'

# Detection rules, generated from rules/clickfix-rules.json. Do not edit here.
$CfaRulesJson = @'
{"name":"clickfix-first-aid-rules","version":"1.0.0","updated":"2026-10-22","notes":"Patterns must work in both JavaScript and .NET regex engines. All patterns are matched case-insensitively.","limits":{"maxChars":20000,"maxLinesForAutoBlock":5},"command":{"executors":[{"id":"powershell","label":"Starts PowerShell","pattern":"\\b(?:powershell|pwsh)(?:\\.exe)?\\b"},{"id":"cmd","label":"Starts the Windows command prompt","pattern":"\\bcmd(?:\\.exe)?\\s*/[ckr]\\b|\\bcmd\\.exe\\b"},{"id":"mshta","label":"Uses mshta, a Windows tool attackers use to run web code","pattern":"\\bmshta(?:\\.exe)?\\b"},{"id":"msiexec","label":"Runs a Windows installer","pattern":"\\bmsiexec(?:\\.exe)?\\b"},{"id":"rundll32","label":"Uses rundll32 to load a program library","pattern":"\\brundll32(?:\\.exe)?\\b"},{"id":"regsvr32","label":"Uses regsvr32 to load a program library","pattern":"\\bregsvr32(?:\\.exe)?\\b"},{"id":"script-host","label":"Runs a Windows script file","pattern":"\\b[wc]script(?:\\.exe)?\\b"},{"id":"certutil","label":"Uses certutil, often abused to download files","pattern":"\\bcertutil(?:\\.exe)?\\b"},{"id":"bitsadmin","label":"Uses bitsadmin, often abused to download files","pattern":"\\bbitsadmin(?:\\.exe)?\\b"},{"id":"conhost","label":"Starts a hidden console window","pattern":"\\bconhost(?:\\.exe)?\\b"},{"id":"finger","label":"Uses the finger tool to fetch commands from a server","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"dotnet-lolbin","label":"Uses a .NET build tool to run code","pattern":"\\b(?:msbuild|installutil|regasm|regsvcs)(?:\\.exe)?\\b"},{"id":"schtasks","label":"Creates a scheduled task","pattern":"\\bschtasks(?:\\.exe)?\\b"},{"id":"invoke-expression","label":"Runs text as code (Invoke-Expression)","pattern":"\\b(?:iex|invoke-expression)\\b"},{"id":"osascript","label":"Runs an AppleScript on a Mac","pattern":"\\bosascript\\b"},{"id":"pipe-to-shell","label":"Pipes downloaded text straight into a shell","pattern":"\\|\\s*(?:sudo\\s+)?(?:ba|z|da)?sh\\b"},{"id":"shell-c","label":"Runs a shell command string","pattern":"\\b(?:ba|z)?sh\\s+-c\\b"}],"remote":[{"id":"url","label":"Contains a web address","pattern":"\\b(?:https?|ftp)://[^\\s\"'<>]+"},{"id":"unc-path","label":"Loads a file from a remote network share","pattern":"\\\\\\\\[a-z0-9._-]+(?:@ssl)?(?:@\\d+)?\\\\"},{"id":"downloader","label":"Downloads something from the internet","pattern":"\\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadstring|downloadfile|downloaddata|net\\.webclient|curl(?:\\.exe)?|wget(?:\\.exe)?)\\b"},{"id":"finger-host","label":"Asks a remote server for commands (finger)","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"ip-address","label":"Contains an IP address","pattern":"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b"},{"id":"bare-domain","label":"Contains an unusual web domain","pattern":"\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\"']|$)"}],"encoded":[{"id":"ps-encoded","label":"Hides its real instructions in encoded text","pattern":"\\s-e(?:nc|ncodedcommand|c)?\\s+[a-z0-9+/=]{20,}"},{"id":"from-base64","label":"Decodes hidden text before running it","pattern":"frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b|\\batob\\("},{"id":"long-base64","label":"Contains a long block of encoded text","pattern":"[a-z0-9+/]{120,}={0,2}"}],"stealth":[{"id":"hidden-window","label":"Hides its window so you cannot see it running","weight":25,"pattern":"\\s-w(?:in(?:dow(?:style)?)?)?\\s+(?:h(?:idden)?|1)\\b"},{"id":"policy-bypass","label":"Turns off PowerShell safety settings","weight":10,"pattern":"\\s-(?:nop(?:rofile)?|ep\\s+bypass|exec(?:utionpolicy)?\\s+bypass|noni(?:nteractive)?)\\b"},{"id":"encoded","label":"Hides its real instructions in encoded text","weight":30,"pattern":"\\s-e(?:nc|ncodedcommand|c)?\\s+[a-z0-9+/=]{20,}|frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b"},{"id":"caret-obfuscation","label":"Disguised with ^ symbols to dodge antivirus","weight":25,"pattern":"\\w\\^\\w\\^?\\w"},{"id":"backtick-obfuscation","label":"Disguised with ` symbols to dodge antivirus","weight":20,"pattern":"[a-z]`[a-z]+`[a-z]"},{"id":"string-splitting","label":"Splits words apart to dodge antivirus","weight":15,"pattern":"['\"]\\s*\\+\\s*['\"]"},{"id":"env-substring","label":"Builds words from pieces of system variables","weight":25,"pattern":"%[a-z_]+:~-?\\d+,-?\\d+%"},{"id":"headless-console","label":"Runs in an invisible console","weight":25,"pattern":"\\bconhost(?:\\.exe)?\\s+--headless"},{"id":"temp-drop","label":"Saves a file into a temporary or app-data folder","weight":10,"pattern":"%temp%|\\$env:temp|%appdata%|\\$env:appdata|%localappdata%|\\$env:localappdata|%programdata%|\\\\appdata\\\\|/tmp/"},{"id":"quiet-install","label":"Installs a program silently, without asking you","weight":20,"pattern":"\\bmsiexec(?:\\.exe)?\\b[^\\n]*\\s/q[nb]?\\b"},{"id":"start-minimized","label":"Starts minimized so you do not notice it","weight":15,"pattern":"\\bstart\\s+(?:\"\"\\s+)?/min\\b"},{"id":"raw-ip","label":"Connects to a raw IP address instead of a website name","weight":20,"pattern":"(?:https?://|\\\\\\\\|@)\\d{1,3}(?:\\.\\d{1,3}){3}\\b"},{"id":"suspicious-domain","label":"Uses a cheap web domain popular with attackers","weight":15,"pattern":"\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\"']|$)"},{"id":"remote-share","label":"Runs code straight from a remote network share","weight":25,"pattern":"\\\\\\\\[a-z0-9._-]+(?:@ssl)?(?:@\\d+)?\\\\"},{"id":"pipe-to-cmd","label":"Feeds downloaded text straight into the command prompt","weight":20,"pattern":"\\|\\s*cmd(?:\\.exe)?\\b"},{"id":"space-padding","label":"Pads the command with spaces to hide part of it","weight":25,"pattern":"\\S {25,}\\S"}],"decoys":[{"id":"fake-verification-comment","label":"Hides fake \"I am not a robot\" text after the real command","pattern":"(?:#|::|\\brem\\b)[^\\n]{0,200}?(?:verif|captcha|robot|human|cloudflare|turnstile|security\\s*check|ray\\s*id|identity|\\u2705|\\u2714)"},{"id":"fake-file-path","label":"Disguises the command as a file path (FileFix trick)","pattern":"#\\s*[a-z]:\\\\[^\\n]*\\.(?:docx?|pdf|xlsx?|pptx?|txt|csv)\\b"}]},"page":{"runShortcut":[{"id":"win-r","label":"Tells you to press Windows + R","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,30}?(?:\\+|\\band\\b|&)\\s*[\"'\\u201c\\u201d]?r\\b|\\bwindows\\s*(?:logo\\s*)?(?:key|button)\\b[^\\n]{0,40}?\\bpress\\s*[\"'\\u201c\\u201d]?r\\b"},{"id":"win-x","label":"Tells you to press Windows + X","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,30}?(?:\\+|\\band\\b|&)\\s*[\"'\\u201c\\u201d]?x\\b"},{"id":"run-dialog","label":"Mentions the Run dialog","pattern":"\\brun\\s+(?:dialog|box|window|prompt)\\b"},{"id":"open-terminal","label":"Tells you to open a terminal","pattern":"\\bopen\\s+(?:the\\s+)?(?:powershell|windows\\s+terminal|terminal|command\\s+prompt)\\b"},{"id":"explorer-address-bar","label":"Tells you to paste into File Explorer (FileFix)","pattern":"file\\s*explorer[^\\n]{0,120}?address\\s*bar|address\\s*bar[^\\n]{0,120}?file\\s*explorer|\\bctrl\\s*\\+\\s*l\\b"},{"id":"mac-terminal","label":"Tells you to open Terminal on a Mac","pattern":"(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*space\\b"}],"paste":[{"id":"paste","label":"Tells you to paste","pattern":"\\bctrl\\s*\\+\\s*v\\b|(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*v\\b|\\bpaste\\b"}],"verifyTheme":[{"id":"verify","label":"Pretends to be a human or security check","pattern":"\\bverif(?:y|ication)\\b|captcha|\\bi\\s*(?:'|\\u2019)?\\s*a?m\\s+not\\s+a\\s+robot\\b|\\bare\\s+you\\s+(?:a\\s+)?human\\b|\\bhuman\\s+check\\b|cloudflare|turnstile|\\bsecurity\\s+check\\b|\\bray\\s+id\\b|\\bprove\\s+you\\b"},{"id":"fake-fix","label":"Pretends you need to fix an error","pattern":"\\bfix\\s+(?:the\\s+|this\\s+)?(?:error|issue|problem)\\b|\\bupdate\\s+your\\s+browser\\b|\\bbrowser\\s+update\\b|\\bfailed\\s+to\\s+load\\b"}]},"verdict":{"stealthBlockAt":25,"stealthOnlyBlockAt":50}}
'@

# ---------------------------------------------------------------------------
# Detection engine (a PowerShell copy of engine/detector.js, without the
# web-page part, which only makes sense inside a browser).
# ---------------------------------------------------------------------------

function New-CfaDetector {
    param([Parameter(Mandatory = $true)] $Rules)
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $compile = {
        param($list)
        $out = New-Object System.Collections.ArrayList
        foreach ($r in @($list)) {
            $w = 0
            if ($r.PSObject.Properties['weight']) { $w = [int]$r.weight }
            [void]$out.Add([pscustomobject]@{
                Id     = [string]$r.id
                Label  = [string]$r.label
                Weight = $w
                Re     = New-Object System.Text.RegularExpressions.Regex -ArgumentList $r.pattern, $opts
            })
        }
        return , $out
    }
    $maxChars = 20000; $maxLines = 5; $blockAt = 25; $stealthOnlyAt = 50
    if ($Rules.PSObject.Properties['limits']) {
        if ($Rules.limits.PSObject.Properties['maxChars']) { $maxChars = [int]$Rules.limits.maxChars }
        if ($Rules.limits.PSObject.Properties['maxLinesForAutoBlock']) { $maxLines = [int]$Rules.limits.maxLinesForAutoBlock }
    }
    if ($Rules.PSObject.Properties['verdict']) {
        if ($Rules.verdict.PSObject.Properties['stealthBlockAt']) { $blockAt = [int]$Rules.verdict.stealthBlockAt }
        if ($Rules.verdict.PSObject.Properties['stealthOnlyBlockAt']) { $stealthOnlyAt = [int]$Rules.verdict.stealthOnlyBlockAt }
    }
    return [pscustomobject]@{
        Executors     = & $compile $Rules.command.executors
        Remote        = & $compile $Rules.command.remote
        Encoded       = & $compile $Rules.command.encoded
        Stealth       = & $compile $Rules.command.stealth
        Decoys        = & $compile $Rules.command.decoys
        MaxChars      = $maxChars
        MaxLines      = $maxLines
        BlockAt       = $blockAt
        StealthOnlyAt = $stealthOnlyAt
    }
}

function Get-CfaMatches {
    param($Group, [string]$Text, [hashtable]$Seen)
    $found = New-Object System.Collections.ArrayList
    foreach ($r in $Group) {
        if ($Seen -and $Seen.ContainsKey($r.Id)) { continue }
        if ($r.Re.IsMatch($Text)) {
            if ($Seen) { $Seen[$r.Id] = $true }
            [void]$found.Add($r)
        }
    }
    return , $found
}

function ConvertTo-CfaNormalized {
    # Undo simple disguises: c^m^d, p`ow`ershell, 'pow'+'ershell', p""owershell
    param([string]$Text)
    $s = $Text -replace '\^', ''
    $s = $s -replace '`', ''
    $s = $s -replace '([''"])\s*\+\s*\1', ''
    $s = $s -replace '""', ''
    return $s
}

function Test-CfaCommand {
    param([Parameter(Mandatory = $true)] $Detector, [AllowEmptyString()][string]$Text)
    $raw = [string]$Text
    if ($raw.Length -gt $Detector.MaxChars) { $raw = $raw.Substring(0, $Detector.MaxChars) }
    $norm = ConvertTo-CfaNormalized $raw
    $lines = @($raw -split "\r\n|\r|\n" | Where-Object { $_ -match '\S' }).Count

    $exec = Get-CfaMatches $Detector.Executors $norm $null
    $remote = Get-CfaMatches $Detector.Remote $norm $null
    $encoded = Get-CfaMatches $Detector.Encoded $raw $null
    $seen = @{}
    $stealth = New-Object System.Collections.ArrayList
    foreach ($m in (Get-CfaMatches $Detector.Stealth $raw $seen)) { [void]$stealth.Add($m) }
    foreach ($m in (Get-CfaMatches $Detector.Stealth $norm $seen)) { [void]$stealth.Add($m) }
    $decoys = Get-CfaMatches $Detector.Decoys $raw $null

    $score = 0
    foreach ($m in $stealth) { $score += $m.Weight }
    $hasExec = $exec.Count -gt 0
    $danger = $hasExec -and ($remote.Count -gt 0 -or $encoded.Count -gt 0)

    $why = New-Object System.Collections.ArrayList
    foreach ($m in @($exec | Select-Object -First 2)) { [void]$why.Add($m.Label) }
    if ($remote.Count) { [void]$why.Add($remote[0].Label) }
    if ($encoded.Count) { [void]$why.Add($encoded[0].Label) }

    $reasons = New-Object System.Collections.ArrayList
    $add = { param($items) foreach ($i in $items) { if (-not $reasons.Contains($i)) { [void]$reasons.Add($i) } } }
    $verdict = 'allow'; $rule = ''

    if ($hasExec) {
        if ($decoys.Count -gt 0) {
            & $add @($decoys | ForEach-Object { $_.Label }); & $add $why; & $add @($stealth | ForEach-Object { $_.Label })
            $verdict = 'block'; $rule = 'decoy'
        } elseif ($danger -and $score -ge $Detector.BlockAt) {
            & $add $why; & $add @($stealth | ForEach-Object { $_.Label })
            if ($lines -gt $Detector.MaxLines) { $verdict = 'warn'; $rule = 'stealthy-but-long' }
            else { $verdict = 'block'; $rule = 'stealthy-download-and-run' }
        } elseif ($danger) {
            & $add $why; & $add @($stealth | ForEach-Object { $_.Label })
            $verdict = 'warn'; $rule = 'download-and-run'
        } elseif ($score -ge $Detector.StealthOnlyAt -and $lines -le $Detector.MaxLines) {
            & $add $why; & $add @($stealth | ForEach-Object { $_.Label })
            $verdict = 'block'; $rule = 'heavily-disguised'
        }
    }

    return [pscustomobject]@{
        Verdict = $verdict
        Rule    = $rule
        Reasons = @($reasons)
        Text    = $raw
    }
}

function Get-CfaDefanged {
    param([string]$Text, [int]$Max = 300)
    $s = [string]$Text
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + ' ...' }
    return ($s -replace '\b(h)(tt)(ps?)://', '$1xx$3[://]')
}

function Test-CfaRandomName {
    # True for names like "NYcTodYVA0": one word, mixed case, letters and digits.
    param([string]$Name)
    $n = ([string]$Name).Trim()
    if ($n -notmatch '^[A-Za-z0-9]{8,}$') { return $false }
    $hasDigit = $n -match '[0-9]'
    $switches = ([regex]::Matches($n, '(?<=[a-z])[A-Z]|(?<=[A-Z])[a-z]')).Count
    # "NYcTodYVA0" -> digit + 4 case switches. "GoogleChromeBeta" -> no digit, 5 switches: not flagged.
    return (($hasDigit -and $switches -ge 3) -or $switches -ge 6)
}

# ---------------------------------------------------------------------------
# Evidence collection (Windows only). Reads, never writes.
# ---------------------------------------------------------------------------

function Get-CfaEvidence {
    param([int]$Days = 30)
    $since = (Get-Date).AddDays(-$Days)
    $ev = [ordered]@{
        Collected   = (Get-Date).ToString('s')
        Days        = $Days
        RunMRU      = @()
        TypedPaths  = @()
        PSHistory   = @()
        TempFiles   = @()
        MsiInstalls = @()
        Autoruns    = @()
        Errors      = @()
    }

    # 1. Run box history (Win+R). Newest first. Values end with "\1".
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
        if (Test-Path -LiteralPath $k) {
            $p = Get-ItemProperty -LiteralPath $k
            $list = @()
            if ($p.PSObject.Properties['MRUList']) {
                foreach ($ch in ([string]$p.MRUList).ToCharArray()) {
                    $prop = $p.PSObject.Properties[[string]$ch]
                    if ($prop) { $list += ([string]$prop.Value -replace '\\1$', '') }
                }
            }
            $ev.RunMRU = $list
        }
    } catch { $ev.Errors += "Run box history: $($_.Exception.Message)" }

    # 2. File Explorer address bar history (FileFix).
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
        if (Test-Path -LiteralPath $k) {
            $p = Get-ItemProperty -LiteralPath $k
            $items = @()
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -match '^url(\d+)$') { $items += [pscustomobject]@{ N = [int]$Matches[1]; V = [string]$prop.Value } }
            }
            $ev.TypedPaths = @($items | Sort-Object N | ForEach-Object { $_.V })
        }
    } catch { $ev.Errors += "File Explorer history: $($_.Exception.Message)" }

    # 3. PowerShell history (last 3000 lines of each history file).
    try {
        $dir = $null
        if ($env:APPDATA) { $dir = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine' }
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            $lines = @()
            foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*_history.txt' -File -ErrorAction SilentlyContinue)) {
                $lines += @(Get-Content -LiteralPath $f.FullName -Tail 3000 -ErrorAction SilentlyContinue)
            }
            $ev.PSHistory = $lines
        }
    } catch { $ev.Errors += "PowerShell history: $($_.Exception.Message)" }

    # 4. Programs and scripts created recently in temporary / app-data folders.
    try {
        $exts = @('.exe', '.msi', '.hta', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.bat', '.cmd', '.scr', '.com', '.pif')
        $roots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC, $env:ProgramData) | Where-Object { $_ } | Select-Object -Unique
        $files = @()
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $depth = 1
            foreach ($f in @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth $depth -Force -ErrorAction SilentlyContinue)) {
                if ($exts -notcontains $f.Extension.ToLowerInvariant()) { continue }
                if ($f.CreationTime -lt $since) { continue }
                $signer = ''; $status = 'NotSigned'
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
                    $status = [string]$sig.Status
                    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false) }
                } catch { $status = 'Unknown' }
                $files += [pscustomobject]@{
                    Path    = $f.FullName
                    Created = $f.CreationTime.ToString('yyyy-MM-dd HH:mm')
                    Size    = $f.Length
                    Signed  = ($status -eq 'Valid')
                    Signer  = $signer
                }
            }
        }
        $ev.TempFiles = $files
    } catch { $ev.Errors += "Recent files: $($_.Exception.Message)" }

    # 5. Programs installed recently (Windows Installer events).
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033; StartTime = $since } -ErrorAction Stop)
        $installs = @()
        foreach ($e in $events) {
            $msg = [string]$e.Message
            $name = ''; $maker = ''
            if ($msg -match 'Product Name:\s*(.*?)\.\s*Product Version') { $name = $Matches[1] }
            if ($msg -match 'Manufacturer:\s*(.*?)\.\s*Installation') { $maker = $Matches[1] }
            $installs += [pscustomobject]@{ Name = $name; Manufacturer = $maker; Time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
        }
        $ev.MsiInstalls = $installs
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { $ev.Errors += "Installer log: $($_.Exception.Message)" }
    }

    # 6. Things that start automatically.
    $auto = @()
    foreach ($k in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
        try {
            if (-not (Test-Path -LiteralPath $k)) { continue }
            $p = Get-ItemProperty -LiteralPath $k
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                $auto += [pscustomobject]@{ Where = ($k -replace '^HK(CU|LM):\\Software\\', 'HK$1 '); Name = $prop.Name; Command = [string]$prop.Value }
            }
        } catch { $ev.Errors += "Startup entries ($k): $($_.Exception.Message)" }
    }
    try {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $cmd = $f.FullName
                if ($f.Extension -eq '.lnk') {
                    $lnk = $shell.CreateShortcut($f.FullName)
                    $cmd = ('{0} {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim()
                }
                $auto += [pscustomobject]@{ Where = 'Startup folder'; Name = $f.Name; Command = $cmd }
            }
        }
    } catch { $ev.Errors += "Startup folders: $($_.Exception.Message)" }
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($a in @($t.Actions)) {
                if (-not $a.PSObject.Properties['Execute'] -or -not $a.Execute) { continue }
                $args2 = ''
                if ($a.PSObject.Properties['Arguments']) { $args2 = [string]$a.Arguments }
                $auto += [pscustomobject]@{ Where = 'Scheduled task'; Name = ($t.TaskPath + $t.TaskName); Command = ('{0} {1}' -f $a.Execute, $args2).Trim() }
            }
        }
    } catch { $ev.Errors += "Scheduled tasks: $($_.Exception.Message)" }
    $ev.Autoruns = $auto

    return [pscustomobject]$ev
}

# ---------------------------------------------------------------------------
# Analysis (pure: works on any evidence object, so it can be tested anywhere).
# ---------------------------------------------------------------------------

function Invoke-CfaAnalysis {
    param([Parameter(Mandatory = $true)] $Detector, [Parameter(Mandatory = $true)] $Evidence)
    $findings = New-Object System.Collections.ArrayList
    $addFinding = {
        param($Level, $Area, $Title, $Item, $Reasons)
        [void]$findings.Add([pscustomobject]@{
            Level = $Level; Area = $Area; Title = $Title
            Item = Get-CfaDefanged $Item; Reasons = @($Reasons)
        })
    }

    $sources = @(
        @{ Area = 'Run box history (Win+R)'; Items = @($Evidence.RunMRU); Title = 'A command in your Run box history looks like a ClickFix attack' },
        @{ Area = 'File Explorer address bar (FileFix)'; Items = @($Evidence.TypedPaths); Title = 'Something pasted into the File Explorer address bar looks like a FileFix attack' },
        @{ Area = 'PowerShell history'; Items = @($Evidence.PSHistory); Title = 'A command in your PowerShell history looks like an attack' }
    )
    foreach ($src in $sources) {
        foreach ($item in $src.Items) {
            if (-not $item) { continue }
            $r = Test-CfaCommand -Detector $Detector -Text ([string]$item)
            if ($r.Verdict -eq 'block') { & $addFinding 'danger' $src.Area $src.Title $item $r.Reasons }
            elseif ($r.Verdict -eq 'warn') { & $addFinding 'review' $src.Area 'A command downloads and runs something. Check that you ran it on purpose' $item $r.Reasons }
        }
    }

    foreach ($a in @($Evidence.Autoruns)) {
        if (-not $a) { continue }
        $r = Test-CfaCommand -Detector $Detector -Text ([string]$a.Command)
        $label = '{0}: {1}' -f $a.Where, $a.Name
        if ($r.Verdict -eq 'block') {
            & $addFinding 'danger' 'Starts automatically' "This runs every time Windows starts and looks like malware ($label)" $a.Command $r.Reasons
        } elseif ($r.Verdict -eq 'warn' -or ([string]$a.Command -match '\\(Temp|AppData\\Roaming)\\' -and [string]$a.Command -match '\b(wscript|cscript|mshta|powershell|cmd|rundll32|regsvr32)\b')) {
            $why = @($r.Reasons)
            if (-not $why.Count) { $why = @('Starts a script from a temporary or app-data folder') }
            & $addFinding 'review' 'Starts automatically' "Check that you recognize this ($label)" $a.Command $why
        }
    }

    foreach ($f in @($Evidence.TempFiles)) {
        if (-not $f -or $f.Signed) { continue }
        & $addFinding 'review' 'New programs in temporary folders' ("Unsigned program created {0}. If you did not download it, it may be what the attack installed" -f $f.Created) $f.Path @('Not signed by any known publisher')
    }

    foreach ($m in @($Evidence.MsiInstalls)) {
        if (-not $m) { continue }
        if ((Test-CfaRandomName $m.Name) -or -not $m.Manufacturer) {
            $why = @()
            if (Test-CfaRandomName $m.Name) { $why += 'The product name looks randomly generated' }
            if (-not $m.Manufacturer) { $why += 'No publisher name' }
            & $addFinding 'review' 'Programs installed recently' ("Installed {0}. Look it up if you do not recognize it" -f $m.Time) ('{0} ({1})' -f $m.Name, $m.Manufacturer) $why
        }
    }

    $overall = 'clean'
    if (@($findings | Where-Object { $_.Level -eq 'review' }).Count) { $overall = 'review' }
    if (@($findings | Where-Object { $_.Level -eq 'danger' }).Count) { $overall = 'danger' }

    return [pscustomobject]@{
        Version  = $CfaVersion
        Overall  = $overall
        Findings = @($findings)
        Checked  = [ordered]@{
            'Run box history (Win+R)'              = @($Evidence.RunMRU).Count
            'File Explorer address bar (FileFix)'  = @($Evidence.TypedPaths).Count
            'PowerShell history lines'             = @($Evidence.PSHistory).Count
            ('New programs in temp folders ({0} days)' -f $Evidence.Days) = @($Evidence.TempFiles).Count
            ('Programs installed ({0} days)' -f $Evidence.Days) = @($Evidence.MsiInstalls).Count
            'Things that start automatically'      = @($Evidence.Autoruns).Count
        }
        Errors   = @($Evidence.Errors)
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

function Write-CfaReport {
    param([Parameter(Mandatory = $true)] $Result)
    $line = '=' * 66
    Write-Host ''
    Write-Host $line -ForegroundColor DarkGray
    Write-Host (" ClickFix First Aid - PC check v{0}" -f $Result.Version) -ForegroundColor White
    Write-Host ' Read-only: nothing on this PC is changed, nothing is sent anywhere.' -ForegroundColor Gray
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ' What was checked' -ForegroundColor White
    foreach ($k in $Result.Checked.Keys) {
        Write-Host ('   [x] {0,-46} {1}' -f $k, $Result.Checked[$k]) -ForegroundColor Gray
    }
    Write-Host ''

    $danger = @($Result.Findings | Where-Object { $_.Level -eq 'danger' })
    $review = @($Result.Findings | Where-Object { $_.Level -eq 'review' })

    foreach ($f in ($danger + $review)) {
        $tag = '[REVIEW]'; $color = 'Yellow'
        if ($f.Level -eq 'danger') { $tag = '[DANGER]'; $color = 'Red' }
        Write-Host (' {0} {1}' -f $tag, $f.Area) -ForegroundColor $color
        Write-Host ('     {0}' -f $f.Title)
        Write-Host ('       {0}' -f $f.Item) -ForegroundColor DarkGray
        if ($f.Reasons.Count) { Write-Host ('     Why: {0}' -f ($f.Reasons -join '; ')) -ForegroundColor Gray }
        Write-Host ''
    }

    if ($Result.Overall -eq 'danger') {
        Write-Host ' RESULT: SIGNS OF A CLICKFIX ATTACK WERE FOUND.' -ForegroundColor Red
        Write-Host ''
        Write-Host ' Do this now, in this order:' -ForegroundColor White
        Write-Host '   1. Disconnect this PC from the internet (Wi-Fi off or cable out).'
        Write-Host '   2. From your PHONE: sign out of all devices in your email account,'
        Write-Host '      change the password and turn on two-step verification.'
        Write-Host '   3. Do the same for Instagram/Facebook, WhatsApp, Telegram, Discord,'
        Write-Host '      banking apps and anything else you were signed in to on this PC.'
        Write-Host '   4. Run a Microsoft Defender Offline scan, or reset Windows.'
        Write-Host ('   Full step-by-step guide: {0}' -f $CfaGuideUrl)
    } elseif ($Result.Overall -eq 'review') {
        Write-Host ' RESULT: NOTHING CLEARLY MALICIOUS, BUT PLEASE REVIEW THE ITEMS ABOVE.' -ForegroundColor Yellow
        Write-Host '   If you do not recognize one, search its name online before trusting it.'
        Write-Host '   If you think you ran a command from a website, follow the guide:'
        Write-Host ('   {0}' -f $CfaGuideUrl)
    } else {
        Write-Host ' RESULT: NO SIGNS OF A CLICKFIX ATTACK WERE FOUND.' -ForegroundColor Green
        Write-Host '   Remember: real "I am not a robot" checks never ask you to press Win+R,'
        Write-Host '   open Terminal, or paste anything.'
    }

    if ($Result.Errors.Count) {
        Write-Host ''
        Write-Host ' Some parts could not be read (this is usually fine):' -ForegroundColor DarkGray
        foreach ($e in $Result.Errors) { Write-Host ('   - {0}' -f $e) -ForegroundColor DarkGray }
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main (skipped when the file is dot-sourced by the tests)
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $rules = $CfaRulesJson | ConvertFrom-Json
    $detector = New-CfaDetector -Rules $rules
    if (-not $Json) { Write-Host ' Checking your PC. This can take a minute...' -ForegroundColor Gray }
    $evidence = Get-CfaEvidence -Days $Days
    $result = Invoke-CfaAnalysis -Detector $detector -Evidence $evidence

    if ($Json) {
        $result | ConvertTo-Json -Depth 6
    } else {
        Write-CfaReport -Result $result
        if (-not $NoPause -and [Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
            [void](Read-Host ' Press Enter to close')
        }
    }

    $code = 0
    if ($result.Overall -eq 'review') { $code = 1 }
    if ($result.Overall -eq 'danger') { $code = 2 }
    exit $code
}
