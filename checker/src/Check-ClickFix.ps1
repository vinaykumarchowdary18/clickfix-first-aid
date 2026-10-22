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
    ClickFix First Aid v__CFA_VERSION__ - free and open source (MIT license).
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

$CfaVersion = '__CFA_VERSION__'
$CfaGuideUrl = '__CFA_GUIDE_URL__'

# Detection rules, generated from rules/clickfix-rules.json. Do not edit here.
$CfaRulesJson = @'
__CFA_RULES_JSON__
'@

# ---------------------------------------------------------------------------
# Detection engine (a PowerShell copy of engine/detector.js, without the
# web-page part, which only makes sense inside a browser).
# ---------------------------------------------------------------------------

function New-CfaDetector {
    param([Parameter(Mandatory = $true)] $Rules)
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
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

function ConvertTo-CfaUnified {
    # Curly quotes and Unicode dashes become plain ' " and - (PowerShell accepts both).
    param([string]$Text)
    $s = $Text -replace '[\u2010-\u2015\u2212]', '-'
    $s = $s -replace '[\u2018\u2019\u201a\u201b]', "'"
    $s = $s -replace '[\u201c\u201d\u201e\u201f]', '"'
    return $s
}

function Get-CfaCodeLineCount {
    # Lines that do something: not empty and not comments (#, ::, rem).
    param([string]$Text)
    return @($Text -split "\r\n|\r|\n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*(#|::|rem\b)' }).Count
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
    # Same decisions as engine/detector.js, without the web-page part.
    # Verdicts: block (attack), hold (downloads and runs something), allow.
    param([Parameter(Mandatory = $true)] $Detector, [AllowEmptyString()][string]$Text)
    $raw = [string]$Text
    if ($raw.Length -gt $Detector.MaxChars) { $raw = $raw.Substring(0, $Detector.MaxChars) }
    $uni = ConvertTo-CfaUnified $raw
    $norm = ConvertTo-CfaNormalized $uni
    $lines = Get-CfaCodeLineCount $raw

    $exec = Get-CfaMatches $Detector.Executors $norm $null
    $remote = Get-CfaMatches $Detector.Remote $norm $null
    $encoded = Get-CfaMatches $Detector.Encoded $uni $null
    $seen = @{}
    $stealth = New-Object System.Collections.ArrayList
    foreach ($m in (Get-CfaMatches $Detector.Stealth $uni $seen)) { [void]$stealth.Add($m) }
    foreach ($m in (Get-CfaMatches $Detector.Stealth $norm $seen)) { [void]$stealth.Add($m) }
    $decoys = Get-CfaMatches $Detector.Decoys $uni $null

    $score = 0
    foreach ($m in $stealth) { $score += $m.Weight }
    $hasExec = $exec.Count -gt 0
    $danger = $hasExec -and ($remote.Count -gt 0 -or $encoded.Count -gt 0)
    $long = $lines -gt $Detector.MaxLines

    $why = New-Object System.Collections.ArrayList
    foreach ($m in @($exec | Select-Object -First 2)) { [void]$why.Add($m.Label) }
    if ($remote.Count) { [void]$why.Add($remote[0].Label) }
    if ($encoded.Count) { [void]$why.Add($encoded[0].Label) }

    $reasons = New-Object System.Collections.ArrayList
    $add = { param($items) foreach ($i in $items) { if (-not $reasons.Contains($i)) { [void]$reasons.Add($i) } } }
    $stealthLabels = @($stealth | ForEach-Object { $_.Label })
    $verdict = 'allow'; $rule = ''

    if ($hasExec) {
        if ($decoys.Count -gt 0) {
            & $add @($decoys | ForEach-Object { $_.Label }); & $add $why; & $add $stealthLabels
            $verdict = 'block'; $rule = 'decoy'
        } elseif ($danger -and $score -ge $Detector.BlockAt) {
            & $add $why; & $add $stealthLabels
            if ($long) { $verdict = 'hold'; $rule = 'stealthy-long-script' } else { $verdict = 'block'; $rule = 'stealthy-download-and-run' }
        } elseif ($score -ge $Detector.StealthOnlyAt) {
            & $add $why; & $add $stealthLabels
            if ($long) { $verdict = 'hold' } else { $verdict = 'block' }
            $rule = 'heavily-disguised'
        } elseif ($danger) {
            & $add $why; & $add $stealthLabels
            $verdict = 'hold'; $rule = 'download-and-run'
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

function ConvertFrom-CfaMsiEvent {
    # Event 1033 fields (Microsoft "Event Logging" docs): 1 ProductName,
    # 2 ProductVersion, 3 ProductLanguage, 4 status (0 = success), 5 Manufacturer.
    param([object[]]$Values, [datetime]$Time)
    $v = @($Values)
    $get = { param($i) if ($v.Count -gt $i -and $null -ne $v[$i]) { [string]$v[$i] } else { '' } }
    $status = & $get 3
    return [pscustomobject]@{
        Name         = & $get 0
        Version      = & $get 1
        Manufacturer = & $get 4
        Succeeded    = ($status -eq '0' -or $status -eq '')
        Time         = $Time.ToString('yyyy-MM-dd HH:mm')
    }
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
        $exts = @('.exe', '.msi', '.hta', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.bat', '.cmd', '.scr', '.com', '.pif', '.cpl', '.msc')
        $roots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC, $env:ProgramData) | Where-Object { $_ } | Select-Object -Unique
        $seenPaths = @{}
        $files = @()
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $isTemp = ($env:TEMP -and $root -eq $env:TEMP)
            foreach ($f in @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue)) {
                $ext = $f.Extension.ToLowerInvariant()
                # DLLs only in Temp: elsewhere in AppData, apps update them all the time.
                if ($exts -notcontains $ext -and -not ($isTemp -and $ext -eq '.dll')) { continue }
                if ($f.CreationTime -lt $since) { continue }
                if ($f.FullName -like '*\Microsoft\Windows\Recent\*') { continue }
                if ($seenPaths.ContainsKey($f.FullName)) { continue }
                $seenPaths[$f.FullName] = $true
                $signer = ''; $status = 'NotSigned'
                if ($f.Length -gt 200MB) {
                    $status = 'Unknown'
                } else {
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
                        $status = [string]$sig.Status
                        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false) }
                    } catch { $status = 'Unknown' }
                }
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
            $values = @($e.Properties | ForEach-Object { $_.Value })
            $m = ConvertFrom-CfaMsiEvent -Values $values -Time $e.TimeCreated
            if ($m.Succeeded) { $installs += $m }
        }
        $ev.MsiInstalls = $installs
    } catch {
        if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $ev.Errors += "Installer log: $($_.Exception.Message)" }
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
                if (@('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') -contains $prop.Name) { continue }
                $auto += [pscustomobject]@{ Where = ($k -replace '^HK(CU|LM):\\Software\\', 'HK$1 '); Name = $prop.Name; Command = [string]$prop.Value }
            }
        } catch { $ev.Errors += "Startup entries ($k): $($_.Exception.Message)" }
    }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { $shell = $null }
    foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        try {
            if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $cmd = $f.FullName
                if ($f.Extension -eq '.lnk' -and $shell) {
                    try {
                        $lnk = $shell.CreateShortcut($f.FullName)
                        $cmd = ('{0} {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim()
                    } catch { $cmd = $f.FullName }
                }
                $auto += [pscustomobject]@{ Where = 'Startup folder'; Name = $f.Name; Command = $cmd }
            }
        } catch { $ev.Errors += "Startup folder ($folder): $($_.Exception.Message)" }
    }
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
            elseif ($r.Verdict -eq 'hold') { & $addFinding 'review' $src.Area 'A command downloads and runs something. Check that you ran it on purpose' $item $r.Reasons }
        }
    }

    foreach ($a in @($Evidence.Autoruns)) {
        if (-not $a) { continue }
        $r = Test-CfaCommand -Detector $Detector -Text ([string]$a.Command)
        $label = '{0}: {1}' -f $a.Where, $a.Name
        if ($r.Verdict -eq 'block') {
            & $addFinding 'danger' 'Starts automatically' "This runs every time Windows starts and looks like malware ($label)" $a.Command $r.Reasons
        } elseif ($r.Verdict -eq 'hold' -or ([string]$a.Command -match '\\(Temp|AppData\\Roaming)\\' -and [string]$a.Command -match '\b(wscript|cscript|mshta|powershell|cmd|rundll32|regsvr32)\b')) {
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
