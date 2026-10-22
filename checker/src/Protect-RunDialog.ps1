<#
.SYNOPSIS
    ClickFix First Aid - turn the Win+R and Win+X keyboard shortcuts off (or back on).

.DESCRIPTION
    ClickFix pages tell you to press Win+R (or Win+X), paste, and press Enter.
    If those two shortcuts do nothing on your PC, the trick stops working.

    This only affects your own Windows user account. It is fully reversible.
    You can still open the Run box by typing "Run" in the Start menu, and the
    Win+X menu by right-clicking the Start button.

    Technical detail: it adds the letters R and X to the DisabledHotkeys value
    under HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced,
    and saves the previous value under HKCU\Software\ClickFixFirstAid so that
    turning it off restores exactly what was there. This setting is widely used
    but not formally documented by Microsoft. File Explorer must restart for it
    to take effect; the script asks before doing that.

    It also checks that Windows Terminal still warns you before pasting
    several lines at once (it only reports this, it does not change it).

    HOW TO RUN IT: right-click this file and choose "Run with PowerShell",
    then pick an option from the menu.

.PARAMETER Mode
    On     = turn the shortcuts off (protection on)
    Off    = turn the shortcuts back on (protection off)
    Status = only show the current state
    Leave it out to get a simple menu.

.PARAMETER NoRestart
    Do not restart File Explorer (the change then applies after you sign out and in).

.PARAMETER Yes
    Restart File Explorer without asking.

.NOTES
    ClickFix First Aid v__CFA_VERSION__ - free and open source (MIT license).
#>
[CmdletBinding()]
param(
    [ValidateSet('On', 'Off', 'Status')]
    [string]$Mode,
    [switch]$NoRestart,
    [switch]$Yes,
    [switch]$NoPause
)

Set-StrictMode -Version 2.0

$CfaKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$CfaValue = 'DisabledHotkeys'
$CfaLetters = @('R', 'X')
# Where we remember what DisabledHotkeys was before, so "off" restores it exactly.
$CfaBackupKey = 'HKCU:\Software\ClickFixFirstAid'

function Get-CfaUpdatedHotkeys {
    # Pure helper. Characters in DisabledHotkeys are treated as key codes, where
    # case matters ("R" is the R key, "r" is a different key), so existing
    # characters are never changed or re-cased. Only uppercase R and X are added.
    param([AllowEmptyString()][string]$Current, [string[]]$Letters, [switch]$Remove)
    $out = [string]$Current
    foreach ($l in $Letters) {
        $u = $l.ToUpperInvariant()
        if ($Remove) {
            $out = $out.Replace($u, '')
        } elseif (-not $out.Contains($u)) {
            $out += $u
        }
    }
    return $out
}

function Get-CfaHotkeyState {
    $current = ''
    $has = $false
    try {
        $p = Get-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -ErrorAction Stop
        $current = [string]$p.$CfaValue
        $has = $true
    } catch { $current = '' }
    return [pscustomobject]@{
        Value     = $current
        HasValue  = $has
        Protected = ($current.Contains('R') -and $current.Contains('X'))
    }
}

function Get-CfaBackup {
    try {
        $b = Get-ItemProperty -LiteralPath $CfaBackupKey -ErrorAction Stop
        if ($null -eq $b.PSObject.Properties['HadValue']) { return $null }
        $before = ''
        if ($b.PSObject.Properties['Before']) { $before = [string]$b.Before }
        return [pscustomobject]@{ HadValue = ([int]$b.HadValue -eq 1); Before = $before }
    } catch { return $null }
}

function Set-CfaHotkeys {
    param([switch]$Remove)
    $state = Get-CfaHotkeyState
    if (-not (Test-Path -LiteralPath $CfaKey)) { New-Item -Path $CfaKey -Force | Out-Null }

    if (-not $Remove) {
        # Remember the original value once, before our first change.
        if (-not (Get-CfaBackup)) {
            if (-not (Test-Path -LiteralPath $CfaBackupKey)) { New-Item -Path $CfaBackupKey -Force | Out-Null }
            Set-ItemProperty -LiteralPath $CfaBackupKey -Name 'Before' -Value $state.Value -Type String
            Set-ItemProperty -LiteralPath $CfaBackupKey -Name 'HadValue' -Value ([int]$state.HasValue) -Type DWord
        }
        $new = Get-CfaUpdatedHotkeys -Current $state.Value -Letters $CfaLetters
        Set-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -Value $new -Type String
        return
    }

    $backup = Get-CfaBackup
    if ($backup) {
        if ($backup.HadValue) {
            Set-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -Value $backup.Before -Type String
        } else {
            Remove-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $CfaBackupKey -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        $new = Get-CfaUpdatedHotkeys -Current $state.Value -Letters $CfaLetters -Remove
        if ($new) { Set-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -Value $new -Type String }
        else { Remove-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -ErrorAction SilentlyContinue }
    }
}

function Restart-CfaExplorer {
    Write-Host ' Restarting File Explorer (the taskbar will blink for a moment)...' -ForegroundColor Gray
    Stop-Process -Name explorer -ErrorAction SilentlyContinue
    # Windows normally restarts the shell by itself. Only start it if it does not.
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (Get-Process -Name explorer -ErrorAction SilentlyContinue) { return }
    }
    Start-Process explorer.exe
}

function Confirm-CfaRestart {
    if ($NoRestart) { return $false }
    if ($Yes) { return $true }
    Write-Host ''
    Write-Host ' The change works after File Explorer restarts. Restarting it closes open folder windows' -ForegroundColor White
    Write-Host ' (your apps and files stay open). Restart File Explorer now? [Y/N]' -ForegroundColor White
    $answer = Read-Host ' Your choice'
    return ($answer -match '^\s*(y|yes)\s*$')
}

function Get-CfaTerminalPasteState {
    # Windows Terminal warns before multi-line pastes unless someone turned it off.
    if (-not $env:LOCALAPPDATA) { return 'not-installed' }
    $paths = @(
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'),
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json')
    )
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            $text = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
            if ($text -match '"multiLinePasteWarning"\s*:\s*false') { return 'off' }
            return 'on'
        }
    }
    return 'not-installed'
}

function Show-CfaStatus {
    $s = Get-CfaHotkeyState
    Write-Host ''
    if ($s.Protected) {
        Write-Host ' Protection is ON: Win+R and Win+X do nothing on this account.' -ForegroundColor Green
    } else {
        Write-Host ' Protection is OFF: Win+R and Win+X work normally.' -ForegroundColor Yellow
    }
    switch (Get-CfaTerminalPasteState) {
        'off' { Write-Host ' Note: Windows Terminal has its multi-line paste warning turned OFF. Consider turning it back on in Terminal settings (Interaction).' -ForegroundColor Yellow }
        'on' { Write-Host ' Windows Terminal will warn you before pasting several lines at once. Good.' -ForegroundColor Gray }
        default { }
    }
    Write-Host ' This switch stops the "press Win+R" trick only. It does not stop someone typing' -ForegroundColor Gray
    Write-Host ' "powershell" in the Start menu or pasting into the File Explorer address bar.' -ForegroundColor Gray
    Write-Host ''
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ''
    Write-Host ' ClickFix First Aid - Win+R / Win+X protection (v__CFA_VERSION__)' -ForegroundColor White

    if (-not $Mode) {
        Show-CfaStatus
        Write-Host '   [1] Turn protection ON  (Win+R and Win+X stop working)'
        Write-Host '   [2] Turn protection OFF (Win+R and Win+X work again)'
        Write-Host '   [Q] Quit without changing anything'
        $choice = Read-Host ' Your choice'
        switch -Regex ($choice) {
            '^\s*1\s*$' { $Mode = 'On' }
            '^\s*2\s*$' { $Mode = 'Off' }
            default { $Mode = 'Status' }
        }
    }

    if ($Mode -eq 'On') {
        Set-CfaHotkeys
        if (Confirm-CfaRestart) { Restart-CfaExplorer } else { Write-Host ' OK. It will take effect the next time you sign in.' -ForegroundColor Gray }
        Write-Host ' Done. If a page ever tells you to press Win+R, nothing will open.' -ForegroundColor Green
        Write-Host ' You can still open Run by typing "Run" in the Start menu.' -ForegroundColor Gray
    } elseif ($Mode -eq 'Off') {
        Set-CfaHotkeys -Remove
        if (Confirm-CfaRestart) { Restart-CfaExplorer } else { Write-Host ' OK. It will take effect the next time you sign in.' -ForegroundColor Gray }
        Write-Host ' Done. Win+R and Win+X work normally again.' -ForegroundColor Yellow
    }
    Show-CfaStatus

    if (-not $NoPause -and [Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        [void](Read-Host ' Press Enter to close')
    }
}
