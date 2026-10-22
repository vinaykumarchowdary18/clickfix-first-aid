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
    then restarts File Explorer so the change takes effect.

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

.NOTES
    ClickFix First Aid v0.1.0 - free and open source (MIT license).
#>
[CmdletBinding()]
param(
    [ValidateSet('On', 'Off', 'Status')]
    [string]$Mode,
    [switch]$NoRestart,
    [switch]$NoPause
)

Set-StrictMode -Version 2.0

$CfaKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$CfaValue = 'DisabledHotkeys'
$CfaLetters = @('R', 'X')

function Get-CfaUpdatedHotkeys {
    # Pure helper: returns the new DisabledHotkeys string.
    param([AllowEmptyString()][string]$Current, [string[]]$Letters, [switch]$Remove)
    $chars = New-Object System.Collections.ArrayList
    foreach ($c in ([string]$Current).ToCharArray()) {
        $u = ([string]$c).ToUpperInvariant()
        if (-not $chars.Contains($u)) { [void]$chars.Add($u) }
    }
    foreach ($l in $Letters) {
        $u = $l.ToUpperInvariant()
        if ($Remove) { while ($chars.Contains($u)) { $chars.Remove($u) } }
        elseif (-not $chars.Contains($u)) { [void]$chars.Add($u) }
    }
    return (-join $chars)
}

function Get-CfaHotkeyState {
    $current = ''
    try {
        $p = Get-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -ErrorAction Stop
        $current = [string]$p.$CfaValue
    } catch { $current = '' }
    $up = $current.ToUpperInvariant()
    return [pscustomobject]@{
        Value     = $current
        WinROff   = $up.Contains('R')
        WinXOff   = $up.Contains('X')
        Protected = ($up.Contains('R') -and $up.Contains('X'))
    }
}

function Set-CfaHotkeys {
    param([switch]$Remove)
    $state = Get-CfaHotkeyState
    $new = Get-CfaUpdatedHotkeys -Current $state.Value -Letters $CfaLetters -Remove:$Remove
    if (-not (Test-Path -LiteralPath $CfaKey)) { New-Item -Path $CfaKey -Force | Out-Null }
    if ($new) {
        Set-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -Value $new -Type String
    } else {
        Remove-ItemProperty -LiteralPath $CfaKey -Name $CfaValue -ErrorAction SilentlyContinue
    }
}

function Restart-CfaExplorer {
    Write-Host ' Restarting File Explorer (the taskbar will blink for a moment)...' -ForegroundColor Gray
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
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
    Write-Host ''
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ''
    Write-Host ' ClickFix First Aid - Win+R / Win+X protection (v0.1.0)' -ForegroundColor White

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
        if (-not $NoRestart) { Restart-CfaExplorer }
        Write-Host ' Done. If a page ever tells you to press Win+R, nothing will open.' -ForegroundColor Green
        Write-Host ' You can still open Run by typing "Run" in the Start menu.' -ForegroundColor Gray
    } elseif ($Mode -eq 'Off') {
        Set-CfaHotkeys -Remove
        if (-not $NoRestart) { Restart-CfaExplorer }
        Write-Host ' Done. Win+R and Win+X work normally again.' -ForegroundColor Yellow
    }
    Show-CfaStatus

    if (-not $NoPause -and [Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        [void](Read-Host ' Press Enter to close')
    }
}
