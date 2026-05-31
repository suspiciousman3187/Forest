$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop = [Environment]::GetFolderPath('Desktop')
$out = Join-Path $desktop "Forest-Doctor-$ts.txt"
$base = Split-Path -Parent $MyInvocation.MyCommand.Path

$lines = New-Object System.Collections.ArrayList
function Out-Line([string]$s) { [void]$lines.Add($s); Write-Host $s }

Out-Line "=== Forest Doctor Report ==="
Out-Line "Generated:     $(Get-Date)"
Out-Line "Forest folder: $base"
Out-Line "Windows user:  $env:USERNAME"
$os = Get-CimInstance Win32_OperatingSystem
Out-Line "Windows:       $($os.Caption) $($os.Version) (build $($os.BuildNumber))"
Out-Line "Architecture:  $env:PROCESSOR_ARCHITECTURE"
Out-Line ""

Out-Line "--- Forest binaries (in this folder) ---"
$expected = 'Forest.exe','Forest.dll','trees\Trees.dll','trees\waitinject.exe','webui\index.html'
foreach ($f in $expected) {
    $p = Join-Path $base $f
    if (Test-Path $p) {
        $fi = Get-Item $p
        $ver = ''
        if ($f -match '\.(exe|dll)$') { try { $ver = " v$([System.Diagnostics.FileVersionInfo]::GetVersionInfo($p).FileVersion)" } catch {} }
        Out-Line ("  [OK]      {0,-28} {1,10:N0} bytes{2}" -f $f, $fi.Length, $ver)
    } else {
        Out-Line ("  [MISSING] {0}" -f $f)
    }
}
Out-Line ""

Out-Line "--- .NET 9 Desktop Runtime (REQUIRED) ---"
$rts = $null
try { $rts = & dotnet --list-runtimes 2>$null } catch {}
if ($LASTEXITCODE -ne 0 -or -not $rts) {
    Out-Line "[FAIL] 'dotnet' not found OR no runtimes installed."
    Out-Line "       Install .NET 9 Desktop Runtime (x64):"
    Out-Line "       https://dotnet.microsoft.com/download/dotnet/9.0  ->  'Desktop Runtime' -> x64"
} else {
    $desktop9 = $rts | Where-Object { $_ -match '^Microsoft\.WindowsDesktop\.App 9\.' }
    if ($desktop9) {
        Out-Line "[OK] .NET 9 Desktop Runtime found:"
        $desktop9 | ForEach-Object { Out-Line "    $_" }
    } else {
        Out-Line "[FAIL] .NET 9 Desktop Runtime NOT found. Installed runtimes:"
        $rts | ForEach-Object { Out-Line "    $_" }
        Out-Line "       Install: https://dotnet.microsoft.com/download/dotnet/9.0  ->  'Desktop Runtime' x64"
    }
}
Out-Line ""

Out-Line "--- WebView2 Runtime (REQUIRED for Forest's UI) ---"
$keys = @(
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
  'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
  'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
)
$wv = $null
foreach ($k in $keys) { try { $v = (Get-ItemProperty $k -ErrorAction Stop).pv; if ($v) { $wv = $v; break } } catch {} }
if ($wv) { Out-Line "[OK] WebView2 Evergreen Runtime v$wv" }
else {
    Out-Line "[FAIL] WebView2 Evergreen Runtime NOT found."
    Out-Line "       Install: https://developer.microsoft.com/microsoft-edge/webview2/  ->  'Evergreen Standalone' (x64)"
}
Out-Line ""

Out-Line "--- Windows Defender (recent quarantines/threats, last 14 days) ---"
try {
    $cut = (Get-Date).AddDays(-14)
    $threats = Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $cut }
    if ($threats) {
        Out-Line "[WARN] Recent threats detected:"
        $threats | Select-Object -First 20 | ForEach-Object {
            Out-Line ("    {0}  {1}" -f $_.InitialDetectionTime, ($_.Resources -join '; '))
        }
        Out-Line "       If Forest.exe / Trees.dll / waitinject.exe appear here, antivirus quarantined them."
        Out-Line "       Restore from quarantine and add an exclusion for this Forest folder."
    } else {
        Out-Line "[OK] No recent Defender detections."
    }
} catch {
    Out-Line "[N/A] Could not query Defender ($($_.Exception.Message))"
}
Out-Line ""

Out-Line "--- Application event log (Forest / .NET / apphost crashes, last 30 min) ---"
try {
    $cut = (Get-Date).AddMinutes(-30)
    $evs = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$cut} -ErrorAction Stop |
           Where-Object {
               $_.ProviderName -in '.NET Runtime','Application Error','Windows Error Reporting' -or
               $_.Message -match 'Forest|apphost'
           }
    if ($evs) {
        $evs | Select-Object -First 10 | ForEach-Object {
            Out-Line ("[{0:HH:mm:ss}] {1}: {2}" -f $_.TimeCreated, $_.ProviderName, $_.LevelDisplayName)
            $first = ($_.Message -split "`r?`n" | Select-Object -First 4) -join '  |  '
            Out-Line "    $first"
        }
    } else {
        Out-Line "[OK] No recent Forest / .NET / apphost / WER errors in the Application log."
    }
} catch {
    Out-Line "[N/A] Event log access denied or empty ($($_.Exception.Message))"
}
Out-Line ""

Out-Line "--- Launch test (start Forest.exe for ~3 seconds) ---"
$exe = Join-Path $base 'Forest.exe'
if (Test-Path $exe) {
    try {
        $proc = Start-Process -FilePath $exe -PassThru -ErrorAction Stop
        Start-Sleep -Milliseconds 3000
        $proc.Refresh()
        if ($proc.HasExited) {
            Out-Line "[FAIL] Forest.exe exited within 3 seconds (exit code $($proc.ExitCode))."
            Out-Line "       Almost always: .NET 9 Desktop Runtime or WebView2 missing, or antivirus killed it."
            Out-Line "       See the sections above."
        } else {
            Out-Line "[OK] Forest.exe started and is still running (PID $($proc.Id))."
            Out-Line "     If the window didn't appear, alt-tab or check your taskbar."
            Out-Line "     You can close it when done."
        }
    } catch {
        Out-Line "[FAIL] Could not start Forest.exe: $($_.Exception.Message)"
    }
} else {
    Out-Line "[SKIP] Forest.exe not found in $base"
}
Out-Line ""

Out-Line "=== End of report ==="

$lines | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host ""
Write-Host "Report saved to:" -ForegroundColor Cyan
Write-Host "  $out"           -ForegroundColor Cyan
Write-Host ""
Write-Host "If Forest still won't start, send that file to the developer." -ForegroundColor Cyan
