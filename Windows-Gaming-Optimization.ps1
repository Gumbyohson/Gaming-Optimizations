#Requires -RunAsAdministrator

<#
.SYNOPSIS
    All-in-one Windows gaming optimization, benchmarking, and performance comparison script.

.DESCRIPTION
    Comprehensive gaming optimization tool that applies 20+ registry tweaks, runs hardware benchmarks,
    and tracks performance improvements with before/after comparisons.
    
    OPTIMIZATIONS APPLIED:
    
    CPU/Performance:
    - Win32PrioritySeparation (optimized for gaming)
    - Power Throttling disabled
    - System Responsiveness set to 10%
    - Timer Resolution enhanced
    - Games task priority optimized (Priority 6, GPU Priority 8)
    - DisablePagingExecutive (locks kernel in RAM on 16GB+ systems)
    
    GPU/Graphics:
    - Hardware Accelerated GPU Scheduling (HAGS) enabled
    - Game Mode enabled
    - Game DVR/Game Bar disabled (unless AMD X3D CPU detected)
    - Fullscreen Optimizations configured
    - DWM MPO fix applied (Windows 11 24H2+ Alt+Tab fix)
    
    Network:
    - Network Throttling disabled
    - TCP settings optimized (DefaultTTL, GlobalMaxTcpWindowSize, Tcp1323Opts, TCPTimedWaitDelay)
    - Nagle's Algorithm disabled
    - Windows Update P2P delivery disabled
    
    Input/Latency:
    - Mouse buffer reduced (100→16)
    - Keyboard buffer reduced (100→16)
    
    System:
    - System Cache optimized (LargeSystemCache=0)
    - Background apps restricted
    - Visual effects optimized
    - Hardware-specific optimizations (AMD Ryzen / Intel recommendations)
    
    Optional/Experimental:
    - Native NVMe support (Windows 11 24H2+ Build 26100+) via -EnableNativeNVMe flag
    
    BENCHMARKS:
    - CPU: Multi-threaded stress (runspace-based), math ops, 2D/4K rendering
    - RAM: Bandwidth, dual-channel detection, module matching validation
    - Disk: Sequential read/write, 4K random IOPS (critical for game loading)
    - Network: Latency to gaming CDNs, DNS resolution, up/down speed
    - GPU: GravityMark integration (FPS, 1%/0.1% lows, clock speeds, thermals)
    
    SAFETY FEATURES:
    - Registry backups before all changes
    - HKCU-safe writes for elevated runs
    - Hardware/OS requirement validation per feature
    - WhatIf/Verbose support
    - Rollback capability
    - Multiple backup retention (never auto-deleted)
    
    FEATURE REQUIREMENTS:
    - HAGS: Windows 10 2004+ (Build 19041+), modern GPU (RTX 20+/RX 5000+/Arc)
    - DirectStorage: Windows 11+ (Build 22000+), NVMe SSD, DX12 GPU
    - Auto HDR: Windows 11+ (Build 22000+), HDR display
    - Native NVMe: Windows 11 24H2+ (Build 26100+), Microsoft NVMe driver, no RAID/VMD/StoreMI
    - Core Optimizations: Windows 10 2004+ (Build 19041+)
    
    WORKFLOW MODES:
    - Auto: Automatically creates baseline or runs comparison (intelligent default)
    - Apply: Applies all optimizations with optional before/after benchmarks
    - CreateBaseline: Establishes performance baseline (no optimizations applied)
    - CompareBaseline: Runs benchmarks and compares to latest baseline
    - Benchmark: Standalone benchmark run
    - Test: Validates which optimizations are currently applied
    - Rollback: Restores registry from backup file
    
    Sources:
    - PC Gaming Optimization Guide: https://www.patreon.com/posts/88124101
    - Native NVMe (Windows 11): https://windowsforum.com/threads/native-nvme-i-o-path-in-windows-server-2025-and-windows-11-performance-boost.394539/
    - Community research and testing

.PARAMETER Action
    Workflow mode. Valid values:
    - Apply: Apply all optimizations (with optional pre/post benchmarks via -BenchmarkBeforeAfter)
    - Rollback: Restore settings from a backup file
    - Test: Check which optimizations are currently active
    - Benchmark: Run standalone performance benchmarks
    - CreateBaseline: Create performance baseline (no optimizations)
    - CompareBaseline: Compare current performance to baseline
    - Auto: Intelligent mode (creates baseline if missing, otherwise runs comparison)
    Default: Auto

.PARAMETER SkipBackup
    Skip creating registry backup before applying changes (NOT RECOMMENDED).
    Backups are critical for rollback capability.

.PARAMETER EnableNativeNVMe
    Enable experimental Native NVMe I/O path support.
    Requirements: Windows 11 24H2+ (Build 26100+), NVMe drive, Microsoft in-box driver, no RAID/VMD/StoreMI.
    May break vendor tools (Samsung Magician, Crucial Storage Executive).

.PARAMETER DebugMode
    Enable detailed debug logging for troubleshooting.

.PARAMETER BenchmarkBeforeAfter
    Run benchmarks before applying optimizations, then prompt to run after restart.
    Only applicable with -Action Apply. Results saved as timestamped JSON files.

.PARAMETER GravityMarkPath
    Optional path to pre-downloaded GravityMark installer/executable/zip.
    If not provided, script will attempt to download from tellusim.com.

.PARAMETER WhatIf
    Preview mode - shows what changes would be made without applying them.

.PARAMETER Verbose
    Provides detailed information about each operation.

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1
    
    Run in Auto mode (intelligent default):
    - If no baseline exists: creates baseline
    - If baseline exists: runs comparison to measure improvements

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Apply
    
    Apply all optimizations with interactive prompts for diagnostics.

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Apply -BenchmarkBeforeAfter
    
    Apply optimizations with before/after benchmarking:
    1. Runs baseline benchmark
    2. Applies optimizations
    3. Prompts to restart
    4. After restart, run with -Action CompareBaseline

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Apply -EnableNativeNVMe
    
    Apply optimizations including experimental Native NVMe support.
    Only use if you have Windows 11 24H2+ and meet all requirements.

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Apply -WhatIf -Verbose
    
    Preview all changes with detailed output (safe mode - no changes applied).

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Test
    
    Verify which optimizations are currently active on your system.

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action CreateBaseline
    
    Create performance baseline before optimizations (for comparison later).

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action CompareBaseline
    
    Compare current performance to baseline (automatically finds latest benchmark file).

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Benchmark
    
    Run standalone benchmark without applying any optimizations.

.EXAMPLE
    .\Windows-Gaming-Optimization.ps1 -Action Rollback
    
    Restore registry settings from a backup file (interactive selection).

.NOTES
    Author: Based on P40L0's Gaming Optimization Guide + Community Research
    Requires: Administrator privileges
    Version: 2.4
    Updated: December 2025
    
    Changelog:
    - Converted CPU benchmark from jobs to runspaces (true 100% core utilization)
    - Added 4K random read/write IOPS testing (critical for game loading)
    - Enhanced RAM module matching validation (warns if non-identical)
    - Fixed false CPU performance warnings (corrected rating thresholds)
    - Removed static benchmark file (now uses timestamped files only)
    - Fixed GravityMark download prompts (added -UseBasicParsing)
    - Added input latency optimizations (mouse/keyboard buffer reduction)
    - Added memory management optimization (DisablePagingExecutive)
    - Added Windows Update P2P disabling
    - Improved benchmark progress display with real-time metrics
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Apply', 'Rollback', 'Test', 'Benchmark', 'CreateBaseline', 'CompareBaseline', 'Auto')]
    [string]$Action = 'Auto',
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableNativeNVMe,
    
    [Parameter(Mandatory=$false)]
    [switch]$DebugMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkBeforeAfter,

    [Parameter(Mandatory=$false)]
    [string]$GravityMarkPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkCPU,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkDisk,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkNetwork,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkGPU,
    
    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkRAM
)

# Helper: get primary monitor resolution (used for GravityMark fullscreen runs)
function Get-PrimaryMonitorResolution {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        if ($b -and $b.Width -gt 0 -and $b.Height -gt 0) {
            return @{ Width = [int]$b.Width; Height = [int]$b.Height }
        }
    }
    catch {
        # Ignore; fallback handled by caller
    }
    return @{ Width = 1920; Height = 1080 }
}

# Helper: get current primary display refresh rate (best-effort)
function Get-PrimaryMonitorRefreshRate {
    try {
        $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Remote|Virtual' } | Select-Object -First 1
        if ($gpu -and $gpu.CurrentRefreshRate -and [int]$gpu.CurrentRefreshRate -gt 0) {
            return [int]$gpu.CurrentRefreshRate
        }
    }
    catch {
        # Ignore; fallback handled below
    }
    return 60
}

# Helper: write a single-line progress update safely (pads to clear previous longer text)
function Write-ProgressLine {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Color = 'Cyan'
    )
    try {
        if (-not $script:__ProgressLineMaxLen) { $script:__ProgressLineMaxLen = 0 }
        if ($Text.Length -gt $script:__ProgressLineMaxLen) { $script:__ProgressLineMaxLen = $Text.Length }
        $out = "`r" + $Text.PadRight([int]$script:__ProgressLineMaxLen)
        Write-Host $out -ForegroundColor $Color -NoNewline
    }
    catch {
        # Fallback: best-effort
        Write-Host ("`r" + $Text + (' ' * 10)) -ForegroundColor $Color -NoNewline
    }
}

# Helper: locate GravityMark if already installed
function Find-InstalledGravityMarkExe {
    try {
        $candidates = @(
            (Join-Path $env:ProgramFiles 'GravityMark\bin\GravityMark.exe'),
            (Join-Path $env:ProgramFiles 'GravityMark\GravityMark.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\bin\GravityMark.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\GravityMark.exe'),
            (Join-Path $env:ProgramFiles 'Tellusim\GravityMark\GravityMark.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Tellusim\GravityMark\GravityMark.exe')
        )

        foreach ($c in $candidates | Select-Object -Unique) {
            if ($c -and (Test-Path $c)) { return (Get-Item $c) }
        }

        $uninstallRoots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        foreach ($root in $uninstallRoots) {
            if (-not (Test-Path $root)) { continue }
            $apps = Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                try { Get-ItemProperty -Path $_.PSPath -ErrorAction Stop } catch { $null }
            } | Where-Object { $_ -and $_.DisplayName -match 'GravityMark' }

            $app = $apps | Sort-Object DisplayVersion -Descending | Select-Object -First 1
            if (-not $app) { continue }

            $more = @()
            if ($app.DisplayIcon) { $more += ($app.DisplayIcon -split ',')[0].Trim('"') }
            if ($app.InstallLocation) {
                $more += (Join-Path $app.InstallLocation 'GravityMark.exe')
                $more += (Join-Path $app.InstallLocation 'bin\GravityMark.exe')
            }
            foreach ($m in $more | Select-Object -Unique) {
                if ($m -and (Test-Path $m)) { return (Get-Item $m) }
            }
        }
    }
    catch { }
    return $null
}

# GravityMark helper: attempt to discover a current Windows download link from the homepage
function Get-GravityMarkWindowsDownloadUrl {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $resp = Invoke-WebRequest -Uri 'https://gravitymark.tellusim.com/' -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5 -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } -ErrorAction Stop
        $html = $resp.Content
        if (-not $html) { return $null }

        # Current site (Dec 2025): Windows downloads are published as MSI links under tellusim.com/download/
        # Prefer non-arm64 MSI if present.
        $msiPattern = '(?i)https://tellusim\.com/download/GravityMark_(?<ver>[0-9.]+)(?<arch>_arm64)?\.msi'
        $msiMatches = [System.Text.RegularExpressions.Regex]::Matches($html, $msiPattern)
        if ($msiMatches -and $msiMatches.Count -gt 0) {
            $items = foreach ($mm in $msiMatches) {
                [pscustomobject]@{
                    Url  = $mm.Value
                    Ver  = $mm.Groups['ver'].Value
                    Arm  = [bool]$mm.Groups['arch'].Success
                }
            }

            $best = $items |
                Sort-Object @{ Expression = { $_.Arm }; Ascending = $true }, @{ Expression = { [version]$_.Ver }; Descending = $true } |
                Select-Object -First 1

            if ($best -and $best.Url) { return $best.Url }
        }

        # Fallback: look for any direct GravityMark package link (msi/zip/exe)
        $m2 = [System.Text.RegularExpressions.Regex]::Match($html, '(?is)href\s*=\s*"(?<u>[^"]*(GravityMark)[^"]*\.(msi|zip|exe))"')
        if ($m2.Success) {
            $u = $m2.Groups['u'].Value
            if ($u -and -not ($u -match '^https?://')) {
                $u = ([Uri]::new([Uri]'https://gravitymark.tellusim.com/', $u)).AbsoluteUri
            }
            return $u
        }

        return $null
    }
    catch {
        return $null
    }
}

# Configuration
# NOTE: Output files are saved alongside this script.
$ResultsPath = $PSScriptRoot
$script:RunTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupPath = "$PSScriptRoot\Gaming-Optimization-Backup-$script:RunTimestamp.reg"
$LogPath = "$PSScriptRoot\Gaming-Optimization-Log-$script:RunTimestamp.txt"
if (-not $script:CurrentTelemetryTag) { $script:CurrentTelemetryTag = $null }

# Resolved baseline path cache (used when baseline was archived or renamed)
$script:ResolvedBaselinePath = $null

# Helper: resolve the latest benchmark file (baseline)
function Resolve-BaselineResultsPath {
    try {
        # Prefer the latest explicitly-tagged baseline (-preopt) when available
        $candidates = @()

        # Helper to collect files from a folder
        function Collect-BenchmarksFrom($folder) {
            if (Test-Path $folder) {
                return Get-ChildItem -Path $folder -Filter 'Gaming-Optimization-Benchmark-*.json' -File -ErrorAction SilentlyContinue
            }
            return @()
        }

        $candidates += Collect-BenchmarksFrom -folder $ResultsPath
        $archiveDir = Join-Path $ResultsPath 'Archive'
        $candidates += Collect-BenchmarksFrom -folder $archiveDir

        if ($candidates -and $candidates.Count -gt 0) {
            # Prefer files explicitly marked as pre-optimization
            $preopts = $candidates | Where-Object { $_.Name -match '\-preopt\.json$' } | Sort-Object LastWriteTime -Descending
            if ($preopts -and $preopts.Count -gt 0) {
                foreach ($cand in $preopts) {
                    if ($cand.Length -gt 50) {
                        $results = Import-BenchmarkResults -FilePath $cand.FullName
                        if ($results -and $results.Results) { return $cand.FullName }
                    }
                }
            }

            # Fallback: choose the latest non-after timestamped result
            $fallback = $candidates | Where-Object { $_.Name -notlike '*-after.json' } | Sort-Object LastWriteTime -Descending
            foreach ($cand in $fallback) {
                if ($cand.Length -gt 50) {
                    $results = Import-BenchmarkResults -FilePath $cand.FullName
                    if ($results -and $results.Results) { return $cand.FullName }
                }
            }
        }
    } catch {
        Write-Debug "Resolve-BaselineResultsPath error: $_"
    }
    return $null
}

# Hardware detection cache
$script:CPUManufacturer = $null
$script:GPUManufacturer = $null
$script:DebugModeEnabled = $DebugMode.IsPresent

# Initialize log file
try {
    "Gaming Optimization Script Log - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $LogPath -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Host "WARNING: Could not create log file at $LogPath : $_" -ForegroundColor Yellow
}

# Enable debug preference if DebugMode switch is used
if ($DebugMode) {
    $DebugPreference = 'Continue'
    Write-Debug "Debug mode enabled"
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output:
    # - INFO/SUCCESS: Write-Host with color
    # - WARNING/ERROR: write to the proper streams (avoid duplicate output)
    switch ($Level) {
        'ERROR' {
            Write-Error $Message -ErrorAction Continue
        }
        'WARNING' {
            Write-Warning $Message
        }
        'SUCCESS' {
            Write-Host $Message -ForegroundColor Green
        }
        default {
            Write-Host $Message -ForegroundColor White
        }
    }
    
    # Write to log file with retry-on-share-violation to handle sync clients (Google Drive, OneDrive)
    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -Path $LogPath -Value $logMessage -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -ge $maxAttempts) {
                Write-Host "WARNING: Could not write to log file after $maxAttempts attempts: $_" -ForegroundColor Yellow
            }
            else {
                $sleepMs = [int](100 * [math]::Pow(2, $attempt - 1))
                Start-Sleep -Milliseconds $sleepMs
            }
        }
    }
    
    # Also write to verbose stream if -Verbose is enabled
    if ($Level -eq "INFO" -or $Level -eq "SUCCESS") {
        Write-Verbose $Message
    }
    
    # Debug output if -DebugMode is enabled
    if ($script:DebugModeEnabled) {
        Write-Debug $Message
    }
}

# List all existing backups (safety: never delete them)
function Get-ExistingBackups {
    try {
        $backupPattern = "$PSScriptRoot\Gaming-Optimization-Backup-*.reg"
        $existingBackups = @(Get-ChildItem -Path $backupPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        
        if ($existingBackups.Count -gt 0) {
            Write-Log "Found $($existingBackups.Count) existing backup file(s):" "INFO"
            foreach ($backup in $existingBackups) {
                $sizeKB = [math]::Round($backup.Length / 1KB, 2)
                Write-Log "  - $($backup.Name) ($sizeKB KB) - Modified: $($backup.LastWriteTime)" "INFO"
            }
        } else {
            Write-Log "No existing backup files found" "INFO"
        }
        
        return $existingBackups
    }
    catch {
        Write-Log "ERROR: Failed to list backup files: $_" "ERROR"
        return @()
    }
}

# Script-level variable to track newly created registry keys
$script:NewlyCreatedKeys = @()

# Add a key to the tracker for rollback purposes
function Add-NewKeyToTracker {
    param([string]$Key)
    $script:NewlyCreatedKeys += $Key
}

# Validate that a registry backup file is valid
function Test-RegistryBackup {
    param([string]$BackupPath)
    
    try {
        if (-not (Test-Path $BackupPath)) {
            Write-Log "Backup file does not exist: $BackupPath" "WARNING"
            return $false
        }
        
        $fileInfo = Get-Item $BackupPath
        if ($fileInfo.Length -lt 100) {
            Write-Log "Backup file is too small to be valid: $($fileInfo.Length) bytes" "WARNING"
            return $false
        }
        
        # Check for Windows Registry Editor header
        $content = Get-Content $BackupPath -First 1 -ErrorAction SilentlyContinue
        if ($content -notmatch "Windows Registry Editor") {
            Write-Log "Backup file does not have valid registry header" "WARNING"
            return $false
        }
        
        Write-Log "Backup file validated successfully ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to validate backup file: $_" "ERROR"
        return $false
    }
}

# Protect registry backups by listing them (informational - we never delete backups)
function Protect-RegistryBackups {
    try {
        $backupPattern = "$PSScriptRoot\Gaming-Optimization-Backup-*.reg"
        $existingBackups = @(Get-ChildItem -Path $backupPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        
        if ($existingBackups.Count -gt 0) {
            Write-Log "Protected backup files (these will never be deleted):" "INFO"
            foreach ($backup in $existingBackups) {
                $sizeKB = [math]::Round($backup.Length / 1KB, 2)
                Write-Log "  - $($backup.Name) ($sizeKB KB)" "INFO"
            }
        }
        
        return $existingBackups
    }
    catch {
        Write-Log "Warning: Could not enumerate backup files: $_" "WARNING"
        return @()
    }
}

# Get the list of keys that were newly created during optimization (for rollback)
function Get-TrackedNewKeys {
    param([string]$BackupFile)
    
    # Return the tracked keys from this session
    # In a more robust implementation, you could store these in a companion file
    return $script:NewlyCreatedKeys
}

# Remove keys that were newly created during optimization (rollback support)
function Remove-NewlyCreatedKeys {
    param([array]$Keys)
    
    foreach ($key in $Keys) {
        try {
            $checkPath = $key -replace '^([A-Z]+)\\', '$1:\'
            if (Test-Path $checkPath) {
                # Use reg delete to remove the key
                $null = & reg delete $key /f 2>&1
                Write-Log "Removed newly-created key: $key" "SUCCESS"
            }
        }
        catch {
            Write-Log "Failed to remove key $key : $_" "WARNING"
        }
    }
}

# Backup registry keys
function Backup-RegistryKeys {
    Write-Log "Creating registry backup at: $BackupPath"
    
    $keysToBackup = @(
        "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl",
        "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
        "HKLM\SOFTWARE\Microsoft\Windows\Dwm",
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
        "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "HKCU\System\GameConfigStore",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
        "HKCU\Software\Microsoft\GameBar",
        "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
        "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides",
        "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    )
    
    $firstKey = $true
    $backupCount = 0
    $skipCount = 0
    $newKeyCount = 0
    
    foreach ($key in $keysToBackup) {
        try {
            # Convert registry path to check-able format (HKLM\... to HKLM:\...)
            $checkPath = $key -replace '^([A-Z]+)\\', '$1:\'
            
            # Track if this key exists before backup
            $keyExistedBefore = Test-Path $checkPath 2>$null
            
            # Try to check if key exists
            if (-not $keyExistedBefore) {
                Write-Log "Skipped (key not found): $key" "INFO"
                # IMPORTANT: This key will be created during optimization, so track it for rollback
                Add-NewKeyToTracker $key
                $newKeyCount++
                $skipCount++
                continue
            }
            
            # Attempt to export the key
            $output = & reg export $key "$BackupPath-temp.reg" /y 2>&1
            
            if (Test-Path "$BackupPath-temp.reg" -ErrorAction SilentlyContinue) {
                if ($firstKey) {
                    # First key - copy entire file including header
                    Get-Content "$BackupPath-temp.reg" | Set-Content $BackupPath
                    $firstKey = $false
                } else {
                    # Subsequent keys - skip the header line
                    Get-Content "$BackupPath-temp.reg" | Select-Object -Skip 1 | Add-Content $BackupPath
                }
                
                # CRITICAL SAFETY: Only remove the temporary file, NEVER delete any permanent backups
                # Temporary files are marked with "-temp.reg" suffix
                try {
                    if (Test-Path "$BackupPath-temp.reg") {
                        Remove-Item "$BackupPath-temp.reg" -Force -ErrorAction Stop
                    }
                } catch {
                    Write-Log "Warning: Could not remove temporary backup file (non-critical): $_" "WARNING"
                    # Don't fail - this is just cleanup
                }
                
                Write-Log "Backed up: $key" "SUCCESS"
                $backupCount++
            }
            else {
                Write-Log "Failed to export $key (temp file not created)" "WARNING"
                Write-Debug "Export output: $output"
            }
        }
        catch {
            Write-Log "Failed to backup $key : $_" "WARNING"
        }
    }
    
    Write-Log "Backup completed: $backupCount keys backed up, $skipCount keys skipped/missing, $newKeyCount keys will be created (tracked)" "SUCCESS"
    Write-Log "Backup saved to: $BackupPath" "SUCCESS"
    
    # CRITICAL: Validate backup before returning
    if (-not (Test-RegistryBackup $BackupPath)) {
        Write-Log "" "ERROR"
        Write-Log "[CRITICAL] Backup validation FAILED!" "ERROR"
        Write-Log "Backup file is corrupted or invalid. Optimizations will NOT proceed." "ERROR"
        Write-Log "Please check the backup file and try again." "ERROR"
        Write-Log "" "ERROR"
        return $false
    }
    
    # SAFETY: Protect all existing backups - none will ever be deleted
    Write-Log "" "INFO"
    Protect-RegistryBackups | Out-Null
    
    return $true
}

# Test if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Get the actual logged-in user (not the elevated admin user)
function Get-LoggedInUser {
    try {
        # Get the process running on the desktop (explorer.exe) to find the actual user
        $explorerProcess = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($explorerProcess) {
            $owner = $explorerProcess.StartInfo.UserName
            if (-not $owner) {
                # Alternative method: Get owner from CIM using Invoke-CimMethod
                try {
                    $cimProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($explorerProcess.Id)" -ErrorAction SilentlyContinue
                    if ($cimProcess) {
                        $owner = Invoke-CimMethod -InputObject $cimProcess -MethodName GetOwner -ErrorAction SilentlyContinue
                        if ($owner -and $owner.User) {
                            return $owner.User
                        }
                    }
                } catch {
                    Write-Debug "Could not get owner via CIM method: $_"
                }
            }
            if ($owner) {
                return $owner
            }
        }
        
        # Fallback: Get from environment variable
        $userName = $env:USERNAME
        if ($userName) {
            # If running elevated, USERNAME might still be admin. Check session ID
            $sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
            $sessionInfo = Get-CimInstance -ClassName Win32_Process -Filter "SessionId=$sessionId" -ErrorAction SilentlyContinue | 
                           Where-Object { $_.Name -eq 'explorer.exe' } | 
                           Select-Object -First 1
            
            if ($sessionInfo) {
                try {
                    $ownerInfo = Invoke-CimMethod -InputObject $sessionInfo -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($ownerInfo -and $ownerInfo.User) {
                        return $ownerInfo.User
                    }
                } catch {
                    Write-Debug "Could not get owner via CIM method: $_"
                }
            }
        }
        
        Write-Log "Could not detect logged-in user, using current context" "WARNING"
        return $null
    }
    catch {
        Write-Log "Error detecting logged-in user: $_" "WARNING"
        return $null
    }
}

# Set registry value for the actual logged-in user (works when script runs elevated)
function Set-UserRegistryValue {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        $Value,
        [string]$Type = "DWord"
    )
    
    try {
        # SAFETY CHECK: Verify parent key exists before attempting modification
        if (-not (Test-RegistryKeyExists $Path)) {
            Write-Log "WARNING: Registry key does not exist, will create it safely: $Path" "WARNING"
        }
        
        # WhatIf support
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set registry value to $Value")) {
            Write-Debug "Setting registry: $Path\$Name = $Value (Type: $Type)"
            
            # If path doesn't start with HKCU:, just use normal Set-ItemProperty
            if (-not $Path.StartsWith("HKCU:")) {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
                return $true
            }
            
            # Try normal HKCU access first (works if script runs in user context)
            if (Test-Path $Path) {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
                return $true
            }
            
            # If normal access fails and we're elevated, try loading user hive
            $userName = Get-LoggedInUser
            if (-not $userName) {
                # Fallback to normal attempt
                if (-not (Test-Path $Path)) {
                    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
                }
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
                return $true
            }
            
            # Extract the subpath from HKCU (e.g., "HKCU:\Software\Test" -> "Software\Test")
            $subPath = $Path -replace '^HKCU:\\?', ''

            # Resolve the user's SID and write to HKEY_USERS\<SID> so it applies to the interactive user
            $userSID = Get-UserSID -UserName $userName
            if (-not $userSID) {
                Write-Log "Failed to resolve SID for user '$userName'; cannot set $Path\\$Name reliably" "WARNING"
                return $false
            }

            $fullPath = "HKEY_USERS\\$userSID\\$subPath"

            # Ensure the key exists and set the value via reg.exe
            & reg.exe add "$fullPath" /f 2>&1 | Out-Null

            switch ($Type.ToLower()) {
                "dword" {
                    & reg.exe add "$fullPath" /v "$Name" /t REG_DWORD /d "$Value" /f 2>&1 | Out-Null
                }
                "string" {
                    & reg.exe add "$fullPath" /v "$Name" /t REG_SZ /d "$Value" /f 2>&1 | Out-Null
                }
                "binary" {
                    & reg.exe add "$fullPath" /v "$Name" /t REG_BINARY /d "$Value" /f 2>&1 | Out-Null
                }
                default {
                    & reg.exe add "$fullPath" /v "$Name" /t REG_DWORD /d "$Value" /f 2>&1 | Out-Null
                }
            }
            
            return $true
        }
        else {
            Write-Verbose "WhatIf: Would set $Path\$Name = $Value"
            return $true
        }
    }
    catch {
        Write-Log "Failed to set registry value at $Path\$Name : $_" "WARNING"
        return $false
    }
}

# Get registry value with fallback for logged-in user
function Get-UserRegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    try {
        # Try normal HKCU access first
        $value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -ne $value) {
            return $value
        }
        
        # If that fails, try accessing the actual user's hive
        $userName = Get-LoggedInUser
        if (-not $userName) {
            return $null
        }
        
        $subPath = $Path -replace '^HKCU:\\?', ''
        $userSID = Get-UserSID -UserName $userName
        
        if ($userSID) {
            $regPath = "REGISTRY::HKEY_USERS\$userSID\$subPath"
            $value = (Get-ItemProperty -Path $regPath -Name $Name -ErrorAction SilentlyContinue).$Name
            return $value
        }
        
        return $null
    }
    catch {
        return $null
    }
}

# Helper to check current optimization settings
function Get-OptimizationStatus {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('PowerThrottling', 'Win32Priority', 'SystemResponsiveness', 'NetworkThrottling', 'GameMode', 'GameDVR', 'TimerResolution', 'FullscreenOptimizations')]
        [string]$Setting
    )
    
    try {
        switch ($Setting) {
            'PowerThrottling' {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
                $value = (Get-ItemProperty -Path $path -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue).PowerThrottlingOff
                return ($value -eq 1)
            }
            'Win32Priority' {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
                $value = (Get-ItemProperty -Path $path -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue).Win32PrioritySeparation
                return ($value -eq 40)  # 0x28 = 40 (short, fixed boost)
            }
            'SystemResponsiveness' {
                $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
                $value = (Get-ItemProperty -Path $path -Name "SystemResponsiveness" -ErrorAction SilentlyContinue).SystemResponsiveness
                return ($value -eq 10)
            }
            'NetworkThrottling' {
                $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
                $value = (Get-ItemProperty -Path $path -Name "NetworkThrottlingIndex" -ErrorAction SilentlyContinue).NetworkThrottlingIndex
                return ($null -ne $value -and [uint32]$value -eq [uint32]0xFFFFFFFF)
            }
            'GameMode' {
                return ((Get-UserRegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled") -eq 1)
            }
            'GameDVR' {
                return ((Get-UserRegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled") -eq 0)
            }
            'TimerResolution' {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
                $value = (Get-ItemProperty -Path $path -Name "GlobalTimerResolutionRequests" -ErrorAction SilentlyContinue).GlobalTimerResolutionRequests
                return ($value -eq 1)
            }
            'FullscreenOptimizations' {
                $value = Get-UserRegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode"
                return ($value -eq 2)
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

# Helper to get user SID
function Get-UserSID {
    param([string]$UserName)
    
    try {
        if ($UserName -like "*\*") {
            $parts = $UserName -split '\\'
            $domain = $parts[0]
            $user = $parts[1]
            $userObj = New-Object System.Security.Principal.NTAccount($domain, $user)
        }
        else {
            $userObj = New-Object System.Security.Principal.NTAccount($UserName)
        }
        
        $sid = $userObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    }
    catch {
        return $null
    }
}

# Verify registry key exists before modifying
function Test-RegistryKeyExists {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        # Convert path format if needed (HKCU\... to HKCU:\...)
        if (-not $Path.Contains(':\')) {
            $Path = $Path -replace '^([A-Z]+)\\', '$1:\'
        }
        
        return (Test-Path $Path 2>$null)
    }
    catch {
        Write-Log "Failed to test registry key: $Path - Error: $_" "WARNING"
        return $false
    }
}

# Get Windows version details
function Get-WindowsVersionInfo {
    $osVersion = [System.Environment]::OSVersion.Version
    $buildNumber = $osVersion.Build
    $ubr = 0  # Update Build Revision
    
    # Try to get UBR (patch level) from registry
    try {
        $ubr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR -ErrorAction SilentlyContinue).UBR
    } catch {
        $ubr = 0
    }
    
    # Determine Windows version (check higher builds first)
    $versionName = "Unknown"
    if ($osVersion.Major -eq 10) {
        if ($buildNumber -ge 26200) {
            $versionName = "Windows 11 25H2"
        }
        elseif ($buildNumber -ge 26100) {
            $versionName = "Windows 11 24H2"
        }
        elseif ($buildNumber -ge 22631) {
            $versionName = "Windows 11 23H2"
        }
        elseif ($buildNumber -ge 22621) {
            $versionName = "Windows 11 22H2"
        }
        elseif ($buildNumber -ge 22000) {
            $versionName = "Windows 11 21H2"
        }
        elseif ($buildNumber -ge 19045) {
            $versionName = "Windows 10 22H2"
        }
        elseif ($buildNumber -ge 19044) {
            $versionName = "Windows 10 21H2"
        }
        elseif ($buildNumber -ge 19043) {
            $versionName = "Windows 10 21H1"
        }
        elseif ($buildNumber -ge 19042) {
            $versionName = "Windows 10 20H2"
        }
        elseif ($buildNumber -ge 19041) {
            $versionName = "Windows 10 2004"
        }
        else {
            $versionName = "Windows 10 (Legacy)"
        }
    }
    
    return @{
        Major = $osVersion.Major
        Minor = $osVersion.Minor
        Build = $buildNumber
        UBR = $ubr
        FullBuild = "$buildNumber.$ubr"
        VersionName = $versionName
        Is24H2OrNewer = ($buildNumber -ge 26100)
        Is25H2OrNewer = ($buildNumber -ge 26200)
        Is23H2OrNewer = ($buildNumber -ge 22631)
        Is22H2OrNewer = ($buildNumber -ge 22621)
        IsWindows11 = ($buildNumber -ge 22000)
        IsWindows10_2004OrNewer = ($buildNumber -ge 19041)
        SupportsHAGS = ($buildNumber -ge 19041)  # Windows 10 2004+
        SupportsDirectStorage = ($buildNumber -ge 22000)  # Windows 11+
        SupportsAutoHDR = ($buildNumber -ge 22000)  # Windows 11+
        SupportsNativeNVMe = ($buildNumber -ge 26100)  # Windows 11 24H2+
    }
}

# Detect CPU manufacturer
function Get-CPUManufacturer {
    if ($script:CPUManufacturer) { return $script:CPUManufacturer }
    
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $name = $cpu.Name.ToLower()

        if ($name -match 'intel') {
            $script:CPUManufacturer = 'Intel'
        }
        elseif ($name -match 'amd') {
            $script:CPUManufacturer = 'AMD'
        }
        else {
            $script:CPUManufacturer = 'Unknown'
        }
        
        Write-Log "Detected CPU: $($cpu.Name)" "INFO"
        Write-Log "CPU Manufacturer: $script:CPUManufacturer" "INFO"
        
        return $script:CPUManufacturer
    }
    catch {
        Write-Log "Failed to detect CPU manufacturer: $_" "WARNING"
        return 'Unknown'
    }
}

# Detect GPU manufacturer
function Get-GPUManufacturers {
    try {
        $gpus = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Remote|Virtual' }
        $vendors = @()
        foreach ($gpu in $gpus) {
            $name = $gpu.Name.ToLower()
            if ($name -match 'nvidia|geforce|quadro|rtx|gtx') {
                $vendors += 'NVIDIA'
            } elseif ($name -match 'amd|radeon|rx ') {
                $vendors += 'AMD'
            } elseif ($name -match 'intel.*arc|intel.*xe|intel') {
                $vendors += 'Intel'
            } else {
                $vendors += 'Unknown'
            }
            Write-Log "Detected GPU: $($gpu.Name)" "INFO"
        }
        return ($vendors | Select-Object -Unique)
    } catch {
        Write-Log "Failed to detect GPU manufacturers: $_" "WARNING"
        return @('Unknown')
    }
}

##############################################################################
# Hybrid GPU helpers
#
# These helpers detect hybrid (iGPU + dGPU) laptop configurations and provide
# interactive guidance. Use `Test-HybridGPU` to enumerate adapters and
# `Show-HybridGPUGuidance` to present recommendations and quick actions.
##############################################################################
function Test-HybridGPU {
    try {
        $adapters = Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterCompatibility, PNPDeviceID, VideoProcessor, DriverVersion

        $iGPUs = @()
        $dGPUs = @()

        foreach ($a in $adapters) {
            $name = ($a.Name -as [string]) -or ""
            $vendor = ($a.AdapterCompatibility -as [string]) -or ""

            if ($name -match 'Intel' -or $vendor -match 'Intel') {
                $iGPUs += $a
            } elseif ($name -match 'NVIDIA' -or $vendor -match 'NVIDIA' -or $name -match 'AMD' -or $vendor -match 'AMD' -or $name -match 'Radeon') {
                $dGPUs += $a
            } else {
                # Heuristic: treat unknowns with 'Microsoft' or 'Basic' as integrated fallbacks
                if ($vendor -match 'Microsoft' -or $name -match 'Basic' -or $name -match 'Microsoft') { $iGPUs += $a } else { $dGPUs += $a }
            }
        }

        $isHybrid = ($iGPUs.Count -gt 0 -and $dGPUs.Count -gt 0)

        return @{ IsHybrid = $isHybrid; Integrated = $iGPUs; Discrete = $dGPUs; AllAdapters = $adapters }
    }
    catch {
        Write-Log "Failed to detect GPU adapters: $_" "WARNING"
        return @{ IsHybrid = $false; Integrated = @(); Discrete = @(); AllAdapters = @() }
    }
}

# Show guidance to the user for hybrid GPU systems and optionally open Graphics Settings
function Show-HybridGPUGuidance {
    param([Hashtable]$HybridInfo)

    if (-not $HybridInfo) { return }

    if ($HybridInfo.IsHybrid) {
        Write-Log "Hybrid GPU configuration detected" "WARNING"
        Write-Log "  Integrated GPU(s): $($HybridInfo.Integrated | ForEach-Object { $_.Name } -join ', ')" "INFO"
        Write-Log "  Discrete GPU(s): $($HybridInfo.Discrete | ForEach-Object { $_.Name } -join ', ')" "INFO"

        Write-Log "Recommendations to ensure games/benchmarks use the discrete GPU:" "INFO"
        Write-Log "  - Open Windows Settings -> System -> Display -> Graphics -> set your game to 'High performance' (maps to dGPU)" "INFO"
        Write-Log "  - Or configure per-app settings in your GPU vendor control panel (NVIDIA/AMD/Intel)" "INFO"
        Write-Log "  - Plug into AC power and use a High Performance power plan for benchmarking" "INFO"

        # Offer quick actions: open Settings, list current per-app GPU prefs, or set one now
        Write-Log "Quick actions: (L)ist per-app GPU preferences, (S)et preference for an app, (O)pen Graphics Settings, (N)one" "INFO"
        $choice = Read-Host "Choose action [L/S/O/N] (default N)"
        switch ($choice.ToUpper()) {
            'L' {
                $prefs = Get-UserGPUPreferences
                if ($prefs.Count -eq 0) { Write-Log "No per-app GPU preferences found." "INFO" }
                else {
                    Write-Log "Per-app GPU preferences:" "INFO"
                    foreach ($p in $prefs) { Write-Log "  $($p.App) => $($p.Value)" "INFO" }
                }
            }
            'S' {
                $app = Read-Host "Enter full path to the application executable (e.g. C:\\Games\\Game.exe)"
                if (-not $app) { Write-Log "No application path entered, aborting." "INFO"; break }
                if (-not (Test-Path $app)) {
                    $ok = Read-Host "Path not found. Continue and create entry anyway? (y/N)"
                    if (-not ($ok -and $ok -match '^[Yy]')) { Write-Log "Aborted by user." "INFO"; break }
                }
                Write-Log "Preference options: (1) Default, (2) PowerSaving (iGPU), (3) HighPerformance (dGPU)" "INFO"
                $prefChoice = Read-Host "Choose preference [1/2/3] (default 3)"
                switch ($prefChoice) { '1' { $pref='Default' } '2' { $pref='PowerSaving' } default { $pref='HighPerformance' } }
                Write-Log "You selected: $pref for $app" "INFO"
                $confirm = Read-Host "Apply this preference now? (y/N)"
                if ($confirm -and $confirm -match '^[Yy]') {
                    Set-UserGPUPreference -AppPath $app -Preference $pref -Force:$true
                } else { Write-Log "No changes applied." "INFO" }
            }
            'O' {
                try { Start-Process ms-settings:display-graphics } catch { Write-Log "Failed to open Settings: $_" "WARNING" }
            }
            default { Write-Log "No quick action taken." "INFO" }
        }
    }
    else { Write-Log "No hybrid GPU detected (single GPU system)" "INFO" }
}


function Get-UserGPUPreferences {
    $path = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
    if (-not (Test-Path $path)) { return @() }
    try {
        $item = Get-ItemProperty -Path $path -ErrorAction Stop
        $props = $item.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' }
        $out = @()
        foreach ($p in $props) { $out += [PSCustomObject]@{ App = $p.Name; Value = $p.Value } }
        return $out
    }
    catch {
        Write-Log "Failed to read UserGpuPreferences: $_" "WARNING"
        return @()
    }
}

# Set per-app GPU preference. Preference values: Default (0), PowerSaving (1), HighPerformance (2)
function Set-UserGPUPreference {
    param(
        [Parameter(Mandatory=$true)][string]$AppPath,
        [ValidateSet('Default','PowerSaving','HighPerformance')][string]$Preference = 'HighPerformance',
        [switch]$Force
    )

    $map = @{ Default = 0; PowerSaving = 1; HighPerformance = 2 }
    $num = $map[$Preference]
    $regPath = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'

    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $valueData = "GpuPreference=$num"
        if (-not $Force) {
            $ok = Read-Host "About to write registry entry: $AppPath => $valueData. Continue? (y/N)"
            if (-not ($ok -and $ok -match '^[Yy]')) { Write-Log "User aborted setting GPU preference." "INFO"; return $false }
        }
        Set-ItemProperty -Path $regPath -Name $AppPath -Value $valueData -Type String -Force
        Write-Log "Set GPU preference for $AppPath to $Preference" "SUCCESS"
        Write-Log "Note: Changes may take effect after next launch of the application or a sign-out/sign-in." "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to set GPU preference: $_" "ERROR"
        return $false
    }
}

# Remove per-app GPU preference entry
function Remove-UserGPUPreference {
    param([Parameter(Mandatory=$true)][string]$AppPath)
    $regPath = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
    try {
        if (-not (Test-Path $regPath)) { Write-Log "UserGpuPreferences not present." "INFO"; return $false }
        if (-not (Get-ItemProperty -Path $regPath -Name $AppPath -ErrorAction SilentlyContinue)) { Write-Log "No entry for $AppPath found." "INFO"; return $false }
        $ok = Read-Host "Remove GPU preference entry for $AppPath? (y/N)"
        if (-not ($ok -and $ok -match '^[Yy]')) { Write-Log "User aborted removal." "INFO"; return $false }
        Remove-ItemProperty -Path $regPath -Name $AppPath -ErrorAction Stop
        Write-Log "Removed GPU preference for $AppPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to remove GPU preference: $_" "ERROR"
        return $false
    }
}

# Check if GPU supports HAGS (Hardware Accelerated GPU Scheduling)
function Test-HAGSCompatibility {
    try {
        $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Remote|Virtual' } | Select-Object -First 1
        $name = $gpu.Name.ToLower()
        
        # NVIDIA: RTX 20 series (Turing) and newer
        if ($name -match 'rtx (20|30|40)\d{2}|rtx (a\d{4})|quadro rtx') {
            return $true
        }
        # Older NVIDIA (GTX 10 series and older) - not recommended
        elseif ($name -match 'gtx (10|9)\d{2}|gtx (7|6)\d{2}') {
            Write-Log "Older NVIDIA GPU detected - HAGS not recommended for GTX 10 series and older" "WARNING"
            return $false
        }
        # AMD: RDNA architecture (RX 5000 series and newer)
        elseif ($name -match 'rx (5\d{3}|6\d{3}|7\d{3})') {
            return $true
        }
        # Older AMD (GCN architecture) - not recommended
        elseif ($name -match 'rx (4\d{2}|5\d{2}|vega)') {
            Write-Log "Older AMD GPU detected - HAGS not recommended for pre-RDNA GPUs" "WARNING"
            return $false
        }
        # Intel Arc
        elseif ($name -match 'arc (a\d{3})') {
            return $true
        }
        else {
            Write-Log "Unable to determine GPU generation - HAGS compatibility unknown" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to check HAGS compatibility: $_" "WARNING"
        return $false
    }
}

# Detect AMD X3D CPUs (require Game Bar for optimal thread scheduling)
function Test-AMDX3DCPU {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $name = $cpu.Name
        
        if ($name -match '5800X3D|5900X3D|7800X3D|7900X3D|7950X3D|9800X3D|9900X3D|9950X3D') {
            return $true
        }
        return $false
    }
    catch {
        Write-Log "Failed to detect AMD X3D CPU: $_" "WARNING"
        return $false
    }
}

# Display feature requirements for all optimizations
function Show-FeatureRequirements {
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Gaming Optimization Feature Requirements" "INFO"
    Write-Log "========================================" "INFO"
    
    $winVersion = Get-WindowsVersionInfo
    
    Write-Log "" "INFO"
    Write-Log "Your System:" "INFO"
    Write-Log "  Windows Version: $($winVersion.VersionName)" "INFO"
    Write-Log "  Build Number: $($winVersion.Build).$($winVersion.UBR)" "INFO"
    Write-Log "" "INFO"
    
    $features = @(
        @{
            Name = "Hardware-Accelerated GPU Scheduling (HAGS)"
            MinBuild = 19041
            MinVersion = "Windows 10 2004 (Build 19041)"
            Requirements = @(
                "Windows 10 2004+ or Windows 11",
                "NVIDIA RTX 20+ series, AMD RX 5000+ series, or Intel Arc GPU",
                "Latest GPU drivers"
            )
            Supported = $winVersion.SupportsHAGS
        },
        @{
            Name = "DirectStorage"
            MinBuild = 22000
            MinVersion = "Windows 11 (Build 22000)"
            Requirements = @(
                "Windows 11 (any version)",
                "NVMe SSD (PCIe 3.0 or newer)",
                "DirectX 12 GPU with Shader Model 6.0+",
                "Game must support DirectStorage API"
            )
            Supported = $winVersion.SupportsDirectStorage
        },
        @{
            Name = "Auto HDR"
            MinBuild = 22000
            MinVersion = "Windows 11 (Build 22000)"
            Requirements = @(
                "Windows 11 (any version)",
                "HDR-capable display",
                "DirectX 11 or DirectX 12 game"
            )
            Supported = $winVersion.SupportsAutoHDR
        },
        @{
            Name = "Native NVMe I/O Path"
            MinBuild = 26100
            MinVersion = "Windows 11 24H2 (Build 26100)"
            Requirements = @(
                "Windows 11 24H2 or newer (Build 26100+)",
                "Latest Windows updates installed",
                "NVMe SSD",
                "Microsoft in-box NVMe driver (NOT vendor drivers)",
                "Full system backup before enabling"
            )
            Supported = $winVersion.SupportsNativeNVMe
            Notes = @(
                "UNOFFICIAL for Windows 11 (community-discovered values)",
                "May break vendor tools (Samsung Magician, etc.)",
                "Expected gains: 10-15% throughput on consumer hardware",
                "Server workloads may see up to 80% IOPS improvement"
            )
        },
        @{
            Name = "Game Mode"
            MinBuild = 22000
            MinVersion = "Windows 11 (Build 22000)"
            Requirements = @(
                "Windows 11 (recommended, also works on Windows 10)",
                "No additional hardware requirements"
            )
            Supported = $true
        },
        @{
            Name = "Core Optimizations (Win32Priority, Network, etc.)"
            MinBuild = 19041
            MinVersion = "Windows 10 2004 (Build 19041)"
            Requirements = @(
                "Windows 10 2004+ or Windows 11",
                "No additional hardware requirements"
            )
            Supported = $true
        }
    )
    
    Write-Log "Feature Support Status:" "INFO"
    Write-Log "" "INFO"
    
    foreach ($feature in $features) {
        $statusIcon = if ($feature.Supported) { "[OK]" } else { "[X]" }
        $statusColor = if ($feature.Supported) { "SUCCESS" } else { "WARNING" }
        
        Write-Log "$statusIcon $($feature.Name)" $statusColor
        Write-Log "    Minimum: $($feature.MinVersion)" "INFO"
        
        if (-not $feature.Supported) {
            Write-Log "    Status: NOT SUPPORTED on your system" "WARNING"
            Write-Log "    Current Build: $($winVersion.Build) | Required: $($feature.MinBuild)+" "WARNING"
        } else {
            Write-Log "    Status: SUPPORTED on your system" "SUCCESS"
        }
        
        Write-Log "    Requirements:" "INFO"
        foreach ($req in $feature.Requirements) {
            Write-Log "      - $req" "INFO"
        }
        
        if ($feature.Notes) {
            Write-Log "    Additional Notes:" "INFO"
            foreach ($note in $feature.Notes) {
                Write-Log "      ! $note" "WARNING"
            }
        }
        
        Write-Log "" "INFO"
    }
    
    Write-Log "========================================" "INFO"
    Write-Log "Key Build Numbers:" "INFO"
    Write-Log "  19041 = Windows 10 2004 (HAGS support starts)" "INFO"
    Write-Log "  22000 = Windows 11 21H2 (DirectStorage, Auto HDR)" "INFO"
    Write-Log "  22621 = Windows 11 22H2" "INFO"
    Write-Log "  22631 = Windows 11 23H2" "INFO"
    Write-Log "  26100 = Windows 11 24H2 (Native NVMe support)" "INFO"
    Write-Log "  26200 = Windows 11 25H2 (future)" "INFO"
    Write-Log "========================================" "INFO"
}

# Apply Win32PrioritySeparation optimization
function Set-Win32Priority {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    Write-Log "Configuring Win32PrioritySeparation for gaming..."
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    try {
        # SAFETY: Verify key exists before modification
        if (-not (Test-Path $path)) {
            Write-Log "WARNING: PriorityControl key does not exist, will be created" "WARNING"
        }
        
        if ($PSCmdlet.ShouldProcess("Win32PrioritySeparation", "Set to 40 (Short, Fixed Boost)")) {
            # Only modify the value, never delete keys or reset them
            Set-ItemProperty -Path $path -Name "Win32PrioritySeparation" -Value 40 -Type DWord
            Write-Log "Set Win32PrioritySeparation to 40 (decimal) - Short, Fixed Boost" "SUCCESS"
            return $true
        }
        else {
            Write-Log "WhatIf: Would set Win32PrioritySeparation to 40" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Failed to set Win32PrioritySeparation: $_" "ERROR"
        return $false
    }
}

# Disable Power Throttling
function Disable-PowerThrottling {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    Write-Log "Disabling Power Throttling..."
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
    
    try {
        if ($PSCmdlet.ShouldProcess("PowerThrottling", "Disable Power Throttling")) {
            # SAFETY: Check if key exists before attempting modification
            if (-not (Test-Path $path)) {
                Write-Log "PowerThrottling key does not exist, creating it safely..." "INFO"
                New-Item -Path $path -Force | Out-Null
                Write-Log "Created PowerThrottling registry key" "INFO"
            }
            else {
                Write-Log "PowerThrottling key exists, modifying value only..." "INFO"
            }
            
            # Only modify the value, never reset or delete the key
            Set-ItemProperty -Path $path -Name "PowerThrottlingOff" -Value 1 -Type DWord
            Write-Log "Power Throttling disabled" "SUCCESS"
            return $true
        }
        else {
            Write-Log "WhatIf: Would disable Power Throttling" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Failed to disable Power Throttling: $_" "ERROR"
        return $false
    }
}

# Apply DWM MPO Fix (Windows 11 24H2+)
function Set-DwmMpoFix {
    Write-Log "Applying DWM MPO Fix..."
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
    try {
        Set-ItemProperty -Path $path -Name "OverlayMinFPS" -Value 0 -Type DWord
        Write-Log "DWM MPO Fix applied - fixes Alt+Tab rendering issues" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to apply DWM MPO Fix: $_" "ERROR"
        return $false
    }
}

# Disable Network Throttling
function Disable-NetworkThrottling {
    Write-Log "Disabling Network Throttling..."
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    try {
        # Value should be 0xffffffff (4294967295 in decimal)
        Set-ItemProperty -Path $path -Name "NetworkThrottlingIndex" -Value 4294967295 -Type DWord
        Write-Log "Network Throttling disabled" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to disable Network Throttling: $_" "ERROR"
        return $false
    }
}

# Set System Responsiveness
function Set-SystemResponsiveness {
    Write-Log "Setting System Responsiveness to 10%..."
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    try {
        Set-ItemProperty -Path $path -Name "SystemResponsiveness" -Value 10 -Type DWord
        Write-Log "System Responsiveness set to 10 (allocates more CPU to games)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to set System Responsiveness: $_" "ERROR"
        return $false
    }
}

# Optimize Games priority
function Set-GamesPriority {
    Write-Log "Optimizing Games priority settings..."
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    
    try {
        # Create the key if it doesn't exist
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
            Write-Log "Created Games task registry key"
        }
        
        # Set optimal values for gaming
        Set-ItemProperty -Path $path -Name "Affinity" -Value 0 -Type DWord
        Set-ItemProperty -Path $path -Name "Background Only" -Value "False" -Type String
        Set-ItemProperty -Path $path -Name "Clock Rate" -Value 10000 -Type DWord
        Set-ItemProperty -Path $path -Name "GPU Priority" -Value 8 -Type DWord
        Set-ItemProperty -Path $path -Name "Priority" -Value 6 -Type DWord
        Set-ItemProperty -Path $path -Name "Scheduling Category" -Value "High" -Type String
        Set-ItemProperty -Path $path -Name "SFIO Priority" -Value "High" -Type String
        
        Write-Log "Games priority optimized for better performance" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to set Games priority: $_" "ERROR"
        return $false
    }
}

# AMD Ryzen-specific optimizations
function Set-AMDRyzenOptimizations {
    Write-Log "Applying AMD Ryzen-specific optimizations..."
    
    $cpuMan = Get-CPUManufacturer
    if ($cpuMan -ne 'AMD') {
        Write-Log "Skipping AMD optimizations - CPU is not AMD Ryzen" "INFO"
        return $false
    }
    
    try {
        # AMD recommends High Performance or AMD Ryzen Balanced power plan
        Write-Log "AMD CPU detected - checking power plan recommendations..." "INFO"
        
        $currentPlan = (Get-CimInstance -ClassName Win32_PowerPlan -Namespace root\cimv2\power | Where-Object {$_.IsActive}).ElementName
        Write-Log "Current power plan: $currentPlan" "INFO"
        
        # Check for AMD Ryzen Balanced plan
        $amdPlan = Get-CimInstance -ClassName Win32_PowerPlan -Namespace root\cimv2\power | Where-Object {$_.ElementName -match 'AMD Ryzen Balanced'}
        
        if ($amdPlan) {
            Write-Log "AMD Ryzen Balanced power plan detected - this is optimal for Ryzen CPUs" "SUCCESS"
        }
        else {
            Write-Log "AMD Ryzen Balanced power plan not found" "WARNING"
            Write-Log "For AMD Ryzen: Install AMD chipset drivers from AMD.com to get the optimal 'AMD Ryzen Balanced' power plan" "INFO"
            Write-Log "Alternatively, use Windows 'High Performance' power plan for desktop" "INFO"
        }
        
        # AMD-specific registry optimizations for CPPC (Collaborative Processor Performance Control)
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7"
        
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "Attributes" -Value 2 -Type DWord
            Write-Log "Enabled CPPC (AMD Preferred Cores) visibility in power options" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to apply AMD optimizations: $_" "ERROR"
        return $false
    }
}

# Intel-specific optimizations (Core Parking note)
function Set-IntelOptimizations {
    Write-Log "Applying Intel-specific optimizations..."
    
    $cpuMan = Get-CPUManufacturer
    if ($cpuMan -ne 'Intel') {
        Write-Log "Skipping Intel optimizations - CPU is not Intel" "INFO"
        return $false
    }
    
    try {
        Write-Log "Intel CPU detected" "INFO"
        Write-Log "NOTE: For Intel CPUs, consider using ParkControl to disable Core Parking and Frequency Scaling" "INFO"
        Write-Log "Download ParkControl from: https://bitsum.com/parkcontrol/" "INFO"
        Write-Log "This is NOT required for AMD Ryzen CPUs (they handle core parking differently)" "INFO"
        
        # Intel-specific High Performance plan recommendation
        $currentPlan = (Get-CimInstance -ClassName Win32_PowerPlan -Namespace root\cimv2\power | Where-Object {$_.IsActive}).ElementName
        Write-Log "Current power plan: $currentPlan" "INFO"
        Write-Log "For Intel CPUs, consider 'High Performance' or custom plans like 'Khorvie's PowerPlan'" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to apply Intel optimizations: $_" "ERROR"
        return $false
    }
}

# Optimize TCP for Gaming
function Optimize-TcpSettings {
    Write-Log "Optimizing TCP settings for gaming..."
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    
    try {
        # Apply recommended TCP optimizations
        Set-ItemProperty -Path $path -Name "DefaultTTL" -Value 64 -Type DWord
        Set-ItemProperty -Path $path -Name "GlobalMaxTcpWindowSize" -Value 65535 -Type DWord
        Set-ItemProperty -Path $path -Name "MaxUserPort" -Value 65534 -Type DWord
        Set-ItemProperty -Path $path -Name "Tcp1323Opts" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "TcpMaxDupAcks" -Value 2 -Type DWord
        Set-ItemProperty -Path $path -Name "TCPTimedWaitDelay" -Value 30 -Type DWord
        
        Write-Log "TCP settings optimized for lower latency and better bandwidth" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to optimize TCP settings: $_" "ERROR"
        return $false
    }
}

# Disable Nagle's Algorithm (requires network adapter identification)
function Disable-NaglesAlgorithm {
    Write-Log "Disabling Nagle's Algorithm for active network interface..."
    
    try {
        # Get IPv4 address
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual"} | Select-Object -First 1).IPAddress
        
        if (-not $ipAddress) {
            Write-Log "Could not find active IPv4 address, skipping Nagle's Algorithm disable" "WARNING"
            return $false
        }
        
        Write-Log "Found active IPv4: $ipAddress"
        
        # Find the interface with matching IP
        $interfacePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        $interfaces = Get-ChildItem -Path $interfacePath
        
        foreach ($interface in $interfaces) {
            $dhcpIP = (Get-ItemProperty -Path $interface.PSPath -Name "DhcpIPAddress" -ErrorAction SilentlyContinue).DhcpIPAddress
            $staticIP = (Get-ItemProperty -Path $interface.PSPath -Name "IPAddress" -ErrorAction SilentlyContinue).IPAddress
            
            if ($dhcpIP -eq $ipAddress -or $staticIP -contains $ipAddress) {
                Set-ItemProperty -Path $interface.PSPath -Name "TcpNoDelay" -Value 1 -Type DWord
                Set-ItemProperty -Path $interface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord
                Write-Log "Nagle's Algorithm disabled for interface with IP $ipAddress" "SUCCESS"
                return $true
            }
        }
        
        Write-Log "Could not find matching network interface" "WARNING"
        return $false
    }
    catch {
        Write-Log "Failed to disable Nagle's Algorithm: $_" "ERROR"
        return $false
    }
}

# Enable Game Mode
function Enable-GameMode {
    Write-Log "Ensuring Game Mode is enabled..."
    
    $path = "HKCU:\Software\Microsoft\GameBar"
    
    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        Set-UserRegistryValue -Path $path -Name "AutoGameModeEnabled" -Value 1 -Type DWord
        Write-Log "Game Mode enabled" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to enable Game Mode: $_" "ERROR"
        return $false
    }
}

# Enable experimental Native NVMe support (Windows 11 24H2/25H2)
function Enable-ExperimentalNVMe {
    Write-Log "Checking for Native NVMe support..."
    
    $winVersion = Get-WindowsVersionInfo
    
    if (-not $winVersion.SupportsNativeNVMe) {
        Write-Log "Native NVMe requires Windows 11 24H2 or newer (Build 26100+)" "WARNING"
        Write-Log "Current version: $($winVersion.VersionName) (Build $($winVersion.Build))" "WARNING"
        Write-Log "Feature Status: NOT SUPPORTED on your system" "WARNING"
        return $false
    }
    
    # Check for NVMe drives
    $nvmeDisks = Get-Disk | Where-Object { $_.BusType -eq 'NVMe' }
    
    if ($nvmeDisks.Count -eq 0) {
        Write-Log "No NVMe drives detected - skipping Native NVMe configuration" "WARNING"
        return $false
    }
    
    Write-Log "Found $($nvmeDisks.Count) NVMe drive(s):" "INFO"
    foreach ($disk in $nvmeDisks) {
        Write-Log "  - $($disk.Model) ($($disk.Size / 1GB)GB)" "INFO"
    }

    # Detect RAID/VMD/StoreMI style stacks that block native NVMe path
    try {
        $storageControllers = @(Get-PnpDevice -Class SCSIAdapter -ErrorAction SilentlyContinue)
        $blockedControllers = $storageControllers | Where-Object { $_.FriendlyName -match 'VMD|RST|Rapid Storage|Optane|StoreMI|RAID' }
        if ($blockedControllers -and $blockedControllers.Count -gt 0) {
            $names = ($blockedControllers | Select-Object -ExpandProperty FriendlyName | Sort-Object -Unique) -join '; '
            Write-Log "Detected RAID/VMD/StoreMI controller(s): $names" "WARNING"
            Write-Log "Native NVMe path requires the drive to be exposed via 'Standard NVM Express Controller' (Microsoft), not through RAID/VMD/StoreMI." "WARNING"
            Write-Log "Disable the RAID/VMD/StoreMI mode in firmware and remove acceleration layers before applying Native NVMe flags." "WARNING"
            return $false
        }
    } catch {
        Write-Debug "Controller detection failed: $_"
    }
    
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"
        
        # Create key if it doesn't exist
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
            Write-Log "Created FeatureManagement\Overrides registry key" "INFO"
        }
        
        Write-Log "Enabling Native NVMe experimental features..." "INFO"
        
        # Enable Native NVMe feature flags for Windows 11
        # Based on: https://windowsforum.com/threads/native-nvme-i-o-path-in-windows-server-2025-and-windows-11-performance-boost.394539/
        # IMPORTANT: These are community-discovered values for Windows 11 (unofficial)
        # Windows Server 2025 uses different value: 1176759950
        Set-ItemProperty -Path $path -Name "735209102" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "1853569164" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "156965516" -Value 1 -Type DWord
        
        Write-Log "Native NVMe features enabled successfully" "SUCCESS"
        Write-Log "" "INFO"
        Write-Log "[WARNING] IMPORTANT NOTES:" "WARNING"
        Write-Log "  - MINIMUM REQUIREMENTS:" "INFO"
        Write-Log "    - Windows 11 24H2 or newer (Build 26100+)" "INFO"
        Write-Log "    - Latest Windows updates installed" "INFO"
        Write-Log "    - Microsoft in-box NVMe driver (not vendor drivers)" "INFO"
        Write-Log "  - Restart required for Native NVMe to take effect" "WARNING"
        Write-Log "  - Expected improvements (lab results):" "INFO"
        Write-Log "    - Server workloads: Up to 80% more IOPS, 45% less CPU usage" "INFO"
        Write-Log "    - Consumer workloads: Typically 10-15% throughput improvement" "INFO"
        Write-Log "  - After restart, check Device Manager -> 'Storage disks' section" "INFO"
        Write-Log "  - COMPATIBILITY WARNINGS:" "WARNING"
        Write-Log "    - May break vendor tools (Samsung Magician, Crucial Storage Executive, etc.)" "WARNING"
        Write-Log "    - Will NOT work if using vendor NVMe drivers" "WARNING"
        Write-Log "    - May cause issues with RAID configurations" "WARNING"
        Write-Log "    - These registry values are UNOFFICIAL for Windows 11" "WARNING"
        Write-Log "  - Monitor drive temperatures manually (some monitoring tools may not work)" "WARNING"
        Write-Log "" "INFO"
        Write-Log "To verify Native NVMe is working after restart:" "INFO"
        Write-Log "  1. Open Device Manager" "INFO"
        Write-Log "  2. Expand 'Storage disks' - NVMe drives should appear there" "INFO"
        Write-Log "  3. Use CrystalDiskMark to benchmark before/after" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to enable Native NVMe: $_" "ERROR"
        return $false
    }
}

# Enable Hardware Accelerated GPU Scheduling (HAGS)
function Enable-HAGS {
    Write-Log "Configuring Hardware Accelerated GPU Scheduling (HAGS)..."
    
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    
    try {
        $winVersion = Get-WindowsVersionInfo
        
        if (-not $winVersion.SupportsHAGS) {
            Write-Log "HAGS requires Windows 10 2004 or newer (Build 19041+)" "WARNING"
            Write-Log "Current version: $($winVersion.VersionName) (Build $($winVersion.Build))" "WARNING"
            return $false
        }
        
        # Check GPU compatibility
        $isCompatible = Test-HAGSCompatibility
        if (-not $isCompatible) {
            Write-Log "Your GPU may not be compatible with HAGS or may experience issues" "WARNING"
            Write-Log "HAGS is recommended for: NVIDIA RTX 20+ series, AMD RX 5000+ series, Intel Arc" "INFO"
            Write-Log "Skipping HAGS enablement for safety" "INFO"
            return $false
        }
        
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        Set-ItemProperty -Path $path -Name "HwSchMode" -Value 2 -Type DWord
        Write-Log "HAGS enabled (HwSchMode = 2)" "SUCCESS"
        Write-Log "Note: Restart required for HAGS to take effect" "INFO"
        Write-Log "Note: Check GPU driver is up to date for full HAGS support" "INFO"
        Write-Log "Note: If you experience stuttering, disable HAGS in Windows Settings" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to enable HAGS: $_" "WARNING"
        return $false
    }
}

# Disable Game DVR and Game Bar (reduces background recording overhead)
function Disable-GameDVR {
    Write-Log "Disabling Game DVR and Game Bar background recording..."
    
    try {
        # Check for AMD X3D CPUs - they need Game Bar for proper thread scheduling
        $isX3D = Test-AMDX3DCPU
        
        if ($isX3D) {
            Write-Log "" "INFO"
            Write-Log "[ALERT] AMD X3D CPU DETECTED" "WARNING"
            Write-Log "AMD X3D CPUs (5800X3D, 7800X3D, 7900X3D, 7950X3D, 9800X3D, etc.) require" "WARNING"
            Write-Log "Xbox Game Bar to remain ENABLED for optimal thread scheduling." "WARNING"
            Write-Log "" "INFO"
            Write-Log "Action: Disabling only Game DVR (recording), keeping Game Bar enabled" "INFO"
            Write-Log "" "INFO"
            
            # Only disable DVR recording, keep Game Bar functional
            $path2 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
            if (-not (Test-Path $path2)) {
                New-Item -Path $path2 -Force | Out-Null
            }
            Set-UserRegistryValue -Path $path2 -Name "AppCaptureEnabled" -Value 0 -Type DWord
            Set-UserRegistryValue -Path $path2 -Name "HistoricalCaptureEnabled" -Value 0 -Type DWord
            
            Write-Log "Game DVR recording disabled, Game Bar preserved for X3D CPU" "SUCCESS"
            return $true
        }
        
        # Standard CPUs - safe to disable Game Bar completely
        
        # Disable Game DVR
        $path1 = "HKCU:\System\GameConfigStore"
        if (-not (Test-Path $path1)) {
            New-Item -Path $path1 -Force | Out-Null
        }
        Set-UserRegistryValue -Path $path1 -Name "GameDVR_Enabled" -Value 0 -Type DWord
        
        # Disable Game Bar
        $path2 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
        if (-not (Test-Path $path2)) {
            New-Item -Path $path2 -Force | Out-Null
        }
        Set-UserRegistryValue -Path $path2 -Name "AppCaptureEnabled" -Value 0 -Type DWord
        Set-UserRegistryValue -Path $path2 -Name "HistoricalCaptureEnabled" -Value 0 -Type DWord
        
        # Disable Game Bar Tips
        $path3 = "HKCU:\Software\Microsoft\GameBar"
        if (-not (Test-Path $path3)) {
            New-Item -Path $path3 -Force | Out-Null
        }
        Set-UserRegistryValue -Path $path3 -Name "ShowStartupPanel" -Value 0 -Type DWord
        Set-UserRegistryValue -Path $path3 -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord
        
        Write-Log "Game DVR and Game Bar disabled" "SUCCESS"
        Write-Log "Note: Game Mode is still enabled for better performance" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to disable Game DVR: $_" "ERROR"
        return $false
    }
}

# Disable Fullscreen Optimizations (improves compatibility)
function Set-FullscreenOptimizations {
    Write-Log "Configuring Fullscreen Optimizations..."
    
    try {
        $path = "HKCU:\System\GameConfigStore"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        # Disable fullscreen optimizations globally
        Set-UserRegistryValue -Path $path -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord
        Set-UserRegistryValue -Path $path -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord
        Set-UserRegistryValue -Path $path -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Type DWord
        
        Write-Log "Fullscreen Optimizations configured for compatibility" "SUCCESS"
        Write-Log "Note: Individual games can still override this in Properties" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to configure Fullscreen Optimizations: $_" "WARNING"
        return $false
    }
}

# Set timer resolution for better frame pacing
function Set-TimerResolution {
    Write-Log "Configuring Windows Timer Resolution..."
    
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        # Set GlobalTimerResolutionRequests to allow applications to set timer resolution
        Set-ItemProperty -Path $path -Name "GlobalTimerResolutionRequests" -Value 1 -Type DWord
        
        Write-Log "Timer Resolution configured for better frame pacing" "SUCCESS"
        Write-Log "Note: Some games use tools like RTSS or in-game settings to manage this" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to configure Timer Resolution: $_" "WARNING"
        return $false
    }
}

# Optimize input latency (mouse/keyboard buffer reduction)
function Set-InputLatencyOptimizations {
    Write-Log "Optimizing input latency (mouse/keyboard buffers)..."
    
    try {
        $mousePathParams = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"
        $kbdPathParams = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"
        
        # Create keys if they don't exist
        if (-not (Test-Path $mousePathParams)) {
            New-Item -Path $mousePathParams -Force | Out-Null
            Write-Log "Created mouclass Parameters key"
        }
        if (-not (Test-Path $kbdPathParams)) {
            New-Item -Path $kbdPathParams -Force | Out-Null
            Write-Log "Created kbdclass Parameters key"
        }
        
        # Reduce input buffers from default 100 to 16 (lower latency)
        Set-ItemProperty -Path $mousePathParams -Name "MouseDataQueueSize" -Value 16 -Type DWord
        Set-ItemProperty -Path $kbdPathParams -Name "KeyboardDataQueueSize" -Value 16 -Type DWord
        
        Write-Log "Input latency optimized: MouseDataQueueSize=16, KeyboardDataQueueSize=16" "SUCCESS"
        Write-Log "NOTE: Restart required for input latency changes to take effect" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to optimize input latency: $_" "ERROR"
        return $false
    }
}

# Optimize memory management (DisablePagingExecutive)
function Set-MemoryManagementOptimizations {
    Write-Log "Optimizing memory management for gaming..."
    
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        
        # Lock kernel in RAM (prevents paging of kernel to disk)
        # Recommended for systems with 16GB+ RAM
        $ram = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        
        if ($ram -ge 16) {
            Set-ItemProperty -Path $path -Name "DisablePagingExecutive" -Value 1 -Type DWord
            Write-Log "DisablePagingExecutive enabled - kernel locked in RAM" "SUCCESS"
        } else {
            Write-Log "Skipping DisablePagingExecutive - system has less than 16GB RAM ($([math]::Round($ram, 1))GB)" "WARNING"
            Write-Log "DisablePagingExecutive is only recommended for systems with 16GB+ RAM" "INFO"
        }
        
        # Ensure LargeSystemCache is disabled (already done in Set-SystemCache)
        $currentCache = (Get-ItemProperty -Path $path -Name "LargeSystemCache" -ErrorAction SilentlyContinue).LargeSystemCache
        if ($currentCache -ne 0) {
            Set-ItemProperty -Path $path -Name "LargeSystemCache" -Value 0 -Type DWord
            Write-Log "LargeSystemCache disabled (optimize for programs)" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to optimize memory management: $_" "ERROR"
        return $false
    }
}

# Disable Windows Update P2P delivery optimization
function Disable-WindowsUpdateP2P {
    Write-Log "Disabling Windows Update P2P delivery optimization..."
    
    try {
        $path1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        $path2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        
        # Create paths if they don't exist
        if (-not (Test-Path $path1)) {
            New-Item -Path $path1 -Force | Out-Null
        }
        if (-not (Test-Path $path2)) {
            New-Item -Path $path2 -Force | Out-Null
        }
        
        # Disable P2P sharing (mode 0 = HTTP only, no P2P)
        Set-ItemProperty -Path $path1 -Name "DODownloadMode" -Value 0 -Type DWord
        Set-ItemProperty -Path $path2 -Name "DODownloadMode" -Value 0 -Type DWord
        
        Write-Log "Windows Update P2P disabled - prevents background bandwidth usage during gaming" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to disable Windows Update P2P: $_" "ERROR"
        return $false
    }
}

# Disable large system cache (improves gaming performance)
function Set-SystemCache {
    Write-Log "Configuring System Cache for gaming..."
    
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        
        # LargeSystemCache = 0 prioritizes application cache over system file cache
        Set-ItemProperty -Path $path -Name "LargeSystemCache" -Value 0 -Type DWord
        
        Write-Log "System Cache optimized for gaming (LargeSystemCache = 0)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to configure System Cache: $_" "ERROR"
        return $false
    }
}

# Check VBS (Virtualization-Based Security) status
function Test-VBSStatus {
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "VBS (Virtualization-Based Security) Check" "INFO"
    Write-Log "========================================" "INFO"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if (-not $deviceGuard) {
            Write-Log "Unable to query VBS status" "WARNING"
            return $false
        }
        
        $vbsStatus = $deviceGuard.VirtualizationBasedSecurityStatus
        
        if ($vbsStatus -eq 2) {
            Write-Log "" "INFO"
            Write-Log "[ALERT] VBS/Memory Integrity is ENABLED" "WARNING"
            Write-Log "" "INFO"
            Write-Log "Impact on Gaming Performance:" "INFO"
            Write-Log "  - FPS reduction: 5-15% (varies by game)" "INFO"
            Write-Log "  - More pronounced in CPU-intensive games" "INFO"
            Write-Log "  - Security benefit: Protection against rootkits and memory exploits" "INFO"
            Write-Log "" "INFO"
            Write-Log "Recommendation for DEDICATED gaming PCs:" "INFO"
            Write-Log "  Consider disabling VBS for better performance" "INFO"
            Write-Log "" "INFO"
            Write-Log "To disable VBS/Memory Integrity:" "INFO"
            Write-Log "  1. Open Windows Security" "INFO"
            Write-Log "  2. Go to: Device Security -> Core isolation" "INFO"
            Write-Log "  3. Turn OFF 'Memory integrity'" "INFO"
            Write-Log "  4. Restart your computer" "INFO"
            Write-Log "" "INFO"
            Write-Log "[WARNING] Only disable on dedicated gaming PCs" "WARNING"
            Write-Log "[WARNING] Do NOT disable on work PCs or systems handling sensitive data" "WARNING"
            Write-Log "" "INFO"
            return $true
        }
        elseif ($vbsStatus -eq 1) {
            Write-Log "VBS is supported but not enabled" "INFO"
            Write-Log "[GOOD] Optimal configuration for gaming performance" "SUCCESS"
            return $true
        }
        else {
            Write-Log "VBS is not supported or disabled" "INFO"
            Write-Log "[GOOD] Optimal configuration for gaming performance" "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Failed to check VBS status: $_" "WARNING"
        return $false
    }
}

# Optimize background apps
function Optimize-BackgroundApps {
    Write-Log "Optimizing background apps for gaming..."
    
    try {
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
        
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        # Disable global background app access (apps can still run when in use)
        Set-UserRegistryValue -Path $path -Name "GlobalUserDisabled" -Value 1 -Type DWord
        
        Write-Log "Background app access restricted" "SUCCESS"
        Write-Log "Note: Apps will still work when you're using them" "INFO"
        Write-Log "Note: You can re-enable specific apps in Settings -> Apps -> Installed apps" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to optimize background apps: $_" "ERROR"
        return $false
    }
}

# Optimize visual effects for performance
function Optimize-VisualEffects {
    Write-Log "Optimizing Windows visual effects for gaming performance..."
    
    try {
        # Set to custom (2) so we can control individual settings
        $path1 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        if (-not (Test-Path $path1)) {
            New-Item -Path $path1 -Force | Out-Null
        }
        Set-UserRegistryValue -Path $path1 -Name "VisualFXSetting" -Value 2 -Type DWord
        
        # Disable specific visual effects that impact gaming performance
        $path2 = "HKCU:\Control Panel\Desktop"
        
        # GPU-specific recommendations
        function Show-GPURecommendations {
            $gpuMans = Get-GPUManufacturers

            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "GPU-Specific Recommendations" "INFO"
            Write-Log "========================================" "INFO"

            if (-not $gpuMans -or $gpuMans.Count -eq 0) {
                Write-Log "Unknown GPU manufacturer - manual configuration recommended" "WARNING"
                return
            }

            foreach ($gpuMan in $gpuMans) {
                switch ($gpuMan) {
                    'NVIDIA' {
                        Write-Log "NVIDIA GPU detected - Additional optimizations to configure manually:" "INFO"
                        Write-Log "" "INFO"
                        Write-Log "NVIDIA Control Panel Settings:" "INFO"
                        Write-Log "  - Enable G-SYNC (if supported)" "INFO"
                        Write-Log "  - Low Latency Mode: On" "INFO"
                        Write-Log "  - Max Frame Rate: Set based on your monitor refresh rate" "INFO"
                        Write-Log "    (e.g., 120Hz = 116fps, 144Hz = 138fps, 165Hz = 157fps)" "INFO"
                        Write-Log "  - Power Management: Normal or Optimal Power" "INFO"
                        Write-Log "  - Vertical Sync: On (works with G-SYNC, not traditional V-Sync)" "INFO"
                        Write-Log "  - Shader Cache: 10GB minimum (100GB if 1TB+ storage)" "INFO"
                        Write-Log "" "INFO"
                        Write-Log "In-Game Settings:" "INFO"
                        Write-Log "  - Enable NVIDIA Reflex when available" "INFO"
                        Write-Log "  - Enable DLSS 3+ for massive performance gains" "INFO"
                        Write-Log "  - Use Borderless Fullscreen mode when possible" "INFO"
                        Write-Log "  - Disable in-game V-Sync (controlled by driver)" "INFO"
                    }
                    'AMD' {
                        Write-Log "AMD GPU detected - Additional optimizations to configure manually:" "INFO"
                        Write-Log "" "INFO"
                        Write-Log "AMD Adrenalin Software Settings:" "INFO"
                        Write-Log "  - Enable FreeSync (if supported)" "INFO"
                        Write-Log "  - Radeon Anti-Lag: Enabled" "INFO"
                        Write-Log "  - Radeon Boost: Enabled (if desired)" "INFO"
                        Write-Log "  - Radeon Chill: Disabled for competitive gaming" "INFO"
                        Write-Log "  - Wait for Vertical Refresh: Enhanced Sync" "INFO"
                        Write-Log "  - Frame Rate Target Control: Set based on monitor" "INFO"
                        Write-Log "" "INFO"
                        Write-Log "In-Game Settings:" "INFO"
                        Write-Log "  - Enable AMD FSR 3+ when available" "INFO"
                        Write-Log "  - Enable AMD Anti-Lag+ when available" "INFO"
                        Write-Log "  - Use Borderless Fullscreen mode when possible" "INFO"
                        Write-Log "  - Disable in-game V-Sync" "INFO"
                        Write-Log "" "INFO"
                        Write-Log "Reference: Guide mentions AMD optimization video at" "INFO"
                        Write-Log "  https://youtu.be/rY-lH6yDlK0" "INFO"
                    }
                    'Intel' {
                        Write-Log "Intel GPU detected" "INFO"
                        Write-Log "  - Ensure latest Intel Graphics drivers installed" "INFO"
                        Write-Log "  - Configure Intel Graphics Command Center for gaming" "INFO"
                    }
                    default {
                        Write-Log "Unknown GPU manufacturer - manual configuration recommended" "WARNING"
                    }
                }
            }
        }

        # Get all physical disks
        $physicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, @{
            Name = "SizeGB"
            Expression = { [math]::Round($_.Size / 1GB, 2) }
        }
        
        Write-Log "" "INFO"
        Write-Log "Physical Disks Detected:" "INFO"
        foreach ($disk in $physicalDisks) {
            $diskType = switch ($disk.MediaType) {
                "SSD" { "SSD" }
                "HDD" { "HDD" }
                "Unspecified" { "Unknown" }
                default { $disk.MediaType }
            }
            Write-Log "  - $($disk.FriendlyName) - $diskType - $($disk.SizeGB) GB" "INFO"
        }
        
        # Get all volumes with drive letters
        Write-Log "" "INFO"
        Write-Log "Drive Space Analysis:" "INFO"
        $volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | Sort-Object DriveLetter
        
        $ssdDrives = @()
        
        foreach ($volume in $volumes) {
            $sizeGB = [math]::Round($volume.Size / 1GB, 2)
            $freeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
            $usedGB = $sizeGB - $freeGB
            $percentFree = [math]::Round(($freeGB / $sizeGB) * 100, 1)
            
            # Determine if this is an SSD by checking the partition's disk
            $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $volume.DriveLetter } | Select-Object -First 1
            if ($partition) {
                $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
                $isSSD = $disk.MediaType -eq 'SSD' -or $disk.BusType -eq 'NVMe'
                
                if ($isSSD) {
                    $ssdDrives += [PSCustomObject]@{
                        DriveLetter = $volume.DriveLetter
                        SizeGB = $sizeGB
                        FreeGB = $freeGB
                        PercentFree = $percentFree
                        IsNVMe = $disk.BusType -eq 'NVMe'
                    }
                }
                
                $driveType = if ($disk.BusType -eq 'NVMe') { "[NVMe]" } elseif ($disk.MediaType -eq 'SSD') { "[SSD]" } else { "[HDD]" }
                $status = if ($percentFree -lt 15) { "[LOW]" } elseif ($percentFree -lt 25) { "[OK]" } else { "[GOOD]" }
                
                Write-Log "  $($volume.DriveLetter): $driveType - $($usedGB)GB used / $($freeGB)GB free ($percentFree%) - $status" "INFO"
            }
        }
        
        return $ssdDrives
    }
    catch {
        Write-Log "Failed to optimize visual effects: $_" "ERROR"
        return $false
    }
}

# Configure pagefile for gaming systems
function Optimize-PageFile {
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Pagefile Configuration for Gaming" "INFO"
    Write-Log "========================================" "INFO"
    
    try {
        # Get total physical RAM
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $totalRAMGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 0)
        
        Write-Log "Total System RAM: $totalRAMGB GB" "INFO"
        
        if ($totalRAMGB -ge 32) {
            Write-Log "[GOOD] System has 32GB+ RAM - Pagefile optimization not critical" "SUCCESS"
            Write-Log "Recommendation: You can disable pagefile or set to system-managed" "INFO"
            Write-Log "" "INFO"
            Write-Log "To disable pagefile manually:" "INFO"
            Write-Log "  1. System Properties -> Advanced -> Performance Settings" "INFO"
            Write-Log "  2. Advanced -> Virtual Memory -> Change" "INFO"
            Write-Log "  3. Uncheck 'Automatically manage paging file size'" "INFO"
            Write-Log "  4. Select 'No paging file' and click Set" "INFO"
            Write-Log "" "INFO"
            Write-Log "[NOTE] Some applications still require a pagefile" "WARNING"
            return $true
        }
        
        Write-Log "[ALERT] System has less than 32GB RAM ($totalRAMGB GB)" "WARNING"
        Write-Log "Pagefile configuration recommended for optimal gaming performance" "INFO"
        
        # Get current pagefile settings
        $pageFiles = Get-CimInstance -ClassName Win32_PageFileSetting
        
        if ($pageFiles) {
            Write-Log "" "INFO"
            Write-Log "Current Pagefile Configuration:" "INFO"
            foreach ($pf in $pageFiles) {
                Write-Log "  - $($pf.Name) - Initial: $($pf.InitialSize)MB, Max: $($pf.MaximumSize)MB" "INFO"
            }
        }
        
        # Get SSD drives from system disks (use Get-Disk which exposes DiskNumber reliably)
        $ssdDrives = @()
        try {
            $disks = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.MediaType -eq 'SSD' -or $_.BusType -eq 'NVMe' }
            foreach ($d in $disks) {
                if (-not $d -or $d.Number -eq $null) {
                    continue
                }
                $parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue
                foreach ($part in $parts) {
                    if ($part -and $part.DriveLetter) {
                        $volume = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
                        if ($volume -and $volume.Size -gt 0) {
                            $ssdDrives += [PSCustomObject]@{
                                DriveLetter = $part.DriveLetter
                                SizeGB = [math]::Round($volume.Size / 1GB, 2)
                                FreeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                                PercentFree = [math]::Round(($volume.SizeRemaining / $volume.Size) * 100, 1)
                                IsNVMe = $d.BusType -eq 'NVMe'
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Warning: Could not enumerate SSD drives - $_" "WARNING"
        }
        
        if ($ssdDrives.Count -eq 0) {
            Write-Log "[ALERT] No SSD drives detected - pagefile should remain on system drive" "WARNING"
            return $false
        }
        
        # Find best SSD for pagefile
        $bestSSD = $ssdDrives | Sort-Object -Property @{Expression={$_.IsNVMe}; Descending=$true}, FreeGB -Descending | Select-Object -First 1
        
        Write-Log "" "INFO"
        Write-Log "Recommended Pagefile Configuration:" "INFO"
        Write-Log "  - Target Drive: $($bestSSD.DriveLetter): $(if($bestSSD.IsNVMe){'[NVMe]'}else{'[SSD]'})" "INFO"
        Write-Log "  - Available Space: $($bestSSD.FreeGB) GB" "INFO"
        
        # Calculate recommended pagefile size
        # For gaming: 1.5x RAM or 16GB minimum, whichever is larger
        $recommendedSizeMB = [math]::Max(16384, [math]::Round($totalRAMGB * 1.5 * 1024))
        $recommendedSizeGB = [math]::Round($recommendedSizeMB / 1024, 1)
        
        Write-Log "  - Recommended Size: $recommendedSizeGB GB ($recommendedSizeMB MB)" "INFO"
        Write-Log "" "INFO"
        
        if ($bestSSD.FreeGB -lt ($recommendedSizeGB + 20)) {
            Write-Log "[ALERT] Insufficient space on $($bestSSD.DriveLetter): for recommended pagefile size" "WARNING"
            Write-Log "[ALERT] Need at least $($recommendedSizeGB + 20)GB free, have $($bestSSD.FreeGB)GB" "WARNING"
            return $false
        }
        
        Write-Log "[NOTE] MANUAL CONFIGURATION REQUIRED" "INFO"
        Write-Log "" "INFO"
        Write-Log "To optimize your pagefile for gaming:" "INFO"
        Write-Log "  1. Press Win + Pause/Break or right-click 'This PC' -> Properties" "INFO"
        Write-Log "  2. Click 'Advanced system settings'" "INFO"
        Write-Log "  3. Under Performance, click 'Settings'" "INFO"
        Write-Log "  4. Go to the 'Advanced' tab, click 'Change' under Virtual memory" "INFO"
        Write-Log "  5. Uncheck 'Automatically manage paging file size for all drives'" "INFO"
        Write-Log "  6. For C: drive - Select 'No paging file' and click 'Set'" "INFO"
        Write-Log "  7. Select $($bestSSD.DriveLetter): drive" "INFO"
        Write-Log "  8. Choose 'Custom size'" "INFO"
        Write-Log "  9. Set Initial size: $recommendedSizeMB MB" "INFO"
        Write-Log " 10. Set Maximum size: $recommendedSizeMB MB" "INFO"
        Write-Log " 11. Click 'Set', then 'OK'" "INFO"
        Write-Log " 12. Restart your computer" "INFO"
        Write-Log "" "INFO"
        Write-Log "Benefits of pagefile on SSD/NVMe:" "INFO"
        Write-Log "  [BENEFIT] Faster paging operations" "INFO"
        Write-Log "  [BENEFIT] Reduced system drive wear" "INFO"
        Write-Log "  [BENEFIT] Better multitasking while gaming" "INFO"
        Write-Log "  [BENEFIT] Prevents out-of-memory crashes" "INFO"
        Write-Log "" "INFO"
        Write-Log "[NOTE] Alternative: Upgrade to 32GB+ RAM to reduce pagefile dependency" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to analyze pagefile configuration: $_" "ERROR"
        return $false
    }
}

# GPU-specific recommendations
function Show-GPURecommendations {
    $gpuMans = Get-GPUManufacturers

    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "GPU-Specific Recommendations" "INFO"
    Write-Log "========================================" "INFO"

    if (-not $gpuMans -or $gpuMans.Count -eq 0) {
        Write-Log "Unknown GPU manufacturer - manual configuration recommended" "WARNING"
        return
    }

    foreach ($gpuMan in $gpuMans) {
        switch ($gpuMan) {
            'NVIDIA' {
                Write-Log "NVIDIA GPU detected - Additional optimizations to configure manually:" "INFO"
                Write-Log "" "INFO"
                Write-Log "NVIDIA Control Panel Settings:" "INFO"
                Write-Log "  - Enable G-SYNC (if supported)" "INFO"
                Write-Log "  - Low Latency Mode: On" "INFO"
                Write-Log "  - Max Frame Rate: Set based on your monitor refresh rate" "INFO"
                Write-Log "    (e.g., 120Hz = 116fps, 144Hz = 138fps, 165Hz = 157fps)" "INFO"
                Write-Log "  - Power Management: Normal or Optimal Power" "INFO"
                Write-Log "  - Vertical Sync: On (works with G-SYNC, not traditional V-Sync)" "INFO"
                Write-Log "  - Shader Cache: 10GB minimum (100GB if 1TB+ storage)" "INFO"
                Write-Log "" "INFO"
                Write-Log "In-Game Settings:" "INFO"
                Write-Log "  - Enable NVIDIA Reflex when available" "INFO"
                Write-Log "  - Enable DLSS 3+ for massive performance gains" "INFO"
                Write-Log "  - Use Borderless Fullscreen mode when possible" "INFO"
                Write-Log "  - Disable in-game V-Sync (controlled by driver)" "INFO"
            }
            'AMD' {
                Write-Log "AMD GPU detected - Additional optimizations to configure manually:" "INFO"
                Write-Log "" "INFO"
                Write-Log "AMD Adrenalin Software Settings:" "INFO"
                Write-Log "  - Enable FreeSync (if supported)" "INFO"
                Write-Log "  - Radeon Anti-Lag: Enabled" "INFO"
                Write-Log "  - Radeon Boost: Enabled (if desired)" "INFO"
                Write-Log "  - Radeon Chill: Disabled for competitive gaming" "INFO"
                Write-Log "  - Wait for Vertical Refresh: Enhanced Sync" "INFO"
                Write-Log "  - Frame Rate Target Control: Set based on monitor" "INFO"
                Write-Log "" "INFO"
                Write-Log "In-Game Settings:" "INFO"
                Write-Log "  - Enable AMD FSR 3+ when available" "INFO"
                Write-Log "  - Enable AMD Anti-Lag+ when available" "INFO"
                Write-Log "  - Use Borderless Fullscreen mode when possible" "INFO"
                Write-Log "  - Disable in-game V-Sync" "INFO"
                Write-Log "" "INFO"
                Write-Log "Reference: Guide mentions AMD optimization video at" "INFO"
                Write-Log "  https://youtu.be/rY-lH6yDlK0" "INFO"
            }
            'Intel' {
                Write-Log "Intel GPU detected" "INFO"
                Write-Log "  - Ensure latest Intel Graphics drivers installed" "INFO"
                Write-Log "  - Configure Intel Graphics Command Center for gaming" "INFO"
            }
            default {
                Write-Log "Unknown GPU manufacturer - manual configuration recommended" "WARNING"
            }
        }
    }

    Write-Log "========================================" "INFO"
}

# Test applied settings
function Test-OptimizationSettings {
    Write-Log "Testing applied optimization settings..." "INFO"
    Write-Log "========================================" "INFO"
    
    $tests = @(
        @{
            Setting = "Win32PrioritySeparation"
            Expected = 40
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue).Win32PrioritySeparation }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'Win32Priority' }
        }
        @{
            Setting = "PowerThrottlingOff"
            Expected = 1
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue).PowerThrottlingOff }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'PowerThrottling' }
        }
        @{
            Setting = "DWM OverlayMinFPS"
            Expected = 0
            Current = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayMinFPS" -ErrorAction SilentlyContinue).OverlayMinFPS }
            IsOptimized = { param($current) $current -eq 0 }
        }
        @{
            Setting = "NetworkThrottlingIndex"
            Expected = "0xFFFFFFFF"
            Current = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -ErrorAction SilentlyContinue).NetworkThrottlingIndex }
            FormatCurrent = { param($value) if ($null -ne $value) { "0x{0:X8}" -f [uint32]$value } else { "Not Set" } }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'NetworkThrottling' }
        }
        @{
            Setting = "SystemResponsiveness"
            Expected = 10
            Current = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -ErrorAction SilentlyContinue).SystemResponsiveness }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'SystemResponsiveness' }
        }
        @{
            Setting = "TimerResolution"
            Expected = 1
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -ErrorAction SilentlyContinue).GlobalTimerResolutionRequests }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'TimerResolution' }
        }
        @{
            Setting = "Game Mode"
            Expected = 1
            Current = { Get-UserRegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'GameMode' }
        }
        @{
            Setting = "Game DVR"
            Expected = 0
            Current = { Get-UserRegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'GameDVR' }
        }
        @{
            Setting = "Fullscreen Optimizations"
            Expected = 2
            Current = { Get-UserRegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" }
            IsOptimized = { param($current) Get-OptimizationStatus -Setting 'FullscreenOptimizations' }
        }
        @{
            Setting = "Mouse Input Latency (MouseDataQueueSize)"
            Expected = 16
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -ErrorAction SilentlyContinue).MouseDataQueueSize }
            IsOptimized = { param($current) $current -eq 16 }
        }
        @{
            Setting = "Keyboard Input Latency (KeyboardDataQueueSize)"
            Expected = 16
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -ErrorAction SilentlyContinue).KeyboardDataQueueSize }
            IsOptimized = { param($current) $current -eq 16 }
        }
        @{
            Setting = "Memory Management (DisablePagingExecutive)"
            Expected = 1
            Current = { (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -ErrorAction SilentlyContinue).DisablePagingExecutive }
            IsOptimized = { param($current) $current -eq 1 }
        }
        @{
            Setting = "Windows Update P2P (DODownloadMode)"
            Expected = 0
            Current = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode }
            IsOptimized = { param($current) $current -eq 0 }
        }
    )

    $results = foreach ($test in $tests) {
        $current = $null
        try { $current = & $test.Current } catch { $current = $null }
        $isOptimized = $false
        try { $isOptimized = & $test.IsOptimized $current } catch { $isOptimized = $false }
        $currentDisplay = if ($test.ContainsKey('FormatCurrent')) {
            & $test.FormatCurrent $current
        } else {
            $current
        }
        [PSCustomObject]@{
            Setting = $test.Setting
            Expected = $test.Expected
            Current = $currentDisplay
            Status = if ($isOptimized) { "[PASS]" } else { "[FAIL]" }
        }
    }
    
    # Display results
    $results | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }
    
    $failCount = ($results | Where-Object { $_.Status -like "*FAIL*" }).Count
    
    if ($failCount -eq 0) {
        Write-Log "All optimization settings verified successfully!" "SUCCESS"
        return $true
    } else {
        Write-Log "$failCount setting(s) failed verification" "WARNING"
        return $false
    }
}

# Benchmark CPU performance
function Invoke-CPUBenchmark {
    param([switch]$ReturnData)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "CPU Performance Benchmark" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Show related optimization settings status
    Write-Log "" "INFO"
    Write-Log "CPU-Related Optimization Settings:" "INFO"
    
    $powerThrottling = Get-OptimizationStatus -Setting 'PowerThrottling'
    $win32Priority = Get-OptimizationStatus -Setting 'Win32Priority'
    $systemResponsiveness = Get-OptimizationStatus -Setting 'SystemResponsiveness'
    $timerResolution = Get-OptimizationStatus -Setting 'TimerResolution'
    
    # Use INFO level to avoid duplicate WARNING stream output
    Write-Log "  Power Throttling Disabled: $(if ($powerThrottling) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "  Win32 Priority Optimized:  $(if ($win32Priority) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "  System Responsiveness:     $(if ($systemResponsiveness) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "  Timer Resolution Enhanced: $(if ($timerResolution) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "" "INFO"

    # Check for hybrid GPU systems and warn user before running benchmarks
    try {
        $hybridInfo = Test-HybridGPU
        if ($hybridInfo.IsHybrid) {
            Show-HybridGPUGuidance -HybridInfo $hybridInfo
        }
    }
    catch {
        Write-Log "Hybrid GPU check failed: $_" "WARNING"
    }
    
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        Write-Log "CPU: $($cpu.Name)" "INFO"
        Write-Log "Cores: $($cpu.NumberOfCores) | Logical Processors: $($cpu.NumberOfLogicalProcessors)" "INFO"
        
        # Capture idle clock speed using multiple methods for reliability
        $idleClockSpeed = $cpu.CurrentClockSpeed
        $perfCounterIdleSpeed = 0
        
        # Try to get idle speed from Performance Monitor (more accurate)
        try {
            $perfCounter = Get-Counter -Counter "\Processor Information(_Total)\Processor Frequency" -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue
            if ($perfCounter -and $perfCounter.CounterSamples[0].CookedValue -gt 0) {
                $perfCounterIdleSpeed = [math]::Round($perfCounter.CounterSamples[0].CookedValue, 0)
                if ($perfCounterIdleSpeed -gt $idleClockSpeed) {
                    $idleClockSpeed = $perfCounterIdleSpeed
                }
            }
        }
        catch { }
        
        # MaxClockSpeed from Win32_Processor is often the base, not boost.
        # We'll measure peak clock during the stress test.

        Write-Log "Current Speed (Idle): $idleClockSpeed MHz | Max Speed: (measuring during test)..." "INFO"
        Write-Log "" "INFO"
        
        # Test 1: Multi-threaded CPU load (stress all cores simultaneously)
        Write-Log "Running CPU benchmark (multi-threaded stress on all $($cpu.NumberOfLogicalProcessors) cores, ~20 seconds)..." "INFO"
        
        $testDuration = 20  # Duration in seconds
        $peakClockSpeed = 0
        # Telemetry log for per-interval data (multiple writes per second)
        $cpuLogTimestamp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format "yyyyMMdd-HHmmss-fff" }
        $resultsDir = $ResultsPath
        if (-not (Test-Path $resultsDir)) { New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null }
        $tag = if ($script:CurrentTelemetryTag) { $script:CurrentTelemetryTag } else { '' }
        $cpuTelemetryLog = Join-Path $resultsDir ("CPU-Load-Telemetry-$cpuLogTimestamp$($tag).csv")
        "timestamp_utc,elapsed_s,display_ops_per_sec,clock_mhz,iterations_est" | Set-Content -Path $cpuTelemetryLog -Encoding UTF8
        $currentIterations = 0
        $lastClockMHz = 0
        
        # Create a scriptblock for the CPU stress work - each runspace runs this independently
        $stressBlock = {
            param($Duration, $SyncHash, $ThreadId)
            $loopStart = [DateTime]::UtcNow
            $iterations = 0
            $lastUpdate = [DateTime]::UtcNow

            while (([DateTime]::UtcNow - $loopStart).TotalSeconds -lt $Duration) {
                for ($k = 0; $k -lt 10000; $k++) {
                    $null = [Math]::Sqrt($k * $k + 1)
                    $iterations++
                }

                if (([DateTime]::UtcNow - $lastUpdate).TotalMilliseconds -ge 100) {
                    $SyncHash["Thread_$ThreadId"] = $iterations
                    $lastUpdate = [DateTime]::UtcNow
                }
            }

            $SyncHash["Thread_${ThreadId}_Final"] = $iterations
        }

        # Initialize synchronized hashtable used by runspaces
        $syncHash = [hashtable]::Synchronized(@{})
        $syncHash['TotalIterations'] = 0
        # Create runspace pool with one runspace per logical processor
        $numCores = $cpu.NumberOfLogicalProcessors
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $numCores)
        $runspacePool.Open()
        
        # Start timer BEFORE launching runspaces to sync with their internal timers
        Write-Host "  CPU Load Test:   " -ForegroundColor Cyan -NoNewline
        $progressStart = Get-Date
        $loadStart = $progressStart
        $lastProgressUpdate = Get-Date
        $lastClockSample = Get-Date
        $clockSamples = @()
        $lastClockMHz = 0
        
        # Start stress test on all logical processors using runspaces
        $runspaces = @()
        for ($i = 0; $i -lt $numCores; $i++) {
            $syncHash["Thread_$i"] = 0
            $syncHash["Thread_${i}_Final"] = 0
            
            $powershell = [powershell]::Create().AddScript($stressBlock).AddArgument($testDuration).AddArgument($syncHash).AddArgument($i)
            $powershell.RunspacePool = $runspacePool
            
            $runspaces += [PSCustomObject]@{
                PowerShell = $powershell
                Handle = $powershell.BeginInvoke()
                ThreadId = $i
            }
        }
        
        # Scale expected max ops to 1,000,000 ops/sec maximum (full CPU saturation target)
        [double]$expectedMaxOps = 1000000
        [double]$baseClock = [double]($cpu.MaxClockSpeed)
        
        # Track iterations at 2-second mark to skip spin-up period in final calculation
        $iterationsAt2Seconds = 0
        $captured2SecondMark = $false
        
        # Monitor until all runspaces complete
        $allCompleted = $false
        while (-not $allCompleted) {
            $elapsed = [Math]::Max(((Get-Date) - $progressStart).TotalSeconds, 0.1)
            $remaining = [Math]::Max($testDuration - $elapsed, 0)
            
            # Check if all runspaces are done
            $allCompleted = $true
            foreach ($rs in $runspaces) {
                if (-not $rs.Handle.IsCompleted) {
                    $allCompleted = $false
                    break
                }
            }
            
            # Read current total iterations by summing per-thread counters using known thread indices
            $currentIterations = 0
            try {
                for ($ti = 0; $ti -lt $numCores; $ti++) {
                    $k = "Thread_$ti"
                    if ($syncHash.ContainsKey($k)) {
                        $v = $syncHash[$k]
                        if ($null -ne $v) { $currentIterations += [int]$v }
                    }
                }
            } catch {
                # In case of a transient concurrency issue, fall back to zero for this sample and continue
                $currentIterations = 0
            }
            
            # Capture iterations at 2-second mark to skip spin-up period
            if (-not $captured2SecondMark -and $elapsed -ge 2.0) {
                $iterationsAt2Seconds = $currentIterations
                $captured2SecondMark = $true
            }
            
            $displayOps = if ($elapsed -gt 0.1) { [int][math]::Round($currentIterations / $elapsed, 0) } else { 0 }
            
            # Bar scales to 100% at expected max
            $perfPercent = if ($expectedMaxOps -gt 0) { [Math]::Min(($displayOps / $expectedMaxOps) * 100, 100) } else { 0 }
            
            # Sample clock speed on main thread every 50ms
            if ((((Get-Date) - $lastClockSample).TotalMilliseconds) -ge 50) {
                try {
                    $perfCounter = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction SilentlyContinue
                    if ($perfCounter -and $perfCounter.CounterSamples[0].CookedValue -gt 0) {
                        [double]$perfValue = [double]($perfCounter.CounterSamples[0].CookedValue)
                        if ($baseClock -gt 0) {
                            $clockCalc = $baseClock * ($perfValue / 100)
                            if (-not [double]::IsNaN($clockCalc) -and -not [double]::IsInfinity($clockCalc)) {
                                $currentClock = [int][math]::Round($clockCalc, 0)
                                if ($currentClock -gt 0) {
                                    $clockSamples += $currentClock
                                    $lastClockMHz = $currentClock
                                }
                            }
                        }
                    }
                }
                catch { }
                $lastClockSample = Get-Date
            }
            
            # Update display every 200ms
            $timeSinceUpdate = ((Get-Date) - $lastProgressUpdate).TotalMilliseconds
            if ($timeSinceUpdate -ge 200) {
                $barLength = 40
                $filledLength = [Math]::Round($barLength * $perfPercent / 100)
                $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                $remainingInt = [int][Math]::Ceiling($remaining)
                $remainingDisplay = if ($remainingInt -lt 1) { "<1s" } else { "${remainingInt}s" }
                
                Write-ProgressLine "  CPU Load Test:   [$bar] $displayOps ops/sec | $remainingDisplay remaining" 'Cyan'
                $logLine = "{0},{1},{2},{3},{4}" -f [DateTime]::UtcNow.ToString("O"), [math]::Round($elapsed,2), $displayOps, $lastClockMHz, $currentIterations
                Add-Content -Path $cpuTelemetryLog -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
                $lastProgressUpdate = Get-Date
            }
            
            if (-not $allCompleted) {
                Start-Sleep -Milliseconds 50
            }
        }

        # Capture end of the actual load period
        $loadEnd = Get-Date
        
        # Collect final results from all runspaces
        $totalIterations = 0
        foreach ($rs in $runspaces) {
            try {
                $rs.PowerShell.EndInvoke($rs.Handle) | Out-Null
                $finalValue = $syncHash["Thread_$($rs.ThreadId)_Final"]
                if ($finalValue -gt 0) {
                    $totalIterations += $finalValue
                }
            }
            catch { }
            $rs.PowerShell.Dispose()
        }
        
        # Cleanup runspace pool
        $runspacePool.Close()
        $runspacePool.Dispose()
        
        # Use clock samples from main thread
        $peakClockSpeed = 0
        $avgClockSpeed = 0
        
        if ($clockSamples.Count -gt 0) {
            $peakClockSpeed = ($clockSamples | Measure-Object -Maximum).Maximum
            $avgClockSpeed = [math]::Round(($clockSamples | Measure-Object -Average).Average, 0)
        }
        
        # Determine the actual load clock speed (prefer peak over average)
        $loadClockSpeed = $idleClockSpeed
        if ($peakClockSpeed -gt $idleClockSpeed) {
            $loadClockSpeed = $peakClockSpeed
        } elseif ($avgClockSpeed -gt $idleClockSpeed) {
            $loadClockSpeed = $avgClockSpeed
        }
        
        # If we still don't have boost speeds, sample immediately after stress
        if ($loadClockSpeed -eq $idleClockSpeed) {
            Start-Sleep -Milliseconds 500
            $cpuNow = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cpuNow -and $cpuNow.CurrentClockSpeed -gt $idleClockSpeed) {
                $loadClockSpeed = $cpuNow.CurrentClockSpeed
            }
        }
        
        # Use only the actual load window to calculate throughput (exclude setup/cleanup overhead and 2-second spin-up)
        $loadDuration = [Math]::Max((($loadEnd - $loadStart).TotalSeconds), 0.1)
        
        # Skip first 2 seconds for final calculation to exclude spin-up period
        $adjustedIterations = if ($captured2SecondMark -and $iterationsAt2Seconds -gt 0) { $totalIterations - $iterationsAt2Seconds } else { $totalIterations }
        $adjustedDuration = if ($captured2SecondMark) { [Math]::Max($loadDuration - 2.0, 0.1) } else { $loadDuration }
        
        $cpuLoadOpsPerSecond = if ($adjustedIterations -gt 0 -and $adjustedDuration -gt 0) { [math]::Round($adjustedIterations / $adjustedDuration, 0) } else { 0 }
        
        # Display final completed progress bar with actual ops/sec
        $finalPerfPercent = if ($cpuLoadOpsPerSecond -gt 0 -and $expectedMaxOps -gt 0) { [Math]::Min(($cpuLoadOpsPerSecond / $expectedMaxOps) * 100, 100) } else { 0 }
        $barLength = 40
        $filledLength = [Math]::Round($barLength * $finalPerfPercent / 100)
        $finalBar = "#" * $filledLength + "." * ($barLength - $filledLength)
        Write-Host "`r  CPU Load Test:   [$finalBar] $cpuLoadOpsPerSecond ops/sec | Complete                    " -ForegroundColor Cyan
        
        # Report both idle and boost clock speeds
        $boostDifference = $loadClockSpeed - $idleClockSpeed
        $boostPercent = if ($idleClockSpeed -gt 0) { [math]::Round(($boostDifference / $idleClockSpeed) * 100, 1) } else { 0 }
        # Display results
        Write-Host "  Performance:       " -ForegroundColor Cyan -NoNewline
        Write-Host "$cpuLoadOpsPerSecond ops/sec " -ForegroundColor White -NoNewline
        Write-Host "($totalIterations iterations)" -ForegroundColor DarkGray
        Write-Host "  Clock Speed Idle:  " -ForegroundColor Cyan -NoNewline
        Write-Host "$idleClockSpeed MHz" -ForegroundColor White
        Write-Host "  Clock Speed Boost: " -ForegroundColor Cyan -NoNewline
        Write-Host "$loadClockSpeed MHz " -ForegroundColor White -NoNewline
        Write-Host "(+$boostDifference MHz, $boostPercent% increase)" -ForegroundColor Green
        
        Write-Log "CPU: $cpuLoadOpsPerSecond ops/sec | Clock: $idleClockSpeed MHz -> $loadClockSpeed MHz (+$boostPercent%)" "SUCCESS"
        
        # Test 2: Mathematical operations (multi-threaded pure compute intensive)
        $mathDuration = 10
        $expectedMaxMathOps = 700000  # Expected max math ops/sec per core
        $numCores = $cpu.NumberOfLogicalProcessors
        $mathSyncHash = [hashtable]::Synchronized(@{})
        for ($i = 0; $i -lt $numCores; $i++) { $mathSyncHash["Thread_$i"] = 0 }
        $mathBlock = {
            param($Duration, $SyncHash, $ThreadId)
            $loopStart = [DateTime]::UtcNow
            $mathOps = 0
            $pi = 3.14159265359
            $e = 2.71828182846
            $lastUpdate = [DateTime]::UtcNow
            while (([DateTime]::UtcNow - $loopStart).TotalSeconds -lt $Duration) {
                for ($i = 0; $i -lt 100000; $i++) {
                    $x = $i * 0.001
                    $result = [Math]::Pow($x, 2) + [Math]::Sqrt($x + 1)
                    $result = [Math]::Sin($result) * [Math]::Cos($result)
                    $result = [Math]::Log($result + 10) * $e / $pi
                    $mathOps++
                }
                if (([DateTime]::UtcNow - $lastUpdate).TotalMilliseconds -ge 100) {
                    $SyncHash["Thread_$ThreadId"] = $mathOps
                    $lastUpdate = [DateTime]::UtcNow
                }
            }
            $SyncHash["Thread_$ThreadId"] = $mathOps
        }
        $mathRunspacePool = [runspacefactory]::CreateRunspacePool(1, $numCores)
        $mathRunspacePool.Open()
        $mathRunspaces = @()
        for ($i = 0; $i -lt $numCores; $i++) {
            $powershell = [powershell]::Create().AddScript($mathBlock).AddArgument($mathDuration).AddArgument($mathSyncHash).AddArgument($i)
            $powershell.RunspacePool = $mathRunspacePool
            $mathRunspaces += [PSCustomObject]@{
                PowerShell = $powershell
                Handle = $powershell.BeginInvoke()
                ThreadId = $i
            }
        }
        $mathStartTime = [DateTime]::UtcNow
        $lastMathUpdate = [DateTime]::UtcNow
        while ($true) {
            $allCompleted = $true
            foreach ($rs in $mathRunspaces) {
                if (-not $rs.Handle.IsCompleted) {
                    $allCompleted = $false
                    break
                }
            }
            $elapsed = [Math]::Max(([DateTime]::UtcNow - $mathStartTime).TotalSeconds, 0.1)
            $remaining = [Math]::Max($mathDuration - $elapsed, 0)
            $timeSinceUpdate = ([DateTime]::UtcNow - $lastMathUpdate).TotalMilliseconds
            if ($timeSinceUpdate -ge 200) {
                $currentOpsPerSec = 0
                for ($i = 0; $i -lt $numCores; $i++) {
                    $val = $mathSyncHash["Thread_$i"]
                    $currentOpsPerSec += $val / $elapsed
                }
                $currentOpsPerSec = [Math]::Round($currentOpsPerSec, 0)
                $perfPercent = [Math]::Min(($currentOpsPerSec / ($expectedMaxMathOps * $numCores)) * 100, 100)
                $barLength = 40
                $filledLength = [Math]::Round($barLength * $perfPercent / 100)
                $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int]$remaining)s" }
                Write-ProgressLine "  Math Load Test:  [$bar] $currentOpsPerSec ops/sec | $remainingDisplay remaining" 'Cyan'
                $lastMathUpdate = [DateTime]::UtcNow
            }
            if ($allCompleted -or $elapsed -ge $mathDuration) { break }
            Start-Sleep -Milliseconds 50
        }
        $mathEndTime = [DateTime]::UtcNow
        $mathOps = 0
        for ($i = 0; $i -lt $numCores; $i++) {
            $mathOps += $mathSyncHash["Thread_$i"]
        }
        foreach ($rs in $mathRunspaces) { try { $rs.PowerShell.EndInvoke($rs.Handle) | Out-Null } catch {} $rs.PowerShell.Dispose() }
        $mathRunspacePool.Close()
        $mathRunspacePool.Dispose()
        $mathDurationActual = ($mathEndTime - $mathStartTime).TotalSeconds
        $mathOpsPerSecond = [math]::Round($mathOps / $mathDurationActual, 0)
        $finalMathPercent = [Math]::Min(($mathOpsPerSecond / ($expectedMaxMathOps * $numCores)) * 100, 100)
        $barLength = 40
        $filledLength = [Math]::Round($barLength * $finalMathPercent / 100)
        $finalMathBar = "#" * $filledLength + "." * ($barLength - $filledLength)
        Write-Host "`r  Math Load Test:  [$finalMathBar] $mathOpsPerSecond ops/sec | Complete        " -ForegroundColor Cyan
        Write-Host "  Math Operations:   " -ForegroundColor Cyan -NoNewline
        Write-Host "$mathOpsPerSecond ops/sec" -ForegroundColor White
        Write-Log "Math: $mathOpsPerSecond ops/sec" "SUCCESS"
        
        # Test 3: 2D Rendering (GDI+ CPU rendering test)
        Write-Host "" -ForegroundColor Cyan
        
        try {
            Add-Type -AssemblyName System.Drawing
            Add-Type -AssemblyName System.Windows.Forms
            
            $renderDuration = 8  # Reduced from 10s for faster benchmarks
            $renderStartTime = Get-Date
            $width = 1920
            $height = 1080
            $bitmap = New-Object System.Drawing.Bitmap($width, $height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $random = New-Object System.Random
            $frameCount = 0
            $lastRenderUpdate = Get-Date
            
            # Render frames for 10 seconds with real-time FPS display
            $expectedMaxFPS = 200  # Expected max FPS for scaling
            while (((Get-Date) - $renderStartTime).TotalSeconds -lt $renderDuration) {
                $graphics.Clear([System.Drawing.Color]::Black)
                
                # Draw 100 shapes per frame
                for ($i = 0; $i -lt 100; $i++) {
                    $x = $random.Next(0, $width)
                    $y = $random.Next(0, $height)
                    $size = $random.Next(10, 50)
                    $color = [System.Drawing.Color]::FromArgb($random.Next(0, 255), $random.Next(0, 255), $random.Next(0, 255))
                    $brush = New-Object System.Drawing.SolidBrush($color)
                    $graphics.FillEllipse($brush, $x, $y, $size, $size)
                    $brush.Dispose()
                }

                # Add a small CPU-only workload per frame to ensure measurable utilization
                for ($c = 0; $c -lt 20000; $c++) { $null = [Math]::Sqrt($c + $frameCount) }
                
                $graphics.Flush([System.Drawing.Drawing2D.FlushIntention]::Sync)
                $frameCount++
                
                # Update progress display every 200ms with current FPS
                $timeSinceUpdate = ((Get-Date) - $lastRenderUpdate).TotalMilliseconds
                if ($timeSinceUpdate -ge 200) {
                    $elapsed = [Math]::Max(((Get-Date) - $renderStartTime).TotalSeconds, 0.1)
                    $remaining = [Math]::Max($renderDuration - $elapsed, 0)
                    $currentFPS = [Math]::Round($frameCount / $elapsed, 1)
                    $perfPercent = [Math]::Min(($currentFPS / $expectedMaxFPS) * 100, 100)
                    
                    $barLength = 40
                    $filledLength = [Math]::Round($barLength * $perfPercent / 100)
                    $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                    $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int]$remaining)s" }
                    
                    Write-ProgressLine "  2D Render Test:  [$bar] $currentFPS FPS | $remainingDisplay remaining" 'Cyan'
                    $lastRenderUpdate = Get-Date
                }
            }
            
            $graphics.Dispose()
            $bitmap.Dispose()
            
            $renderEndTime = Get-Date
            $renderDurationActual = ($renderEndTime - $renderStartTime).TotalSeconds
            $renderFPS = [math]::Round($frameCount / $renderDurationActual, 1)
            
            $finalRenderPercent = [Math]::Min(($renderFPS / $expectedMaxFPS) * 100, 100)
            $barLength = 40
            $filledLength = [Math]::Round($barLength * $finalRenderPercent / 100)
            $finalRenderBar = "#" * $filledLength + "." * ($barLength - $filledLength)
            Write-Host "`r  2D Render Test:  [$finalRenderBar] $renderFPS FPS | Complete        " -ForegroundColor Cyan
            
            Write-Host "  2D Render (CPU):   " -ForegroundColor Cyan -NoNewline
            Write-Host "$renderFPS FPS" -ForegroundColor White
            Write-Log "2D Render: $renderFPS FPS" "SUCCESS"
        }
        catch {
            Write-Log "2D rendering test skipped: $_" "WARNING"
            $renderFPS = 0
        }
        
        # Test 4: Advanced CPU Graphics Rendering (Heavy Draw Operations)
        Write-Host "" -ForegroundColor Cyan
        
        try {
            Add-Type -AssemblyName System.Drawing
            $advancedDuration = 10  # Reduced from 15s for faster benchmarks
            $advancedBitmap = New-Object System.Drawing.Bitmap(3840, 2160)  # 4K bitmap for heavier workload
            $advancedGraphics = [System.Drawing.Graphics]::FromImage($advancedBitmap)
            $advancedGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $advancedGraphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            
            $advancedRenderStartTime = Get-Date
            $advancedFrameCount = 0
            $lastAdvancedUpdate = Get-Date
            
            while (((Get-Date) - $advancedRenderStartTime).TotalSeconds -lt $advancedDuration) {
                # Aggressive drawing: multiple layers with complex shapes
                for ($layer = 0; $layer -lt 5; $layer++) {
                    for ($i = 0; $i -lt 2000; $i++) {  # 2000 objects x 5 layers = 10K objects per frame
                        $x = ($i * 23 + $layer * 100) % 3840
                        $y = ($i * 41 + $layer * 200) % 2160
                        $size = (($i % 150) + 30)
                        $color = [System.Drawing.Color]::FromArgb(
                            ($i * $layer * 7) % 256,
                            ($i * $layer * 11) % 256,
                            ($i * $layer * 13) % 256
                        )
                        $brush = New-Object System.Drawing.SolidBrush($color)
                        $advancedGraphics.FillEllipse($brush, $x, $y, $size, $size)
                        $advancedGraphics.FillRectangle($brush, ($x + 20) % 3840, ($y + 20) % 2160, ($size - 10), ($size - 10))
                        $brush.Dispose()
                    }
                }
                
                # Draw text layers (CPU-intensive)
                $font = New-Object System.Drawing.Font("Arial", 64, [System.Drawing.FontStyle]::Bold)
                $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
                $advancedGraphics.DrawString("CPU GRAPHICS TEST - FRAME $advancedFrameCount", $font, $brush, 100, 100)
                $advancedGraphics.DrawString("Heavy Draw Load Pattern", $font, $brush, 100, 300)
                $font.Dispose()
                $brush.Dispose()
                
                # Flush to ensure rendering happens
                $advancedGraphics.Flush([System.Drawing.Drawing2D.FlushIntention]::Sync)
                $advancedFrameCount++
                
                # Update progress display every 300ms with real-time FPS
                $timeSinceUpdate = ((Get-Date) - $lastAdvancedUpdate).TotalMilliseconds
                if ($timeSinceUpdate -ge 300) {
                    $elapsed = [Math]::Max(((Get-Date) - $advancedRenderStartTime).TotalSeconds, 0.1)
                    $remaining = [Math]::Max($advancedDuration - $elapsed, 0)
                    $currentFPS = [Math]::Round($advancedFrameCount / $elapsed, 1)
                    $expectedMaxFPS = 50  # Expected max FPS for 4K heavy load
                    $perfPercent = [Math]::Min(($currentFPS / $expectedMaxFPS) * 100, 100)
                    
                    $barLength = 40
                    $filledLength = [Math]::Round($barLength * $perfPercent / 100)
                    $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                    $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int]$remaining)s" }
                    
                    Write-ProgressLine "  4K Graphics:     [$bar] $currentFPS FPS | $remainingDisplay remaining" 'Cyan'
                    $lastAdvancedUpdate = Get-Date
                }
            }
            
            $advancedGraphics.Dispose()
            $advancedBitmap.Dispose()
            
            $advancedRenderEndTime = Get-Date
            $advancedRenderDuration = ($advancedRenderEndTime - $advancedRenderStartTime).TotalSeconds
            $advancedRenderFPS = [math]::Round($advancedFrameCount / $advancedRenderDuration, 1)
            
            $finalAdvancedPercent = [Math]::Min(($advancedRenderFPS / $expectedMaxFPS) * 100, 100)
            $barLength = 40
            $filledLength = [Math]::Round($barLength * $finalAdvancedPercent / 100)
            $finalAdvancedBar = "#" * $filledLength + "." * ($barLength - $filledLength)
            Write-Host "`r  4K Graphics:     [$finalAdvancedBar] $advancedRenderFPS FPS | Complete        " -ForegroundColor Cyan
            
            Write-Host "  4K Graphics (CPU): " -ForegroundColor Cyan -NoNewline
            Write-Host "$advancedRenderFPS FPS " -ForegroundColor White -NoNewline
            Write-Host "(CPU-only, no GPU)" -ForegroundColor DarkGray
            Write-Log "4K Graphics (CPU-only software rendering): $advancedRenderFPS FPS" "SUCCESS"
        }
        catch {
            Write-Log "Advanced graphics rendering test skipped: $_" "WARNING"
            $advancedRenderFPS = 0
        }
        
        # Use CPU Load test ops/sec as the hash/prime proxy so the summary is populated
        $primesPerSecond = $cpuLoadOpsPerSecond

        # Rating
        Write-Log "" "INFO"
        $rating = ""
        # NOTE: 4K graphics render test is CPU-only (no GPU) and unrealistically harsh, so we primarily rate on CPU ops/sec and math performance
        # For reference: Ryzen 5 5600X = ~270K primes/sec, ~1.2M math ops/sec | Ryzen 9 5900X = ~450K primes/sec, ~2M math ops/sec
        if ($primesPerSecond -gt 200000 -and $mathOpsPerSecond -gt 1000000) {
            $rating = "EXCELLENT"
            Write-Log "[EXCELLENT] CPU performance is excellent for gaming" "SUCCESS"
        } elseif ($primesPerSecond -gt 100000 -and $mathOpsPerSecond -gt 500000) {
            $rating = "GOOD"
            Write-Log "[GOOD] CPU performance is good for gaming" "SUCCESS"
        } elseif ($primesPerSecond -gt 50000 -and $mathOpsPerSecond -gt 250000) {
            $rating = "FAIR"
            Write-Log "[FAIR] CPU performance is adequate for gaming" "INFO"
        } else {
            $rating = "WARNING"
            Write-Log "[WARNING] CPU performance may be limiting gaming performance" "WARNING"
        }
        
        if ($ReturnData) {
            return @{
                CPUName = $cpu.Name
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
                CurrentClockSpeed = $idleClockSpeed
                MaxClockSpeed = $cpu.MaxClockSpeed
                ClockSpeedUnderLoad = $loadClockSpeed
                HashesPerSecond = $primesPerSecond
                PrimesPerSecond = $primesPerSecond
                MathOpsPerSecond = $mathOpsPerSecond
                RenderFPS2D = $renderFPS
                RenderFPS4KAdvanced = $advancedRenderFPS
                PowerThrottlingOptimized = $powerThrottling
                Win32PriorityOptimized = $win32Priority
                SystemResponsivenessOptimized = $systemResponsiveness
                TimerResolutionOptimized = $timerResolution
                Rating = $rating
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to benchmark CPU: $_" "ERROR"
        return $false
    }
}

# Benchmark disk performance
function Invoke-DiskBenchmark {
    param([switch]$ReturnData)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Disk Performance Benchmark" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        # Get system drive
        $systemDrive = $env:SystemDrive
        Write-Log "Testing drive: $systemDrive" "INFO"
        
        # Get disk info
        $null = Get-Volume | Where-Object { $_.DriveLetter -eq $systemDrive.TrimEnd(':') } | Select-Object -First 1
        $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $systemDrive.TrimEnd(':') } | Select-Object -First 1
        
        if ($partition) {
            $disk = Get-PhysicalDisk -DeviceNumber $partition.DiskNumber
            Write-Log "Disk: $($disk.FriendlyName)" "INFO"
            Write-Log "Type: $($disk.MediaType) | Bus: $($disk.BusType)" "INFO"
            Write-Log "Size: $([math]::Round($disk.Size / 1GB, 2)) GB" "INFO"
        }
        
        Write-Log "" "INFO"
        
        # Test file path - use temp directory to avoid root directory overhead
        $testDir = "$systemDrive\temp"
        if (-not (Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        $testFile = "$testDir\gaming-perf-test.tmp"
        Write-Log "Test file location: $testFile" "INFO"
        $testSizeMB = 256
        $testSizeBytes = $testSizeMB * 1MB
        
        # Write test with live throughput display
        Write-Log "Running sequential write test ($testSizeMB MB)..." "INFO"
        $writeChunkSize = 4MB
        $writeBuffer = New-Object byte[] $writeChunkSize
        (New-Object Random).NextBytes($writeBuffer)
        $bytesWritten = 0
        $writeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastUpdate = Get-Date
        $baseMax = if ($disk.BusType -eq 'NVMe') { 7000 } elseif ($disk.MediaType -eq 'SSD') { 600 } else { 200 }
        Write-Host "  Disk Write:    " -ForegroundColor Cyan -NoNewline
        
        $fsWrite = [System.IO.File]::Open($testFile, [System.IO.FileMode]::Create)
        try {
            while ($bytesWritten -lt $testSizeBytes) {
                $remaining = $testSizeBytes - $bytesWritten
                $currentChunk = [Math]::Min($writeChunkSize, $remaining)
                $fsWrite.Write($writeBuffer, 0, $currentChunk)
                $bytesWritten += $currentChunk
                
                $elapsed = [Math]::Max(0.0001, $writeStopwatch.Elapsed.TotalSeconds)
                $currentMBps = [math]::Round(($bytesWritten / 1MB) / $elapsed, 0)
                $speedPercent = [Math]::Min([Math]::Round(($currentMBps / $baseMax) * 100, 0), 100)
                $barLength = 40
                $filledLength = [Math]::Round($barLength * $speedPercent / 100)
                $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                $remainingMB = ($testSizeBytes - $bytesWritten) / 1MB
                $remainingSeconds = if ($currentMBps -gt 0) { $remainingMB / $currentMBps } else { 0 }
                $remainingDisplay = if ($remainingSeconds -lt 1) { "<1s" } else { "$([int][Math]::Ceiling($remainingSeconds))s" }
                
                # Update every ~150ms
                if ((((Get-Date) - $lastUpdate).TotalMilliseconds) -ge 150) {
                    Write-ProgressLine "  Disk Write:    [$bar] $currentMBps MB/s | $remainingDisplay remaining" 'Cyan'
                    $lastUpdate = Get-Date
                }
            }
        }
        finally {
            $fsWrite.Close()
        }
        $writeStopwatch.Stop()
        
        # Display final write result with completed bar
        $writeDuration = $writeStopwatch.Elapsed.TotalSeconds
        if ($writeDuration -gt 0) {
            $writeMBps = [math]::Round($testSizeMB / $writeDuration, 2)
            $finalWritePercent = [Math]::Min([Math]::Round(($writeMBps / $baseMax) * 100, 0), 100)
            $finalWriteBar = "#" * [Math]::Round(40 * $finalWritePercent / 100) + "." * (40 - [Math]::Round(40 * $finalWritePercent / 100))
            Write-Host "`r  Disk Write:    [$finalWriteBar] $writeMBps MB/s | Complete        " -ForegroundColor Cyan
            Write-Log "Write Speed: $writeMBps MB/s (completed in $([math]::Round($writeDuration, 2))s)" "SUCCESS"
            
            # Visual performance bar for write - adjust max based on actual performance
            $baseMax = if ($disk.BusType -eq 'NVMe') { 7000 } elseif ($disk.MediaType -eq 'SSD') { 600 } else { 200 }
            $maxWrite = if ($writeMBps -gt $baseMax) { [math]::Ceiling($writeMBps * 1.1) } else { $baseMax }
            $writePercent = [math]::Min([math]::Round(($writeMBps / $maxWrite) * 100, 0), 100)
            $writeBarLength = [math]::Round($writePercent / 2, 0)
            $writeBar = "#" * $writeBarLength + "." * (50 - $writeBarLength)
            
            $diskTypeLabel = if ($disk.BusType -eq 'NVMe') { 
                "NVMe PCIe" 
            } elseif ($disk.MediaType -eq 'SSD') { 
                "SATA SSD" 
            } else { 
                "HDD" 
            }
            
            # Performance rating
            $perfRating = if ($disk.BusType -eq 'NVMe') {
                if ($writeMBps -gt 4000) { "EXCELLENT" }
                elseif ($writeMBps -gt 2500) { "GOOD" }
                elseif ($writeMBps -gt 1200) { "FAIR" }
                else { "SLOW" }
            } elseif ($disk.MediaType -eq 'SSD') {
                if ($writeMBps -gt 450) { "EXCELLENT" }
                elseif ($writeMBps -gt 250) { "GOOD" }
                elseif ($writeMBps -gt 120) { "FAIR" }
                else { "SLOW" }
            } else {
                if ($writeMBps -gt 130) { "GOOD" }
                elseif ($writeMBps -gt 80) { "FAIR" }
                else { "SLOW" }
            }
            
            Write-Host "  Performance: [$writeBar] $writePercent% " -ForegroundColor Cyan -NoNewline
            Write-Host "[$perfRating for $diskTypeLabel]" -ForegroundColor $(if ($perfRating -eq "EXCELLENT" -or $perfRating -eq "GOOD") { "Green" } elseif ($perfRating -eq "FAIR") { "Yellow" } else { "Red" })
        }
        
        # Read test with live throughput display
        Write-Log "" "INFO"
        Write-Log "Running sequential read test ($testSizeMB MB)..." "INFO"
        
        $readChunkSize = 4MB
        $readBuffer = New-Object byte[] $readChunkSize
        $bytesRead = 0
        $readStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastReadUpdate = Get-Date
        Write-Host "  Disk Read:     " -ForegroundColor Cyan -NoNewline
        
        $fsRead = [System.IO.File]::Open($testFile, [System.IO.FileMode]::Open)
        try {
            while ($bytesRead -lt $testSizeBytes) {
                $remaining = $testSizeBytes - $bytesRead
                $currentChunk = [Math]::Min($readChunkSize, $remaining)
                $null = $fsRead.Read($readBuffer, 0, $currentChunk)
                $bytesRead += $currentChunk
                
                $elapsed = [Math]::Max(0.0001, $readStopwatch.Elapsed.TotalSeconds)
                $currentMBps = [math]::Round(($bytesRead / 1MB) / $elapsed, 0)
                $baseMaxRead = if ($disk.BusType -eq 'NVMe') { 7000 } elseif ($disk.MediaType -eq 'SSD') { 600 } else { 200 }
                $speedPercent = [Math]::Min([Math]::Round(($currentMBps / $baseMaxRead) * 100, 0), 100)
                $barLength = 40
                $filledLength = [Math]::Round($barLength * $speedPercent / 100)
                $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                $remainingMB = ($testSizeBytes - $bytesRead) / 1MB
                $remainingSeconds = if ($currentMBps -gt 0) { $remainingMB / $currentMBps } else { 0 }
                $remainingDisplay = if ($remainingSeconds -lt 1) { "<1s" } else { "$([int][Math]::Ceiling($remainingSeconds))s" }
                
                if ((((Get-Date) - $lastReadUpdate).TotalMilliseconds) -ge 150) {
                    Write-ProgressLine "  Disk Read:     [$bar] $currentMBps MB/s | $remainingDisplay remaining" 'Cyan'
                    $lastReadUpdate = Get-Date
                }
            }
        }
        finally {
            $fsRead.Close()
        }
        $readStopwatch.Stop()
        
        # Display final read result with completed bar
        $readDuration = $readStopwatch.Elapsed.TotalSeconds
        if ($readDuration -gt 0) {
            $readMBps = [math]::Round($testSizeMB / $readDuration, 2)
            $finalReadPercent = [Math]::Min([Math]::Round(($readMBps / $baseMaxRead) * 100, 0), 100)
            $finalReadBar = "#" * [Math]::Round(40 * $finalReadPercent / 100) + "." * (40 - [Math]::Round(40 * $finalReadPercent / 100))
            Write-Host "`r  Disk Read:     [$finalReadBar] $readMBps MB/s | Complete        " -ForegroundColor Cyan
            Write-Log "Read Speed: $readMBps MB/s (completed in $([math]::Round($readDuration, 2))s)" "SUCCESS"
            
            # Visual performance bar for read - adjust max based on actual performance
            # Determine expected max based on drive type
            $baseMax = if ($disk.BusType -eq 'NVMe') { 7000 } elseif ($disk.MediaType -eq 'SSD') { 600 } else { 200 }
            # If actual speed exceeds base max, adjust to 110% of actual speed for proper display
            $maxRead = if ($readMBps -gt $baseMax) { [math]::Ceiling($readMBps * 1.1) } else { $baseMax }
            $readPercent = [math]::Min([math]::Round(($readMBps / $maxRead) * 100, 0), 100)
            $readBarLength = [math]::Round($readPercent / 2, 0)
            $readBar = "#" * $readBarLength + "." * (50 - $readBarLength)
            
            # Determine actual drive type for display
            $diskTypeLabel = if ($disk.BusType -eq 'NVMe') { 
                "NVMe PCIe" 
            } elseif ($disk.MediaType -eq 'SSD') { 
                "SATA SSD" 
            } else { 
                "HDD" 
            }
            
            # Performance rating
            $perfRating = if ($disk.BusType -eq 'NVMe') {
                if ($readMBps -gt 5000) { "EXCELLENT" }
                elseif ($readMBps -gt 3000) { "GOOD" }
                elseif ($readMBps -gt 1500) { "FAIR" }
                else { "SLOW" }
            } elseif ($disk.MediaType -eq 'SSD') {
                if ($readMBps -gt 500) { "EXCELLENT" }
                elseif ($readMBps -gt 300) { "GOOD" }
                elseif ($readMBps -gt 150) { "FAIR" }
                else { "SLOW" }
            } else {
                if ($readMBps -gt 150) { "GOOD" }
                elseif ($readMBps -gt 100) { "FAIR" }
                else { "SLOW" }
            }
            
            Write-Host "  Performance: [$readBar] $readPercent% " -ForegroundColor Cyan -NoNewline
            Write-Host "[$perfRating for $diskTypeLabel]" -ForegroundColor $(if ($perfRating -eq "EXCELLENT" -or $perfRating -eq "GOOD") { "Green" } elseif ($perfRating -eq "FAIR") { "Yellow" } else { "Red" })
        }
        
        # Random 4K read/write test (critical for gaming load times and texture streaming)
        Write-Log "" "INFO"
        Write-Log "Running random 4K read/write test (128 MB, gaming workload simulation)..." "INFO"
        
        # Use larger file size (128MB) to avoid full caching and get more realistic results
        $random4KSize = 128MB
        $blockSize = 4KB
        # Use temp directory for test file to avoid root directory overhead
        $testDir = "$systemDrive\temp"
        if (-not (Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        $random4KFile = "$testDir\random4k_test.bin"
        Write-Log "4K test file location: $random4KFile" "INFO"
        $random = New-Object System.Random
        
        # Create test file for random access
        $create4KBuffer = New-Object byte[] $random4KSize
        $random.NextBytes($create4KBuffer)
        [System.IO.File]::WriteAllBytes($random4KFile, $create4KBuffer)
        
        # Random 4K Write Test
        Write-Host "  4K Random Write: " -ForegroundColor Cyan -NoNewline
        $random4KWriteOps = 0
        $random4KWriteStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $targetDuration = 3  # 3 seconds test
        
        $fs4KWrite = [System.IO.File]::Open($random4KFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $writeBlock = New-Object byte[] $blockSize
            $lastUpdate = Get-Date
            
            while ($random4KWriteStopwatch.Elapsed.TotalSeconds -lt $targetDuration) {
                # Random seek position (aligned to 4K)
                $randomPos = [long]($random.Next(0, [int]($random4KSize / $blockSize))) * $blockSize
                $fs4KWrite.Seek($randomPos, [System.IO.SeekOrigin]::Begin) | Out-Null
                $random.NextBytes($writeBlock)
                $fs4KWrite.Write($writeBlock, 0, $blockSize)
                $random4KWriteOps++
                
                # Update display every 200ms
                if ((((Get-Date) - $lastUpdate).TotalMilliseconds) -ge 200) {
                    $elapsed = [Math]::Max(0.01, $random4KWriteStopwatch.Elapsed.TotalSeconds)
                    $iops = [math]::Round($random4KWriteOps / $elapsed, 0)
                    $remaining = [Math]::Max(0, $targetDuration - $elapsed)
                    $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int][Math]::Ceiling($remaining))s" }
                    Write-ProgressLine "  4K Random Write: $iops IOPS | $remainingDisplay remaining" 'Cyan'
                    $lastUpdate = Get-Date
                }
            }
            $fs4KWrite.Flush($true)
        }
        finally {
            $fs4KWrite.Close()
        }
        $random4KWriteStopwatch.Stop()
        
        $random4KWriteIOPS = [math]::Round($random4KWriteOps / $random4KWriteStopwatch.Elapsed.TotalSeconds, 0)
        $random4KWriteMBps = [math]::Round(($random4KWriteIOPS * $blockSize) / 1MB, 1)
        Write-Host "`r  4K Random Write: $random4KWriteIOPS IOPS ($random4KWriteMBps MB/s) | Complete        " -ForegroundColor Cyan
        Write-Log "4K Random Write: $random4KWriteIOPS IOPS ($random4KWriteMBps MB/s)" "SUCCESS"
        
        # Random 4K Read Test
        Write-Host "  4K Random Read:  " -ForegroundColor Cyan -NoNewline
        $random4KReadOps = 0
        $random4KReadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        $fs4KRead = [System.IO.File]::Open($random4KFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $readBlock = New-Object byte[] $blockSize
            $lastUpdate = Get-Date
            
            while ($random4KReadStopwatch.Elapsed.TotalSeconds -lt $targetDuration) {
                # Random seek position (aligned to 4K)
                $randomPos = [long]($random.Next(0, [int]($random4KSize / $blockSize))) * $blockSize
                $fs4KRead.Seek($randomPos, [System.IO.SeekOrigin]::Begin) | Out-Null
                $null = $fs4KRead.Read($readBlock, 0, $blockSize)
                $random4KReadOps++
                
                # Update display every 200ms
                if ((((Get-Date) - $lastUpdate).TotalMilliseconds) -ge 200) {
                    $elapsed = [Math]::Max(0.01, $random4KReadStopwatch.Elapsed.TotalSeconds)
                    $iops = [math]::Round($random4KReadOps / $elapsed, 0)
                    $remaining = [Math]::Max(0, $targetDuration - $elapsed)
                    $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int][Math]::Ceiling($remaining))s" }
                    Write-ProgressLine "  4K Random Read:  $iops IOPS | $remainingDisplay remaining" 'Cyan'
                    $lastUpdate = Get-Date
                }
            }
        }
        finally {
            $fs4KRead.Close()
        }
        $random4KReadStopwatch.Stop()
        
        $random4KReadIOPS = [math]::Round($random4KReadOps / $random4KReadStopwatch.Elapsed.TotalSeconds, 0)
        $random4KReadMBps = [math]::Round(($random4KReadIOPS * $blockSize) / 1MB, 1)
        Write-Host "`r  4K Random Read:  $random4KReadIOPS IOPS ($random4KReadMBps MB/s) | Complete        " -ForegroundColor Cyan
        Write-Log "4K Random Read: $random4KReadIOPS IOPS ($random4KReadMBps MB/s)" "SUCCESS"
        
        # Performance assessment for 4K random ops (critical for gaming)
        Write-Log "" "INFO"
        $random4KRating = if ($disk.BusType -eq 'NVMe') {
            if ($random4KReadIOPS -gt 400000) { "EXCELLENT" }
            elseif ($random4KReadIOPS -gt 200000) { "GOOD" }
            elseif ($random4KReadIOPS -gt 100000) { "FAIR" }
            else { "SLOW" }
        } elseif ($disk.MediaType -eq 'SSD') {
            if ($random4KReadIOPS -gt 80000) { "EXCELLENT" }
            elseif ($random4KReadIOPS -gt 40000) { "GOOD" }
            elseif ($random4KReadIOPS -gt 20000) { "FAIR" }
            else { "SLOW" }
        } else {
            if ($random4KReadIOPS -gt 100) { "FAIR" }
            else { "SLOW" }
        }
        
        if ($random4KRating -eq "EXCELLENT" -or $random4KRating -eq "GOOD") {
            Write-Log "[$random4KRating] 4K random performance is excellent for fast game loading and texture streaming" "SUCCESS"
        } elseif ($random4KRating -eq "FAIR") {
            Write-Log "[$random4KRating] 4K random performance is adequate but could be better" "INFO"
        } else {
            Write-Log "[$random4KRating] 4K random performance is slow - may cause stuttering in open-world games" "WARNING"
        }
        
        # Cleanup
        Remove-Item $random4KFile -Force -ErrorAction SilentlyContinue
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        
        # Rating
        Write-Log "" "INFO"
        $avgSpeed = ($writeMBps + $readMBps) / 2
        $rating = ""
        $diskType = if ($disk.BusType) { "$($disk.MediaType)-$($disk.BusType)" } else { $disk.MediaType }
        
        if ($disk.BusType -eq 'NVMe') {
            if ($avgSpeed -gt 2000) {
                $rating = "EXCELLENT"
                Write-Log "[EXCELLENT] NVMe performance is excellent for gaming" "SUCCESS"
            } elseif ($avgSpeed -gt 1000) {
                $rating = "GOOD"
                Write-Log "[GOOD] NVMe performance is good for gaming" "SUCCESS"
            } else {
                $rating = "WARNING"
                Write-Log "[WARNING] NVMe performance lower than expected" "WARNING"
            }
        } elseif ($disk.MediaType -eq 'SSD') {
            if ($avgSpeed -gt 400) {
                $rating = "EXCELLENT"
                Write-Log "[EXCELLENT] SSD performance is excellent for gaming" "SUCCESS"
            } elseif ($avgSpeed -gt 250) {
                $rating = "GOOD"
                Write-Log "[GOOD] SSD performance is good for gaming" "SUCCESS"
            } else {
                $rating = "WARNING"
                Write-Log "[WARNING] SSD performance lower than expected" "WARNING"
            }
        } else {
            $rating = "WARNING"
            Write-Log "[WARNING] HDD detected - Consider upgrading to SSD/NVMe for better gaming performance" "WARNING"
        }
        
        if ($ReturnData) {
            return @{
                DiskName = $disk.FriendlyName
                DiskType = $diskType
                WriteMBps = $writeMBps
                ReadMBps = $readMBps
                Random4KReadIOPS = $random4KReadIOPS
                Random4KWriteIOPS = $random4KWriteIOPS
                Random4KReadMBps = $random4KReadMBps
                Random4KWriteMBps = $random4KWriteMBps
                AverageSpeed = [math]::Round($avgSpeed, 2)
                Rating = $rating
            }
        }
        return $true
    }
    catch {
        $errorMsg = "Failed to benchmark disk: $_"
        # Just output to console - Write-Log has its own internal error handling
        Write-Host "ERROR: $errorMsg" -ForegroundColor Red
        
        # Cleanup on error - check if variables exist before using them
        if ($null -ne $testFile -and (Test-Path $testFile -ErrorAction SilentlyContinue)) {
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $random4KFile -and (Test-Path $random4KFile -ErrorAction SilentlyContinue)) {
            Remove-Item $random4KFile -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
}

# Benchmark network performance
function Invoke-NetworkBenchmark {
    param([switch]$ReturnData)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Network Performance Benchmark" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Show related optimization settings status
    Write-Log "" "INFO"
    Write-Log "Network-Related Optimization Settings:" "INFO"
    
    $networkThrottling = Get-OptimizationStatus -Setting 'NetworkThrottling'
    
    # Use INFO level to avoid duplicate WARNING stream output
    Write-Log "  Network Throttling Disabled: $(if ($networkThrottling) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "" "INFO"
    
    try {
        # Get network adapter info, prefer active default route
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual -and $_.InterfaceDescription -notlike '*Xbox*' }
        # Normalize link speed and add human-readable display + numeric value for sorting
        $adapters = $adapters | ForEach-Object {
            $a = $_
            $linkSpeedRaw = $a.LinkSpeed

            # Fallback: some adapters expose speed only via WMI
            if (-not $linkSpeedRaw -or $linkSpeedRaw -eq 0) {
                try {
                    $wmi = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "InterfaceIndex=$($a.ifIndex)" -ErrorAction SilentlyContinue
                    if ($wmi -and $wmi.Speed -gt 0) { $linkSpeedRaw = [double]$wmi.Speed }
                } catch {}
            }

            $linkSpeedBps = 0
            if ($linkSpeedRaw -is [double] -or $linkSpeedRaw -is [int64] -or $linkSpeedRaw -is [int]) {
                $linkSpeedBps = [double]$linkSpeedRaw
            }
            elseif ($linkSpeedRaw -match '([0-9.]+)\s*([A-Za-z]+)bps') {
                $num = [double]$matches[1]
                switch ($matches[2].ToLower()) {
                    'gbps' { $linkSpeedBps = $num * 1e9 }
                    'mbps' { $linkSpeedBps = $num * 1e6 }
                    default { $linkSpeedBps = $num }
                }
            }

            $linkSpeedDisplay = "Unknown"
            if ($linkSpeedBps -ge 1e9) {
                $linkSpeedDisplay = "{0} Gbps" -f [math]::Round($linkSpeedBps / 1e9, 2)
            }
            elseif ($linkSpeedBps -ge 1e6) {
                $linkSpeedDisplay = "{0} Mbps" -f [math]::Round($linkSpeedBps / 1e6, 1)
            }
            elseif ($linkSpeedRaw) {
                $linkSpeedDisplay = "$linkSpeedRaw"
            }

            $a | Add-Member -NotePropertyName LinkSpeedBps -NotePropertyValue $linkSpeedBps -Force
            $a | Add-Member -NotePropertyName LinkSpeedDisplay -NotePropertyValue $linkSpeedDisplay -Force
            $a
        }

        $adaptersWithIp = foreach ($a in $adapters) {
            $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.IPAddress -and
                    $_.IPAddress -notmatch '^169\.254\.' -and
                    $_.IPAddress -ne '0.0.0.0' -and
                    ($_.AddressState -eq 'Preferred' -or -not $_.AddressState)
                } | Select-Object -First 1
            if ($ip) {
                $a | Add-Member -NotePropertyName PrimaryIPv4 -NotePropertyValue $ip.IPAddress -Force
                $a
            }
        }
        # If no adapters exposed an IPv4, still keep the best active adapter for reporting
        if (-not $adaptersWithIp -or $adaptersWithIp.Count -eq 0) { $adaptersWithIp = $adapters }
        $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Sort-Object -Property @{Expression = { $_.InterfaceMetric + $_.RouteMetric }} | Select-Object -First 1
        $adapter = $null
        if ($defaultRoute) {
            $adapter = $adaptersWithIp | Where-Object { $_.ifIndex -eq $defaultRoute.InterfaceIndex } |
                Sort-Object -Property @{Expression = { -1 * $_.LinkSpeedBps }} | Select-Object -First 1
        }
        # Require IPv4 for selection; if none on default route, pick fastest with IPv4.
        if (-not $adapter) {
            $adapter = $adaptersWithIp | Sort-Object -Property @{Expression = { if ($_.InterfaceDescription -like '*Ethernet*') { 0 } elseif ($_.InterfaceDescription -like '*Wi-Fi*' -or $_.InterfaceDescription -like '*Wireless*') { 1 } else { 2 } }}, @{Expression = { -1 * $_.LinkSpeedBps }} | Select-Object -First 1
        }
        if ($adapter) {
            Write-Log "Network Adapter: $($adapter.InterfaceDescription)" "INFO"
            Write-Log "Link Speed: $($adapter.LinkSpeedDisplay)" "INFO"
        } else {
            Write-Log "No active network adapter detected; results may be incomplete" "WARNING"
        }
        
        # Get IP configuration for selected adapter
        $ipConfig = $null
        if ($adapter -and $adapter.PSObject.Properties.Name -contains 'PrimaryIPv4') {
            $ipConfig = $adapter.PrimaryIPv4
        } elseif ($adapter) {
            $ipConfigObj = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.IPAddress -and
                    $_.IPAddress -notmatch '^169\.254\.' -and
                    $_.IPAddress -ne '0.0.0.0' -and
                    $_.PrefixOrigin -in @('Dhcp','Manual','Other','WellKnown','RouterAdvertisement')
                } | Select-Object -First 1
            $ipConfig = if ($ipConfigObj) { $ipConfigObj.IPAddress } else { $null }
        }
        if ($ipConfig) {
            Write-Log "IP Address: $ipConfig" "INFO"
        } elseif ($adapter) {
            $anyIPv4 = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '0.0.0.0' } |
                Select-Object -First 1
            if ($anyIPv4) {
                Write-Log "No IPv4 address found for selected adapter ($($adapter.InterfaceDescription)); continuing." "INFO"
            } else {
                Write-Log "No IPv4 address found (no active IPv4 configured)" "WARNING"
            }
        }
        
        Write-Log "" "INFO"
        
        # Latency test to common gaming servers
        $testServers = @(
            @{Name="Steam CDN"; Address="cdn.cloudflare.steamstatic.com"},
            @{Name="Epic CDN"; Address="fastly-download.epicgames.com"},
            @{Name="Battle.net CDN"; Address="blzddist1-a.akamaihd.net"},
            @{Name="Cloudflare"; Address="one.one.one.one"}
        )
        
        Write-Log "Testing network latency..." "INFO"
        $totalLatency = 0
        $successCount = 0
        $allResults = @()
        $netLogTimestamp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format "yyyyMMdd-HHmmss-fff" }
        $netResultsDir = $ResultsPath
        if (-not (Test-Path $netResultsDir)) { New-Item -ItemType Directory -Path $netResultsDir -Force | Out-Null }
        $netTag = if ($script:CurrentTelemetryTag) { $script:CurrentTelemetryTag } else { '' }
        $netLogFile = Join-Path $netResultsDir ("Network-Latency-$netLogTimestamp$($netTag).csv")
        "timestamp_utc,server,method,latency_ms,success" | Set-Content -Path $netLogFile -Encoding UTF8
        
        foreach ($server in $testServers) {
            try {
                $latencySamples = @()
                $serverStart = Get-Date
                $lastUpdate = Get-Date
                Write-Host "  $($server.Name):   " -ForegroundColor Cyan -NoNewline

                # Resolve once to avoid DNS timing skew in samples
                $ipTarget = $null
                try {
                    $ipTarget = [System.Net.Dns]::GetHostAddresses($server.Address) |
                        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                        Select-Object -First 1
                } catch {}

                if (-not $ipTarget) {
                    throw "DNS resolution failed"
                }

                # Warm-up connection (primes route/ARP); don't record
                try {
                    $warm = New-Object System.Net.Sockets.TcpClient
                    $arWarm = $warm.BeginConnect($ipTarget, 443, $null, $null)
                    $null = $arWarm.AsyncWaitHandle.WaitOne(1200)
                    $warm.Close()
                } catch { }
                
                for ($i = 1; $i -le 3; $i++) {
                    try {
                        # TCP connect timing to port 443 (stable and doesn't include HTTP payload)
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $sw = [System.Diagnostics.Stopwatch]::StartNew()
                        $ar = $tcp.BeginConnect($ipTarget, 443, $null, $null)
                        if (-not $ar.AsyncWaitHandle.WaitOne(2000)) {
                            $tcp.Close()
                            throw "TCP connect timeout"
                        }
                        $tcp.EndConnect($ar)
                        $sw.Stop()
                        $tcp.Close()

                        $tcpLatency = [double]$sw.Elapsed.TotalMilliseconds
                        if ($tcpLatency -gt 0) {
                            $latencySamples += $tcpLatency
                            $allResults += @{Name=$server.Name; Latency=$tcpLatency}
                            $csvLine = "{0},{1},{2},{3},{4}" -f [DateTime]::UtcNow.ToString("O"), $server.Name, "tcp443", [math]::Round($tcpLatency,1), 1
                            Add-Content -Path $netLogFile -Value $csvLine -Encoding UTF8 -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        # Network timeout or other error - still record attempt time if available
                    }
                    
                    # Small delay between requests
                    Start-Sleep -Milliseconds 300
                    
                    # Live latency meter (higher fill = lower latency)
                    $currentAvg = if ($latencySamples.Count -gt 0) { ($latencySamples | Measure-Object -Average).Average } else { 0 }
                    $maxLatencyTarget = 100
                    $score = 100 - [Math]::Min(100, [Math]::Round(($currentAvg / $maxLatencyTarget) * 100, 0))
                    $barLength = 40
                    $filledLength = [Math]::Round($barLength * $score / 100)
                    $bar = "#" * $filledLength + "." * ($barLength - $filledLength)
                    
                    $elapsed = ((Get-Date) - $serverStart).TotalSeconds
                    $perPing = if ($i -gt 0) { $elapsed / $i } else { 0.2 }
                    $remaining = [Math]::Max(0, (3 - $i) * $perPing)
                    $remainingDisplay = if ($remaining -lt 1) { "<1s" } else { "$([int][Math]::Ceiling($remaining))s" }
                    $latencyDisplay = if ($currentAvg -gt 0) { "$([math]::Round($currentAvg,1))ms" } else { "--" }
                    
                    if ((((Get-Date) - $lastUpdate).TotalMilliseconds) -ge 150) {
                        Write-ProgressLine "  $($server.Name):   [$bar] $latencyDisplay | ${remainingDisplay} remaining" 'Cyan'
                        $lastUpdate = Get-Date
                    }
                }

                # Display final result with completed bar
                if ($latencySamples.Count -gt 0) {
                    $serverAvgLatency = ($latencySamples | Measure-Object -Average).Average
                    $finalLatency = [math]::Round($serverAvgLatency, 1)
                    $finalScore = 100 - [Math]::Min(100, [Math]::Round(($finalLatency / $maxLatencyTarget) * 100, 0))
                    $finalBar = "#" * [Math]::Round(40 * $finalScore / 100) + "." * (40 - [Math]::Round(40 * $finalScore / 100))
                    Write-Host "`r  $($server.Name):   [$finalBar] ${finalLatency}ms | Complete        " -ForegroundColor Cyan
                } else {
                    Write-Host "`r  $($server.Name):   [........................................] Failed        " -ForegroundColor Red
                }
                
                if ($latencySamples.Count -gt 0) {
                    $serverAvgLatency = ($latencySamples | Measure-Object -Average).Average
                    $serverMinLatency = ($latencySamples | Measure-Object -Minimum).Minimum
                    $serverMaxLatency = ($latencySamples | Measure-Object -Maximum).Maximum
                    
                    # Calculate jitter (average deviation from mean)
                    $jitter = 0
                    if ($latencySamples.Count -gt 1) {
                        $deviations = $latencySamples | ForEach-Object { [Math]::Abs($_ - $serverAvgLatency) }
                        $jitter = [math]::Round(($deviations | Measure-Object -Average).Average, 1)
                    }
                    
                    Write-Log "$($server.Name): Avg $([math]::Round($serverAvgLatency, 1))ms | Min $([math]::Round($serverMinLatency, 1))ms | Max $([math]::Round($serverMaxLatency, 1))ms | Jitter $([math]::Round($jitter, 1))ms" "SUCCESS"
                    
                    $totalLatency += $serverAvgLatency
                    $successCount++
                }
            } catch {
                Write-Log "$($server.Name): Test failed" "WARNING"
            }
        }
        
        # Rating
        $rating = ""
        $avgLatency = 0
        $minLatency = 0
        $maxLatency = 0
        
        if ($successCount -gt 0) {
            Write-Log "" "INFO"
            $avgLatency = [math]::Round($totalLatency / $successCount, 0)
            
            # Calculate min/max across all servers
            if ($allResults.Count -gt 0) {
                $allLatencies = $allResults | ForEach-Object { $_.Latency }
                $minLatency = ($allLatencies | Measure-Object -Minimum).Minimum
                $maxLatency = ($allLatencies | Measure-Object -Maximum).Maximum
            }
            
            Write-Log "Average Latency: ${avgLatency}ms" "INFO"
            
            if ($avgLatency -lt 20) {
                $rating = "EXCELLENT"
                Write-Log "[EXCELLENT] Network latency is excellent for gaming" "SUCCESS"
            } elseif ($avgLatency -lt 50) {
                $rating = "GOOD"
                Write-Log "[GOOD] Network latency is good for gaming" "SUCCESS"
            } elseif ($avgLatency -lt 100) {
                $rating = "FAIR"
                Write-Log "[FAIR] Network latency is acceptable for gaming" "INFO"
            } else {
                $rating = "WARNING"
                Write-Log "[WARNING] High network latency may affect online gaming" "WARNING"
            }
        }

        # Compute global min/max from hashtable array
        if ($allResults.Count -gt 0) {
            # Extract latency values from hashtable array
            $allLatencies = $allResults | ForEach-Object { $_.Latency }
            $minLatency = ($allLatencies | Measure-Object -Minimum).Minimum
            $maxLatency = ($allLatencies | Measure-Object -Maximum).Maximum
        }
        
        # DNS resolution test
        Write-Log "" "INFO"
        Write-Log "Testing DNS resolution..." "INFO"
        $dnsServers = @("steampowered.com", "epicgames.com", "battle.net")
        $dnsTotal = 0
        $dnsCount = 0
        
        foreach ($domain in $dnsServers) {
            try {
                $startTime = Get-Date
                $null = [System.Net.Dns]::GetHostAddresses($domain)
                $endTime = Get-Date
                $dnsTime = ($endTime - $startTime).TotalMilliseconds
                
                Write-Log "$domain : $([math]::Round($dnsTime, 0))ms" "SUCCESS"
                $dnsTotal += $dnsTime
                $dnsCount++
            } catch {
                Write-Log "$domain : Failed" "WARNING"
            }
        }
        
        $avgDNS = 0
        if ($dnsCount -gt 0) {
            $avgDNS = [math]::Round($dnsTotal / $dnsCount, 0)
            Write-Log "Average DNS Resolution: ${avgDNS}ms" "INFO"
            
            if ($avgDNS -lt 30) {
                Write-Log "[GOOD] DNS resolution is fast" "SUCCESS"
            } elseif ($avgDNS -lt 100) {
                Write-Log "[FAIR] DNS resolution is acceptable" "INFO"
            } else {
                Write-Log "[WARNING] Slow DNS resolution - consider using faster DNS servers (1.1.1.1 or 8.8.8.8)" "WARNING"
            }
        }
        
        # Internet Speed Test
        Write-Log "" "INFO"
        Write-Log "Testing internet speed..." "INFO"
        
        $downloadSpeed = 0
        $uploadSpeed = 0
        
        try {
            # Use the asheroto speedtest tool
            Write-Host "  Internet Speed: " -ForegroundColor Cyan -NoNewline
            $speedStart = Get-Date

            function Convert-SpeedToMbps {
                param(
                    [Parameter(Mandatory = $true)][double]$Value,
                    [string]$Prefix
                )
                $prefixValue = if ([string]::IsNullOrEmpty($Prefix)) { '' } else { $Prefix }
                switch ($prefixValue.ToUpperInvariant()) {
                    'G' { return [math]::Round($Value * 1000, 1) }
                    'M' { return [math]::Round($Value, 1) }
                    'K' { return [math]::Round($Value / 1000, 2) }
                    default { return [math]::Round($Value, 1) }
                }
            }

            # Run the speedtest and capture full output (not just the last lines)
            $speedtestText = (& powershell -NoProfile -Command "irm asheroto.com/speedtest | iex" 2>&1 | Out-String)
            $speedtestLines = $speedtestText -split "`r?`n"

            # Parse the results to find download and upload speeds
            $downloadSpeed = 0
            $uploadSpeed = 0
            foreach ($lineStr in $speedtestLines) {
                if ([string]::IsNullOrWhiteSpace($lineStr)) { continue }

                # Match common variants like:
                #   Download: 100.5 Mbps
                #   Download: 1.2 Gbps
                #   Upload: 40.2 Mb/s
                if ($lineStr -match '(?i)\bdownload\b.*?([0-9]+(?:\.[0-9]+)?)\s*([GMK])?\s*(?:bps|bit/s|bits/s|b/s)') {
                    $downloadSpeed = Convert-SpeedToMbps -Value ([double]$matches[1]) -Prefix $matches[2]
                }
                if ($lineStr -match '(?i)\bupload\b.*?([0-9]+(?:\.[0-9]+)?)\s*([GMK])?\s*(?:bps|bit/s|bits/s|b/s)') {
                    $uploadSpeed = Convert-SpeedToMbps -Value ([double]$matches[1]) -Prefix $matches[2]
                }
            }
            
            $elapsed = ((Get-Date) - $speedStart).TotalSeconds
            
            if ($downloadSpeed -gt 0 -and $uploadSpeed -gt 0) {
                # Scale progress bar to 1000 Mbps (1 Gbps) maximum
                $expectedMaxMbps = 1000
                $speedPercent = [Math]::Min(($downloadSpeed / $expectedMaxMbps) * 100, 100)
                $barLength = 40
                $filledLength = [Math]::Round($barLength * $speedPercent / 100)
                $finalBar = "#" * $filledLength + "." * ($barLength - $filledLength)
                Write-Host "`r  Internet Speed: [$finalBar] Down: $([math]::Round($downloadSpeed,1)) Mbps | Up: $([math]::Round($uploadSpeed,1)) Mbps | Complete" -ForegroundColor Cyan
                Write-Log "Download Speed: $([math]::Round($downloadSpeed,1)) Mbps | Upload Speed: $([math]::Round($uploadSpeed,1)) Mbps" "SUCCESS"
            } else {
                Write-Host "`r  Internet Speed: [........................................] Speedtest skipped (optional)" -ForegroundColor Yellow
                Write-Log "Speedtest skipped - optional test" "INFO"
            }
        }
        catch {
            Write-Host "`r  Internet Speed: [........................................] Skipped        " -ForegroundColor Yellow
            Write-Log "Speedtest skipped - optional test" "INFO"
        }
        
        # Speed rating
        if ($downloadSpeed -gt 0) {
            Write-Log "" "INFO"
            if ($downloadSpeed -gt 100) {
                Write-Log "[EXCELLENT] Internet speed is excellent for online gaming" "SUCCESS"
            } elseif ($downloadSpeed -gt 50) {
                Write-Log "[GOOD] Internet speed is good for online gaming" "SUCCESS"
            } elseif ($downloadSpeed -gt 25) {
                Write-Log "[FAIR] Internet speed is adequate for gaming" "INFO"
            } else {
                Write-Log "[WARNING] Slow internet speed may affect downloads and updates" "WARNING"
            }
        }
        
        if ($ReturnData) {
            return @{
                AdapterName = if ($adapter) { $adapter.InterfaceDescription } else { "Unknown" }
                LinkSpeed = if ($adapter -and $adapter.LinkSpeedDisplay) { $adapter.LinkSpeedDisplay } elseif ($adapter) { $adapter.LinkSpeed } else { "Unknown" }
                LinkSpeedBps = if ($adapter) { $adapter.LinkSpeedBps } else { 0 }
                NetworkThrottlingOptimized = $networkThrottling
                AvgLatency = $avgLatency
                MinLatency = $minLatency
                MaxLatency = $maxLatency
                AvgDNSResolution = $avgDNS
                # Keep both legacy and summary-friendly property names
                DownloadSpeed = $downloadSpeed
                UploadSpeed = $uploadSpeed
                DownloadMbps = $downloadSpeed
                UploadMbps = $uploadSpeed
                Rating = $rating
            }
        }
        return $true
    }
    catch {
        Write-Log "Failed to benchmark network: $_" "ERROR"
        return $false
    }
}

# Benchmark GPU performance and capabilities
# Get or install nvidia-smi
function Get-NvidiaSmi {
    param([switch]$AutoInstall)
    
    # Check common locations
    $nvidiaSmiPaths = @(
        "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        "${env:ProgramFiles(x86)}\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        "$env:SystemRoot\System32\nvidia-smi.exe"
    )
    
    foreach ($path in $nvidiaSmiPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Not found - offer to install
    Write-Log "nvidia-smi not found in standard locations" "WARNING"
    
    if ($AutoInstall) {
        Write-Log "Attempting to locate nvidia-smi from NVIDIA driver installation..." "INFO"
        
        # Try to find it in driver cache/installation
        $driverPaths = @(
            "$env:ProgramData\NVIDIA Corporation\Installer2",
            "C:\NVIDIA\DisplayDriver"
        )
        
        foreach ($driverPath in $driverPaths) {
            if (Test-Path $driverPath) {
                $foundSmi = Get-ChildItem -Path $driverPath -Filter "nvidia-smi.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundSmi) {
                    Write-Log "Found nvidia-smi at: $($foundSmi.FullName)" "SUCCESS"
                    
                    # Copy to standard location
                    $targetDir = "$env:ProgramFiles\NVIDIA Corporation\NVSMI"
                    if (-not (Test-Path $targetDir)) {
                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    }
                    
                    $targetPath = "$targetDir\nvidia-smi.exe"
                    Copy-Item -Path $foundSmi.FullName -Destination $targetPath -Force
                    Write-Log "Copied nvidia-smi to: $targetPath" "SUCCESS"
                    
                    return $targetPath
                }
            }
        }
        
        # If still not found, suggest driver reinstall
        Write-Log "nvidia-smi could not be located in driver cache" "WARNING"
        Write-Log "To get nvidia-smi, please:" "INFO"
        Write-Log "  1. Download latest NVIDIA driver from nvidia.com/drivers" "INFO"
        Write-Log "  2. Choose 'Custom' installation" "INFO"
        Write-Log "  3. Ensure 'Display Driver' components are selected" "INFO"
        Write-Log "  4. nvidia-smi will be installed to C:\Program Files\NVIDIA Corporation\NVSMI\" "INFO"
        Write-Log "" "INFO"
        Write-Log "Alternatively, nvidia-smi is included in CUDA Toolkit" "INFO"
        Write-Log "  Download from: developer.nvidia.com/cuda-downloads" "INFO"
    }
    
    return $null
}

function Invoke-GPUBenchmark {
    param([switch]$ReturnData)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "GPU Performance Analysis" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Show related optimization settings status
    Write-Log "" "INFO"
    Write-Log "GPU-Related Optimization Settings:" "INFO"
    
    $gameMode = Get-OptimizationStatus -Setting 'GameMode'
    $gameDVR = Get-OptimizationStatus -Setting 'GameDVR'
    $fullscreenOpt = Get-OptimizationStatus -Setting 'FullscreenOptimizations'
    
    # Use INFO level to avoid duplicate WARNING stream output
    Write-Log "  Game Mode Enabled:              $(if ($gameMode) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "  Game DVR Disabled:              $(if ($gameDVR) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "  Fullscreen Optimizations Set:   $(if ($fullscreenOpt) { '[OK] OPTIMIZED' } else { '[X] Not Optimized' })" "INFO"
    Write-Log "" "INFO"
    
    try {
        $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Remote|Virtual' } | Select-Object -First 1
        
        if (-not $gpu) {
            Write-Log "No dedicated GPU detected" "WARNING"
            return $false
        }
        
        Write-Log "GPU: $($gpu.Name)" "INFO"
        Write-Log "Driver Version: $($gpu.DriverVersion)" "INFO"
        Write-Log "Driver Date: $($gpu.DriverDate)" "INFO"

        # Initialize telemetry placeholders
        $gpuUtilization = 0
        $gpuTemperature = 0
        $gpuPowerDraw = 0
        $gpuClockSpeed = 0
        $gpuClockSpeedUnderLoad = 0
        $gpuMaxClockSpeed = 0
        $gpuMemoryUsed = 0
        
        # Memory - Use multiple methods to get accurate VRAM
        $vramGB = 0
        $vramSource = ""
        $nvidiaSmiPath = $null
        
        # Method 1: Try nvidia-smi for NVIDIA GPUs (most accurate)
        $hasNvidiaSmiMetrics = $false
        if ($gpu.Name -match 'NVIDIA') {
            try {
                $nvidiaSmiPath = Get-NvidiaSmi -AutoInstall
                if ($nvidiaSmiPath) {
                    Write-Log "Using nvidia-smi for accurate VRAM detection..." "INFO"
                    $nvidiaSmiOutput = & $nvidiaSmiPath --query-gpu=memory.total --format=csv,noheader,nounits 2>$null
                    if ($nvidiaSmiOutput -and $nvidiaSmiOutput -match '^\d+') {
                        $vramMB = [int]$nvidiaSmiOutput.Trim()
                        $vramGB = [math]::Round($vramMB / 1024, 2)
                        $vramSource = "nvidia-smi"
                        Write-Log "nvidia-smi detected: $vramGB GB VRAM" "SUCCESS"
                    }

                    # Collect utilization/temperature/power/clock/memory in one query.
                    # Sample multiple times and derive:
                    # - Idle clock from low-util samples
                    # - "Under load" clock only if utilization indicates real load
                    try {
                        $samples = @()
                        for ($s = 0; $s -lt 12; $s++) {
                            $metricLine = & $nvidiaSmiPath --query-gpu=utilization.gpu,temperature.gpu,power.draw,clocks.current.graphics,clocks.max.graphics,memory.used --format=csv,noheader,nounits 2>$null
                            if ($metricLine -and $metricLine.Contains(',')) {
                                $parts = $metricLine -split ',' | ForEach-Object { $_.Trim() }
                                if ($parts.Count -ge 6) {
                                    $samples += [pscustomobject]@{
                                        Util     = [int]$parts[0]
                                        Temp     = [int]$parts[1]
                                        Power    = [double]$parts[2]
                                        Clock    = [int]$parts[3]
                                        MaxClock = [int]$parts[4]
                                        MemUsed  = [double]$parts[5]
                                    }
                                    $hasNvidiaSmiMetrics = $true
                                }
                            }
                            Start-Sleep -Milliseconds 350
                        }

                        if ($hasNvidiaSmiMetrics -and $samples.Count -gt 0) {
                            $gpuMaxClockSpeed = ($samples | Measure-Object -Property MaxClock -Maximum).Maximum
                            $gpuUtilization = ($samples | Measure-Object -Property Util -Maximum).Maximum
                            $gpuTemperature = ($samples | Measure-Object -Property Temp -Maximum).Maximum
                            $gpuPowerDraw = [math]::Round((($samples | Measure-Object -Property Power -Maximum).Maximum), 1)
                            $gpuMemoryUsed = [math]::Round((($samples | Measure-Object -Property MemUsed -Maximum).Maximum) / 1024, 2)

                            $idleCandidates = @($samples | Where-Object { $_.Util -le 10 -and $_.Clock -gt 0 } | Select-Object -ExpandProperty Clock)
                            if ($idleCandidates.Count -gt 0) {
                                $gpuClockSpeed = [int][math]::Round((($idleCandidates | Measure-Object -Average).Average), 0)
                            } else {
                                $gpuClockSpeed = ($samples | Where-Object { $_.Clock -gt 0 } | Measure-Object -Property Clock -Minimum).Minimum
                            }

                            # Only call it "under load" if we actually observed load.
                            if ($gpuUtilization -ge 30) {
                                $gpuClockSpeedUnderLoad = ($samples | Where-Object { $_.Clock -gt 0 } | Measure-Object -Property Clock -Maximum).Maximum
                            } else {
                                $gpuClockSpeedUnderLoad = 0
                            }
                        }
                    }
                    catch {
                        Write-Debug "nvidia-smi metric query failed: $_"
                    }
                }
            }
            catch {
                Write-Debug "nvidia-smi VRAM detection failed: $_"
            }
        }
        
        # Method 2: Try DXGI (DirectX Graphics Infrastructure)
        if ($vramGB -eq 0) {
            try {
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DXGI {
    [DllImport("dxgi.dll")]
    public static extern int CreateDXGIFactory1(ref Guid riid, out IntPtr ppFactory);
    
    [DllImport("dxgi.dll")]
    public static extern int EnumAdapters1(IntPtr pFactory, uint Adapter, out IntPtr ppAdapter);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct DXGI_ADAPTER_DESC1 {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string Description;
        public uint VendorId;
        public uint DeviceId;
        public uint SubSysId;
        public uint Revision;
        public UIntPtr DedicatedVideoMemory;
        public UIntPtr DedicatedSystemMemory;
        public UIntPtr SharedSystemMemory;
        public long AdapterLuid;
        public uint Flags;
    }
}
"@ -ErrorAction SilentlyContinue
            
                $iidFactory = [Guid]"7b7166ec-21c7-44ae-b21a-c9ae321ae369"
                $pFactory = [IntPtr]::Zero
                $hr = [DXGI]::CreateDXGIFactory1([ref]$iidFactory, [ref]$pFactory)
            
                if ($hr -eq 0 -and $pFactory -ne [IntPtr]::Zero) {
                    # Try to get first adapter
                    $pAdapter = [IntPtr]::Zero
                    $hr = [DXGI]::EnumAdapters1($pFactory, 0, [ref]$pAdapter)
                
                    if ($hr -eq 0 -and $pAdapter -ne [IntPtr]::Zero) {
                        $desc = New-Object DXGI+DXGI_ADAPTER_DESC1
                        # Read adapter description from memory
                        [System.Runtime.InteropServices.Marshal]::PtrToStructure($pAdapter, $desc)
                        $dedicatedVRAM = [uint64]$desc.DedicatedVideoMemory
                        if ($dedicatedVRAM -gt 0) {
                            $vramGB = [math]::Round($dedicatedVRAM / 1GB, 2)
                            $vramSource = "DXGI (DirectX)"
                        }
                    }
                }
            }
            catch {
                Write-Debug "DXGI VRAM detection failed: $_"
            }
        }
        
        # Method 3: Try WMI VideoMemoryType query (more reliable than AdapterRAM)
        if ($vramGB -eq 0) {
            try {
                $videoMem = Get-CimInstance -Query "SELECT * FROM Win32_VideoController WHERE Name LIKE '%$($gpu.Name)%'" -ErrorAction SilentlyContinue
                if ($videoMem.AdapterRAM -gt 0) {
                    # AdapterRAM is in bytes
                    $vramGB = [math]::Round($videoMem.AdapterRAM / 1GB, 2)
                    $vramSource = "WMI"
                }
            }
            catch {
                Write-Debug "WMI VRAM detection failed: $_"
            }
        }
        
        # Method 4: Try registry (NVIDIA HardwareInformation.MemorySize)
        if ($vramGB -eq 0) {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}"
                $devices = Get-ChildItem $regPath -ErrorAction SilentlyContinue
                
                foreach ($device in $devices) {
                    $deviceProps = Get-ItemProperty $device.PSPath -ErrorAction SilentlyContinue
                    
                    # Check if this is the right GPU by matching driver description
                    if ($deviceProps.DriverDesc -match $gpu.Name.Split(' ')[0]) {
                        # Try HardwareInformation.MemorySize (NVIDIA)
                        $memSize = $deviceProps.'HardwareInformation.MemorySize'
                        if ($memSize -and $memSize -gt 0) {
                            $vramGB = [math]::Round($memSize / 1GB, 2)
                            $vramSource = "Registry (HardwareInformation)"
                            break
                        }
                        
                        # Try HardwareInformation.qwMemorySize (NVIDIA alternative)
                        $qwMemSize = $deviceProps.'HardwareInformation.qwMemorySize'
                        if ($qwMemSize -and $qwMemSize -gt 0) {
                            $vramGB = [math]::Round($qwMemSize / 1GB, 2)
                            $vramSource = "Registry (qwMemorySize)"
                            break
                        }
                    }
                }
            }
            catch {
                Write-Debug "Registry VRAM detection failed: $_"
            }
        }
        
        # Method 5: Try parsing from GPU name (last resort for common GPUs)
        if ($vramGB -eq 0) {
            $gpuNameLower = $gpu.Name.ToLower()
            # Common patterns in GPU names
            if ($gpuNameLower -match '(\d+)\s*gb') {
                $vramGB = [int]$matches[1]
                $vramSource = "GPU Name Pattern"
            }
            elseif ($gpuNameLower -match 'rtx\s*40(90|80|70|60)') {
                # RTX 4000 series defaults
                $vramGB = switch -Regex ($matches[1]) {
                    '90' { 24 }
                    '80' { 16 }
                    '70' { 12 }
                    '60' { 8 }
                }
                $vramSource = "GPU Model Estimate"
            }
            elseif ($gpuNameLower -match 'rtx\s*30(90|80|70|60)\s*(ti)?') {
                # RTX 3000 series - check for 12GB 3060 variant
                if ($gpuNameLower -match '3060' -and $gpuNameLower -notmatch 'ti') {
                    # RTX 3060 has 12GB (unique in the lineup)
                    $vramGB = 12
                }
                else {
                    $vramGB = switch -Regex ($matches[1]) {
                        '90' { 24 }
                        '80' { 10 }
                        '70' { 8 }
                        '60' { 8 }
                    }
                }
                $vramSource = "GPU Model Estimate"
            }
        }
        
        # GPU Clock speeds and performance metrics
        Write-Log "" "INFO"
        try {
            if ($gpuMaxClockSpeed -gt 0 -and $gpuClockSpeed -gt 0) {
                $clockPercentIdle = [math]::Round(($gpuClockSpeed / $gpuMaxClockSpeed) * 100, 0)
                Write-Log "  Max Clock Speed: $gpuMaxClockSpeed MHz" "INFO"
                Write-Log "  Clock (current):  $gpuClockSpeed MHz ($clockPercentIdle% of max)" "INFO"
            } elseif ($hasNvidiaSmiMetrics) {
                Write-Log "  Max Clock Speed: (unavailable)" "INFO"
                Write-Log "  Clock (current):  $gpuClockSpeed MHz" "INFO"
            }

            if ($hasNvidiaSmiMetrics) {
                Write-Log "  Temperature:     $gpuTemperature C" "INFO"
                Write-Log "  Power Draw:      $gpuPowerDraw W" "INFO"
                Write-Log "  Utilization:     $gpuUtilization%" "INFO"
                Write-Log "  Memory Used:     $gpuMemoryUsed GB" "INFO"
            }
        }
        catch {
            Write-Debug "Could not read GPU performance metrics: $_"
        }
        
        # Resolution
        Write-Log "" "INFO"
        Write-Log "Current Resolution: $($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)" "INFO"
        Write-Log "Refresh Rate: $($gpu.CurrentRefreshRate) Hz" "INFO"
        
        if ($gpu.CurrentRefreshRate -ge 144) {
            Write-Log "[EXCELLENT] High refresh rate display" "SUCCESS"
        } elseif ($gpu.CurrentRefreshRate -ge 120) {
            Write-Log "[GOOD] High refresh rate capable" "SUCCESS"
        } elseif ($gpu.CurrentRefreshRate -ge 60) {
            Write-Log "[FAIR] Standard refresh rate" "INFO"
        }
        
        # Check DirectX support
        Write-Log "" "INFO"
        try {
            $dxDiag = Get-CimInstance -ClassName Win32_VideoController | Select-Object -First 1
            Write-Log "Video Processor: $($dxDiag.VideoProcessor)" "INFO"
            Write-Log "Video Architecture: $($dxDiag.VideoArchitecture)" "INFO"
        } catch {
            Write-Debug "Could not get extended GPU info"
        }
        
        # HAGS status - Check multiple locations
        Write-Log "" "INFO"
        $hagsEnabled = $false
        
        # Method 1: Check primary location (most common)
        $hagsPath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        if (Test-Path $hagsPath1) {
            $hagsValue = (Get-ItemProperty -Path $hagsPath1 -Name "HwSchMode" -ErrorAction SilentlyContinue).HwSchMode
            if ($hagsValue -eq 2) {
                $hagsEnabled = $true
            }
        }
        
        # Method 2: Check scheduler subkey (Windows 11 24H2)
        if (-not $hagsEnabled) {
            $hagsPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler"
            if (Test-Path $hagsPath2) {
                $schedValue = (Get-ItemProperty -Path $hagsPath2 -Name "EnablePreemption" -ErrorAction SilentlyContinue).EnablePreemption
                if ($schedValue -eq 1) {
                    $hagsEnabled = $true
                }
            }
        }
        
        # Method 3: Check per-adapter feature settings (most reliable for Windows 11)
        if (-not $hagsEnabled) {
            $featurePath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\FeatureSetUsage"
            if (Test-Path $featurePath) {
                $featureValue = (Get-ItemProperty -Path $featurePath -Name "HwSchMode" -ErrorAction SilentlyContinue).HwSchMode
                if ($featureValue -eq 2) {
                    $hagsEnabled = $true
                }
            }
        }
        
        # Method 4: Try to read from actual adapter key
        if (-not $hagsEnabled -and $gpu.PNPDeviceID) {
            try {
                $null = $gpu.PNPDeviceID -replace '\\', '_'
                $adapterPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
                if (Test-Path $adapterPath) {
                    $adapters = Get-ChildItem -Path $adapterPath -ErrorAction SilentlyContinue
                    foreach ($adapter in $adapters) {
                        $hwSchMode = (Get-ItemProperty -Path $adapter.PSPath -Name "HwSchMode" -ErrorAction SilentlyContinue).HwSchMode
                        if ($hwSchMode -eq 2) {
                            $hagsEnabled = $true
                            break
                        }
                    }
                }
            }
            catch {
                Write-Debug "Could not check adapter-specific HAGS settings"
            }
        }
        
        # Report status
        if ($hagsEnabled) {
            Write-Log "Hardware-Accelerated GPU Scheduling: ENABLED" "SUCCESS"
        } else {
            Write-Log "Hardware-Accelerated GPU Scheduling: DISABLED" "INFO"
            Write-Log "Consider enabling HAGS for potentially better performance (if supported)" "INFO"
        }
        
        # GPU recommendations based on manufacturer
        Write-Log "" "INFO"
        $gpuName = $gpu.Name.ToLower()
        $rating = "FAIR"
        
        if ($gpuName -match 'rtx (40|30)\d{2}') {
            $rating = "EXCELLENT"
            Write-Log "[EXCELLENT] High-end modern GPU - excellent for gaming at high settings" "SUCCESS"
        } elseif ($gpuName -match 'rtx 20\d{2}|rx (6|7)\d{3}') {
            $rating = "GOOD"
            Write-Log "[GOOD] Modern GPU - good for gaming at high settings" "SUCCESS"
        } elseif ($gpuName -match 'gtx (16|10)\d{2}|rx 5\d{3}') {
            $rating = "FAIR"
            Write-Log "[FAIR] Mid-range GPU - suitable for gaming at medium-high settings" "INFO"
        } elseif ($gpuName -match 'gtx (9|7)\d{2}|rx (4|5)\d{2}') {
            $rating = "WARNING"
            Write-Log "[WARNING] Older GPU - may struggle with newer games at high settings" "WARNING"
        }
        
        if ($ReturnData) {
            return @{
                BenchmarkRan = $true
                GPUName = $gpu.Name
                VRAMGB = $vramGB
                DriverVersion = $gpu.DriverVersion
                RefreshRate = $gpu.CurrentRefreshRate
                Resolution = "$($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution)"
                HAGSEnabled = $hagsEnabled
                GameModeOptimized = $gameMode
                GameDVROptimized = $gameDVR
                FullscreenOptimizationsOptimized = $fullscreenOpt
                Utilization = $gpuUtilization
                Temperature = $gpuTemperature
                PowerDraw = $gpuPowerDraw
                ClockSpeed = $gpuClockSpeed
                ClockSpeedUnderLoad = $gpuClockSpeedUnderLoad
                MaxClockSpeed = $gpuMaxClockSpeed
                MemoryUsed = $gpuMemoryUsed
                VramSource = $vramSource
                Rating = $rating
            }
        }
        return $true
    }
    catch {
        Write-Log "Failed to analyze GPU: $_" "ERROR"
        return $false
    }
}

# GPU Rendering Benchmark using Unigine Superposition
function Invoke-GPURenderingBenchmark {
    param(
        [switch]$ReturnData,
        [switch]$SkipPrompt
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "GPU Rendering Benchmark (DirectX/OpenGL)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $useGravityMark = $true
    
    # Check if we should skip this (optional benchmark) - but only prompt if not explicitly specified
    if (-not $WhatIfPreference -and -not $SkipPrompt) {
        Write-Host "`n===============================================" -ForegroundColor Yellow
        Write-Host "Optional: GPU Rendering Benchmark (3D Stress Test)" -ForegroundColor Yellow
        Write-Host "===============================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Cyan
        Write-Host "  1. Run GravityMark benchmark" -ForegroundColor Green
        Write-Host "  2. Skip GPU benchmark" -ForegroundColor White
        Write-Host ""
        Write-Host "Choose (1/2, default=1): " -NoNewline -ForegroundColor Cyan
        $choice = Read-Host
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $choice = "1"
        }

        if ($choice -eq "2") {
            Write-Log "GPU rendering benchmark skipped by user" "INFO"
            
            if ($ReturnData) {
                return @{
                    TestRun = $false
                    Tool = "Skipped"
                    Score = 0
                    FPS = 0
                    Rating = "NOT_TESTED"
                }
            }
            return $true
        }
    }
    
    try {
        if ($useGravityMark) {
            try {
                Write-Log "Setting up GravityMark GPU benchmark..." "INFO"

            $gravityTemp = Join-Path $env:TEMP "GravityMark_Temp"
            if (-not (Test-Path $gravityTemp)) {
                New-Item -ItemType Directory -Path $gravityTemp -Force | Out-Null
            }

            $gravityDownload = Join-Path $gravityTemp "GravityMark_download.bin"
            $gravityDir = Join-Path $gravityTemp "GravityMark"
            $gravityExe = $null

            # Allow manual path to avoid brittle URLs
            $downloadSuccess = $false
            $gravityPackagePath = $null
            if ($GravityMarkPath -and (Test-Path $GravityMarkPath)) {
                Write-Log "Using GravityMark at specified path: $GravityMarkPath" "INFO"
                $gravityPackagePath = $GravityMarkPath
                $downloadSuccess = $true
            } else {
                # If already installed, use it and skip MSI download/install entirely.
                $installed = Find-InstalledGravityMarkExe
                if ($installed -and (Test-Path $installed.FullName)) {
                    $gravityExe = $installed
                    $downloadSuccess = $true
                    Write-Log "GravityMark already installed at: $($gravityExe.FullName)" "INFO"
                }
            }

            if (-not $downloadSuccess) {
                $discovered = Get-GravityMarkWindowsDownloadUrl
                $gravityUrls = @(
                    $discovered
                ) | Where-Object { $_ -and $_.Trim() -ne '' } | Select-Object -Unique

                foreach ($gravityUrl in $gravityUrls) {
                    try {
                        Write-Log "Attempting GravityMark download from: $gravityUrl" "INFO"
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $gravityUrl -OutFile $gravityDownload -UseBasicParsing -TimeoutSec 180 -MaximumRedirection 5 -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } -ErrorAction Stop
                            $fileBytes = [System.IO.File]::ReadAllBytes($gravityDownload)
                            $isZip = ($fileBytes.Length -ge 2 -and $fileBytes[0] -eq 0x50 -and $fileBytes[1] -eq 0x4B) # 'PK'
                            $isMsi = ($fileBytes.Length -ge 8 -and $fileBytes[0] -eq 0xD0 -and $fileBytes[1] -eq 0xCF -and $fileBytes[2] -eq 0x11 -and $fileBytes[3] -eq 0xE0 -and $fileBytes[4] -eq 0xA1 -and $fileBytes[5] -eq 0xB1 -and $fileBytes[6] -eq 0x1A -and $fileBytes[7] -eq 0xE1) # OLE compound file header

                            if ($isZip -or $isMsi -or ($gravityUrl -match '(?i)\.msi($|\?)')) {
                                $dest = if ($isMsi -or ($gravityUrl -match '(?i)\.msi($|\?)')) {
                                    Join-Path $gravityTemp 'GravityMark.msi'
                                } else {
                                    Join-Path $gravityTemp 'GravityMark.zip'
                                }
                                Move-Item -Path $gravityDownload -Destination $dest -Force
                                $gravityPackagePath = $dest
                                $downloadSuccess = $true
                                Write-Log "GravityMark downloaded successfully" "SUCCESS"
                                break
                            }

                            Write-Log "GravityMark download was not a recognized package (likely HTML); ignoring" "WARNING"
                            Remove-Item $gravityDownload -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        $msg = $_.Exception.Message
                        Write-Log "Failed GravityMark download from $gravityUrl : $msg" "WARNING"
                    }
                }
            }

            if (-not $downloadSuccess) {
                Write-Log "GravityMark download failed (site links likely changed)." "WARNING"
                Write-Log "Manual option: download from https://gravitymark.tellusim.com/ and rerun with -GravityMarkPath <exe-or-msi>" "INFO"
                if ($ReturnData) {
                    return @{
                        TestRun = $false
                        Tool = "GravityMark (download failed)"
                        Score = 0
                        FPS = 0
                        Rating = "NOT_TESTED"
                    }
                }
                return $true
            }

            # If we found an installed exe, skip staging/extraction and run it in-place.

            # Only continue with GravityMark if we have a package/exe
            if ($downloadSuccess -and ($gravityExe -or $gravityPackagePath)) {
                try {
                    if (-not $gravityExe) {
                        if (Test-Path $gravityDir) { Remove-Item -Path $gravityDir -Recurse -Force -ErrorAction SilentlyContinue }
                    }
                    if ($gravityExe) {
                        # No staging required
                    }
                    elseif ($gravityPackagePath -like '*.zip') {
                        Expand-Archive -Path $gravityPackagePath -DestinationPath $gravityDir -Force
                    }
                    elseif ($gravityPackagePath -like '*.msi') {
                        # Preferred behavior: silently install GravityMark, then run it.
                        # This matches the product's intended deployment and avoids brittle ZIP packaging.
                        $gravityExe = $null

                        # If already installed, use it.
                        try {
                            $uninstallRoots = @(
                                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                            )
                            foreach ($root in $uninstallRoots) {
                                if (-not (Test-Path $root)) { continue }
                                $apps = Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                                    try { Get-ItemProperty -Path $_.PSPath -ErrorAction Stop } catch { $null }
                                } | Where-Object { $_ -and $_.DisplayName -match 'GravityMark' }

                                $app = $apps | Sort-Object DisplayVersion -Descending | Select-Object -First 1
                                if ($app) {
                                    $candidates = @()
                                    # Known common install locations
                                    $candidates += @(
                                        (Join-Path $env:ProgramFiles 'GravityMark\bin\GravityMark.exe'),
                                        (Join-Path $env:ProgramFiles 'GravityMark\GravityMark.exe'),
                                        (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\bin\GravityMark.exe'),
                                        (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\GravityMark.exe')
                                    )
                                    if ($app.DisplayIcon) { $candidates += ($app.DisplayIcon -split ',')[0].Trim('"') }
                                    if ($app.InstallLocation) { $candidates += (Join-Path $app.InstallLocation 'GravityMark.exe') }
                                    foreach ($c in $candidates) {
                                        if ($c -and (Test-Path $c)) {
                                            $gravityExe = Get-Item $c
                                            break
                                        }
                                    }
                                }
                                if ($gravityExe) { break }
                            }
                        } catch {}

                        if (-not $gravityExe) {
                            Write-Log "Installing GravityMark silently from MSI..." "INFO"
                            $msiLog = Join-Path $gravityTemp 'GravityMark_msiexec.log'
                            $msiArgs = @(
                                '/i', $gravityPackagePath,
                                '/qn',
                                '/norestart',
                                '/log', $msiLog
                            )

                            $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
                            if (-not $p -or $p.ExitCode -ne 0) {
                                throw "msiexec /i failed with exit code $($p.ExitCode) (log: $msiLog)"
                            }

                            # Re-check installed location after install
                            try {
                                $uninstallRoots = @(
                                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                                )
                                foreach ($root in $uninstallRoots) {
                                    if (-not (Test-Path $root)) { continue }
                                    $apps = Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                                        try { Get-ItemProperty -Path $_.PSPath -ErrorAction Stop } catch { $null }
                                    } | Where-Object { $_ -and $_.DisplayName -match 'GravityMark' }
                                    $app = $apps | Sort-Object DisplayVersion -Descending | Select-Object -First 1
                                    if ($app) {
                                        $candidates = @()
                                        if ($app.DisplayIcon) { $candidates += ($app.DisplayIcon -split ',')[0].Trim('"') }
                                        if ($app.InstallLocation) { $candidates += (Join-Path $app.InstallLocation 'GravityMark.exe') }
                                        $candidates += @(
                                            (Join-Path $env:ProgramFiles 'GravityMark\GravityMark.exe'),
                                            (Join-Path $env:ProgramFiles 'GravityMark\bin\GravityMark.exe'),
                                            (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\GravityMark.exe'),
                                            (Join-Path ${env:ProgramFiles(x86)} 'GravityMark\bin\GravityMark.exe'),
                                            (Join-Path $env:ProgramFiles 'Tellusim\GravityMark\GravityMark.exe'),
                                            (Join-Path ${env:ProgramFiles(x86)} 'Tellusim\GravityMark\GravityMark.exe')
                                        )
                                        foreach ($c in $candidates | Select-Object -Unique) {
                                            if ($c -and (Test-Path $c)) {
                                                $gravityExe = Get-Item $c
                                                break
                                            }
                                        }
                                    }
                                    if ($gravityExe) { break }
                                }
                            } catch {}
                        }

                        if (-not $gravityExe) {
                            # Fallback: attempt a silent administrative extraction if installation didn't yield a detectable exe.
                            Write-Log "GravityMark installed but executable not found via registry; attempting MSI extraction..." "WARNING"
                            New-Item -ItemType Directory -Path $gravityDir -Force | Out-Null
                            $msiArgs = @('/a', $gravityPackagePath, '/qn', '/norestart', "TARGETDIR=$gravityDir")
                            $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
                            if (-not $p -or $p.ExitCode -ne 0) {
                                throw "msiexec /a failed with exit code $($p.ExitCode)"
                            }
                            $gravityExe = Get-ChildItem -Path $gravityDir -Filter 'GravityMark.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        }

                        if ($gravityExe) {
                            # If we have a usable installed/extracted exe, overwrite $gravityDir search base so the later lookup succeeds.
                            $gravityDir = Split-Path $gravityExe.FullName -Parent
                        }
                    }
                    else {
                        # If user provided an EXE path, stage it into a folder
                        New-Item -ItemType Directory -Path $gravityDir -Force | Out-Null
                        Copy-Item -Path $gravityPackagePath -Destination (Join-Path $gravityDir 'GravityMark.exe') -Force
                    }
                }
                catch {
                    Write-Log "Failed to stage GravityMark package: $_" "ERROR"
                    if ($ReturnData) {
                        return @{
                            TestRun = $false
                            Tool = "GravityMark (extract failed)"
                            Score = 0
                            FPS = 0
                            Rating = "NOT_TESTED"
                        }
                    }
                    return $false
                }

                if (-not $gravityExe) {
                    $gravityExe = Get-ChildItem -Path $gravityDir -Filter "GravityMark.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                }
                if (-not $gravityExe) {
                    Write-Log "GravityMark executable not found after extraction" "ERROR"
                    if ($ReturnData) {
                        return @{
                            TestRun = $false
                            Tool = "GravityMark (exe not found)"
                            Score = 0
                            FPS = 0
                            Rating = "NOT_TESTED"
                        }
                    }
                    return $false
                }

                # GravityMark uses single-dash options (from manual + installed run_*.bat files).
                # NOTE: -times must be a filename relative to WorkingDirectory (absolute paths are not reliably created).
                $gmTag = if ($script:CurrentTelemetryTag) { $script:CurrentTelemetryTag } else { '' }
                $gmPrefix = if ($script:RunTimestamp) { "GravityMark_times_$script:RunTimestamp" } else { "GravityMark_times_$([Guid]::NewGuid().ToString('N'))" }
                $gravityTimesName = "$gmPrefix-$([Guid]::NewGuid().ToString('N'))$($gmTag).csv"
                $gravityBin = Split-Path $gravityExe.FullName -Parent
                $gravityTimesPath = Join-Path $gravityBin $gravityTimesName

                # Manual renderer flag is -direct3d12 (short aliases may exist, but use documented option).
                $native = Get-PrimaryMonitorResolution

                # Attempt GravityMark, retrying up to twice with progressively reduced memory settings if OOM occurs.
                $gmAttempt = 0
                $gmProcess = $null
                $gmStdout = ""
                $gmStderr = ""
                while ($gmAttempt -lt 3) {
                    $gmAttempt++
                    switch ($gmAttempt) {
                        1 {
                            # Native fullscreen (best fidelity) - try Direct3D12 first
                            $width = [string]$native.Width
                            $height = [string]$native.Height
                            $fullscreen = '1'
                            $rendererFlag = '-direct3d12'
                        }
                        2 {
                            # First fallback: try Direct3D11 at native resolution
                            $width = [string]$native.Width
                            $height = [string]$native.Height
                            $fullscreen = '1'
                            $rendererFlag = '-direct3d11'
                            Write-Log "GravityMark fallback: attempt 2 - try Direct3D11 renderer" "WARNING"
                        }
                        3 {
                            # Aggressive fallback: reduced resolution 640x360 windowed (very low memory use), use Direct3D11
                            $width = '640'
                            $height = '360'
                            $fullscreen = '0'
                            $rendererFlag = '-direct3d11'
                            Write-Log "GravityMark fallback: attempt 3 - 640x360 windowed (aggressive) using D3D11" "WARNING"
                        }
                    }

                    $gmArgs = @(
                        $rendererFlag,
                        '-benchmark', '1',
                        '-close', '1',
                        '-status', '1',
                        '-count', '1',
                        '-fullscreen', $fullscreen,
                        '-fps', '0',
                        '-info', '0',
                        '-sensors', '0',
                        '-width', $width,
                        '-height', $height,
                        '-times', $gravityTimesName
                    )

                    $gmInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $gmInfo.FileName = $gravityExe.FullName
                    $gmInfo.Arguments = $gmArgs -join " "
                    # GravityMark loads ../data.zip; run from bin folder.
                    $gmInfo.WorkingDirectory = $gravityBin
                    $gmInfo.UseShellExecute = $false
                    $gmInfo.RedirectStandardOutput = $true
                    $gmInfo.RedirectStandardError = $true
                    $gmInfo.CreateNoWindow = $true
                    $gmInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

                    if ($gmProcess) {
                        try { if (-not $gmProcess.HasExited) { $gmProcess.Kill() } } catch {}
                        $gmProcess = $null
                    }

                    $gmProcess = [System.Diagnostics.Process]::Start($gmInfo)

                    # Wait for completion (6 minutes) and capture output
                    $gmCompleted = $gmProcess.WaitForExit(360000)
                    $gmStdout = $gmProcess.StandardOutput.ReadToEnd()
                    $gmStderr = $gmProcess.StandardError.ReadToEnd()

                    # If process exited cleanly, break loop
                    if ($gmCompleted -and $gmProcess.ExitCode -eq 0) { break }

                    # If we detected out-of-memory in stderr/stdout and haven't exhausted fallbacks, retry
                    $combined = "{0}`n{1}" -f $gmStderr, $gmStdout
                    if ($combined -match 'out of memory' -and $gmAttempt -lt 3) {
                        Write-Log "GravityMark reported out-of-memory; retrying with more aggressive fallback..." "WARNING"
                        Continue
                    }
                    else {
                        # No retry condition; exit loop
                        break
                    }
                }

                # Sample NVIDIA telemetry during the GravityMark run for accurate "Clock Load".
                $gmTelemetry = @()
                $telemetryJob = $null
                try {
                    $nvidiaSmiPath = Get-NvidiaSmi
                    if ($nvidiaSmiPath -and $gmProcess -and $gmProcess.Id -gt 0) {
                        $telemetryJob = Start-Job -ArgumentList @($gmProcess.Id, $nvidiaSmiPath) -ScriptBlock {
                            param($procId, $smi)
                            $start = Get-Date
                            while ($true) {
                                $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
                                if (-not $p) { break }
                                try {
                                    $line = & $smi --query-gpu=utilization.gpu,temperature.gpu,power.draw,clocks.current.graphics,clocks.max.graphics --format=csv,noheader,nounits 2>$null
                                    if ($line -and $line.Contains(',')) {
                                        $parts = $line -split ',' | ForEach-Object { $_.Trim() }
                                        if ($parts.Count -ge 5) {
                                            [pscustomobject]@{
                                                Ts       = [DateTime]::UtcNow
                                                Util     = [int]$parts[0]
                                                Temp     = [int]$parts[1]
                                                Power    = [double]$parts[2]
                                                Clock    = [int]$parts[3]
                                                MaxClock = [int]$parts[4]
                                            }
                                        }
                                    }
                                } catch {}
                                Start-Sleep -Milliseconds 500
                                if (((Get-Date) - $start).TotalMinutes -gt 10) { break }
                            }
                        }
                    }
                } catch {}

                $gmCompleted = $gmProcess.WaitForExit(360000)  # 6 minute timeout

                if ($telemetryJob) {
                    try {
                        $null = Wait-Job -Job $telemetryJob -Timeout 30
                        if ($telemetryJob.State -eq 'Running') {
                            Stop-Job -Job $telemetryJob -Force -ErrorAction SilentlyContinue
                        }
                        $gmTelemetry = @(Receive-Job -Job $telemetryJob -Wait -ErrorAction SilentlyContinue)
                    } catch {}
                    try { Remove-Job -Job $telemetryJob -Force -ErrorAction SilentlyContinue } catch {}
                }

                if (-not $gmCompleted) {
                    Write-Log "GravityMark timeout - killing process" "WARN"
                    Stop-Process -InputObject $gmProcess -Force -ErrorAction SilentlyContinue
                    if ($ReturnData) {
                        return @{
                            TestRun = $false
                            Tool = "GravityMark (timeout)"
                            Score = 0
                            FPS = 0
                            Rating = "TIMEOUT"
                        }
                    }
                    return $true
                }

                $gmStdout = $gmProcess.StandardOutput.ReadToEnd()
                $gmStderr = $gmProcess.StandardError.ReadToEnd()
                if ($gmStdout) {
                    Write-Debug $gmStdout
                }
                if ($gmStderr) {
                    Write-Debug $gmStderr
                }

                if ($gmProcess.ExitCode -ne 0) {
                    $snippet = $gmStderr
                    if (-not $snippet) { $snippet = $gmStdout }
                    if ($snippet -and $snippet.Length -gt 600) { $snippet = $snippet.Substring(0, 600) }
                    Write-Log "GravityMark exited with code $($gmProcess.ExitCode). Output: $snippet" "WARNING"
                }

                $gmScore = 0
                $gmFps = 0

                # Derive NVIDIA load metrics (best-effort)
                $gmGpuClockAvg = 0
                $gmGpuClockMax = 0
                $gmGpuMaxClock = 0
                $gmGpuUtilMax = 0
                $gmGpuTempMax = 0
                $gmGpuPowerMax = 0
                if ($gmTelemetry -and $gmTelemetry.Count -gt 0) {
                    $clockVals = @($gmTelemetry | Where-Object { $_.Clock -gt 0 } | Select-Object -ExpandProperty Clock)
                    if ($clockVals.Count -gt 0) {
                        $gmGpuClockAvg = [int][math]::Round((($clockVals | Measure-Object -Average).Average), 0)
                        $gmGpuClockMax = ($clockVals | Measure-Object -Maximum).Maximum
                    }
                    $gmGpuMaxClock = ($gmTelemetry | Measure-Object -Property MaxClock -Maximum).Maximum
                    $gmGpuUtilMax = ($gmTelemetry | Measure-Object -Property Util -Maximum).Maximum
                    $gmGpuTempMax = ($gmTelemetry | Measure-Object -Property Temp -Maximum).Maximum
                    $gmGpuPowerMax = [math]::Round((($gmTelemetry | Measure-Object -Property Power -Maximum).Maximum), 1)
                }

                # Parse FPS from the -times output. Manual format:
                #   <index> <time> <delta time> <pass index>
                # delta time is seconds per frame.
                $gmOnePercentLowFps = 0
                $gmPointOnePercentLowFps = 0
                if (Test-Path $gravityTimesPath) {
                    try {
                        $lines = Get-Content -Path $gravityTimesPath -ErrorAction Stop
                        $deltas = foreach ($ln in $lines) {
                            if (-not $ln) { continue }
                            $parts = ($ln -split '\s+') | Where-Object { $_ -ne '' }
                            if ($parts.Count -ge 3) {
                                $dt = 0.0
                                if ([double]::TryParse($parts[2], [ref]$dt) -and $dt -gt 0) { $dt }
                            }
                        }
                        if ($deltas -and $deltas.Count -gt 0) {
                            # Skip initial warmup frames to stabilize FPS estimate
                            $stable = if ($deltas.Count -gt 60) { $deltas | Select-Object -Skip 30 } else { $deltas }
                            $avgDt = ($stable | Measure-Object -Average).Average
                            if ($avgDt -gt 0) {
                                $gmFps = [math]::Round((1.0 / $avgDt), 1)
                            }

                            # Compute 1% and 0.1% lows using the same approach as the built-in rendering test:
                            # take the 99th/99.9th percentile frametime (worst 1% / 0.1%), then convert to FPS.
                            $frameMs = $stable | ForEach-Object { $_ * 1000.0 }
                            if ($frameMs -and $frameMs.Count -ge 10) {
                                $sorted = $frameMs | Sort-Object -Descending
                                $n = $sorted.Count
                                $idx1 = [math]::Floor($n * 0.01)
                                $idx01 = [math]::Floor($n * 0.001)
                                $idx1 = [math]::Min([math]::Max($idx1, 0), $n - 1)
                                $idx01 = [math]::Min([math]::Max($idx01, 0), $n - 1)
                                $oneMs = [double]$sorted[$idx1]
                                $p01Ms = [double]$sorted[$idx01]
                                if ($oneMs -gt 0) { $gmOnePercentLowFps = [math]::Round((1000.0 / $oneMs), 1) }
                                if ($p01Ms -gt 0) { $gmPointOnePercentLowFps = [math]::Round((1000.0 / $p01Ms), 1) }
                            }
                        }
                    }
                    catch {
                        Write-Log "Failed to parse GravityMark times file: $_" "WARN"
                    }
                } else {
                    Write-Log "GravityMark did not produce a -times file at: $gravityTimesPath" "WARNING"
                }

                # Fallback parsing from stdout/stderr if present
                if ($gmFps -le 0 -and ($gmStdout + "`n" + $gmStderr) -match "FPS[:=]\s*([0-9.]+)") {
                    $gmFps = [double]$matches[1]
                }
                if ($gmScore -le 0 -and ($gmStdout + "`n" + $gmStderr) -match "Score[:=]\s*([0-9.]+)") {
                    $gmScore = [double]$matches[1]
                }

                $displayHz = Get-PrimaryMonitorRefreshRate
                if (-not $displayHz -or $displayHz -lt 30) { $displayHz = 60 }
                $ratingTargetHz = if ($displayHz -ge 120) { 120 } else { [int]$displayHz }
                $ratingNote = if ($displayHz -lt 120) { "Rating scaled to ${displayHz}Hz display" } else { "Rating scaled to 120Hz cap (display ${displayHz}Hz)" }
                $lowForRating = if ($gmOnePercentLowFps -gt 0) { $gmOnePercentLowFps } else { $gmFps }

                # Target is min(display refresh, 120 Hz): meeting/exceeding is good; below target is not.
                $gmRating = if ($gmFps -ge $ratingTargetHz -and $lowForRating -ge ($ratingTargetHz * 0.85)) { "EXCELLENT" }
                elseif ($gmFps -ge $ratingTargetHz) { "VERY_GOOD" }
                elseif ($gmFps -ge ($ratingTargetHz * 0.90)) { "GOOD" }
                elseif ($gmFps -gt 0) { "BELOW_TARGET" }
                else { "UNKNOWN" }

                $logTarget = "Target=${ratingTargetHz}Hz (display ${displayHz}Hz)"
                if ($gmGpuClockAvg -gt 0) {
                    Write-Log "GravityMark: FPS=$gmFps (1%=$gmOnePercentLowFps, 0.1%=$gmPointOnePercentLowFps), $logTarget, Score=$gmScore, Rating=$gmRating, GPUClockAvg=$gmGpuClockAvg MHz" "INFO"
                } else {
                    Write-Log "GravityMark: FPS=$gmFps (1%=$gmOnePercentLowFps, 0.1%=$gmPointOnePercentLowFps), $logTarget, Score=$gmScore, Rating=$gmRating" "INFO"
                }

                if ($ReturnData) {
                    return @{
                        TestRun = $true
                        Tool = "GravityMark"
                        Score = $gmScore
                        FPS = $gmFps
                        OnePercentLowFPS = $gmOnePercentLowFps
                        PointOnePercentLowFPS = $gmPointOnePercentLowFps
                        TargetRefreshRate = $ratingTargetHz
                        RatingTargetHz = $ratingTargetHz
                        DisplayRefreshRateHz = $displayHz
                        RatingNote = $ratingNote
                        Rating = $gmRating
                        Width = $native.Width
                        Height = $native.Height
                        GpuClockAvgMHz = $gmGpuClockAvg
                        GpuClockMaxMHz = $gmGpuClockMax
                        GpuMaxClockMHz = $gmGpuMaxClock
                        GpuUtilMax = $gmGpuUtilMax
                        GpuTempMax = $gmGpuTempMax
                        GpuPowerMaxW = $gmGpuPowerMax
                    }
                }

                return $true
            } # End of if ($downloadSuccess)
            }
            finally {
                if (Test-Path $gravityTemp) {
                    Remove-Item -Path $gravityTemp -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # Should never reach here; keep a safe fallback.
        if ($ReturnData) {
            return @{
                TestRun = $false
                Tool = "Skipped"
                Score = 0
                FPS = 0
                Rating = "NOT_TESTED"
            }
        }
        return $true
    }
    catch {
        Write-Log "Failed to run GPU rendering benchmark: $_" "ERROR"
        
        if ($ReturnData) {
            return @{
                TestRun = $false
                Tool = "Unigine Superposition (error)"
                Score = 0
                FPS = 0
                Rating = "ERROR"
            }
        }
        return $false
    }
    finally {
        # No extra temp cleanup needed here (GravityMark temp is handled in its block)
    }
}

# Save benchmark results to JSON file
function Save-BenchmarkResults {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Results,
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $targetDir = Split-Path -Parent $FilePath
        if ($targetDir -and -not (Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }

        $resultsWithTimestamp = @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ComputerName = $env:COMPUTERNAME
            Results = $Results
        }
        
        $json = $resultsWithTimestamp | ConvertTo-Json -Depth 10
        Set-Content -Path $FilePath -Value $json -Force
        Write-Log "Benchmark results saved to: $FilePath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to save benchmark results: $_" "ERROR"
        return $false
    }
}

# Benchmark RAM performance and configuration
function Invoke-RAMBenchmark {
    param([switch]$ReturnData)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RAM Performance Benchmark" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Log "" "INFO"
    
    try {
        # Get RAM information
        $ramModules = Get-CimInstance -ClassName Win32_PhysicalMemory
        $totalRAMGB = [math]::Round(($ramModules | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        $ramCount = $ramModules.Count
        
        Write-Log "Total RAM: $totalRAMGB GB" "INFO"
        Write-Log "RAM Modules: $ramCount" "INFO"
        Write-Log "" "INFO"
        
        # Analyze dual channel configuration
        $isDualChannel = $false
        $channelStatus = "Unknown"
        
        if ($ramCount -eq 1) {
            $isDualChannel = $false
            $channelStatus = "Single Channel (1 stick)"
            Write-Log "[WARNING] Single channel RAM detected - performance is significantly reduced!" "WARNING"
            Write-Log "  - Single channel provides ~50% less memory bandwidth" "WARNING"
            Write-Log "  - Recommendation: Add a matching RAM stick to enable dual channel" "WARNING"
        }
        elseif ($ramCount -eq 2) {
            # Check if modules are identical (same size and speed)
            $firstModule = $ramModules[0]
            $secondModule = $ramModules[1]
            
            if ($firstModule.Capacity -eq $secondModule.Capacity -and 
                $firstModule.Speed -eq $secondModule.Speed) {
                $isDualChannel = $true
                $channelStatus = "Dual Channel (2 matching sticks)"
                Write-Log "[EXCELLENT] Dual channel configuration detected!" "SUCCESS"
            }
            else {
                $isDualChannel = $false
                $channelStatus = "Mixed Configuration (2 non-matching sticks)"
                Write-Log "[WARNING] RAM sticks don't match - may not be running in dual channel" "WARNING"
                Write-Log "  - For best performance, use matching RAM sticks" "WARNING"
            }
        }
        elseif ($ramCount -eq 4) {
            # Check if modules are paired correctly
            $uniqueSizes = ($ramModules | Select-Object -ExpandProperty Capacity -Unique).Count
            $uniqueSpeeds = ($ramModules | Select-Object -ExpandProperty Speed -Unique).Count
            
            if ($uniqueSizes -eq 1 -and $uniqueSpeeds -eq 1) {
                $isDualChannel = $true
                $channelStatus = "Dual Channel (4 matching sticks)"
                Write-Log "[EXCELLENT] Quad channel/Dual channel configuration detected!" "SUCCESS"
            }
            else {
                $channelStatus = "Mixed Configuration (4 sticks)"
                Write-Log "[WARNING] RAM sticks may not be optimally configured" "WARNING"
            }
        }
        else {
            $channelStatus = "$ramCount sticks (configuration unknown)"
            Write-Log "RAM Configuration: $ramCount sticks" "INFO"
        }
        
        Write-Log "Channel Status: $channelStatus" "INFO"
        Write-Log "" "INFO"
        
        # Get RAM speed information
        $ramSpeeds = @()
        $configuredSpeed = 0
        
        # Track module characteristics for matching validation
        $moduleDetails = @()
        
        foreach ($module in $ramModules) {
            $moduleIndex = ([array]::IndexOf($ramModules, $module)) + 1
            $manufacturer = if ([string]::IsNullOrWhiteSpace($module.Manufacturer)) { "Unknown" } else { $module.Manufacturer.Trim() }
            $partNumber = if ([string]::IsNullOrWhiteSpace($module.PartNumber)) { "Unknown" } else { $module.PartNumber.Trim() }
            
            Write-Log "Module ${moduleIndex}:" "INFO"
            Write-Log "  Manufacturer: $manufacturer" "INFO"
            if ($partNumber -ne "Unknown") {
                Write-Log "  Part Number: $partNumber" "INFO"
            }
            Write-Log "  Capacity: $([math]::Round($module.Capacity / 1GB, 0)) GB" "INFO"
            Write-Log "  Speed: $($module.Speed) MHz (Configured)" "INFO"
            
            # ConfiguredClockSpeed is the actual running speed
            $configuredSpeed = $module.Speed
            $ramSpeeds += $configuredSpeed
            
            # Some modules report max speed
            if ($module.ConfiguredVoltage) {
                Write-Log "  Voltage: $($module.ConfiguredVoltage) mV" "INFO"
            }
            
            # Store module details for matching validation
            $moduleDetails += @{
                Index = $moduleIndex
                Manufacturer = $manufacturer
                PartNumber = $partNumber
                Capacity = $module.Capacity
                Speed = $module.Speed
            }
            
            Write-Log "" "INFO"
        }
        
        # Validate all modules are identical
        if ($ramCount -ge 2) {
            $firstModule = $moduleDetails[0]
            $allIdentical = $true
            $mismatchDetails = @()
            
            for ($i = 1; $i -lt $moduleDetails.Count; $i++) {
                $currentModule = $moduleDetails[$i]
                
                if ($currentModule.Manufacturer -ne $firstModule.Manufacturer) {
                    $allIdentical = $false
                    $mismatchDetails += "Module $($currentModule.Index) manufacturer ($($currentModule.Manufacturer)) differs from Module 1 ($($firstModule.Manufacturer))"
                }
                if ($currentModule.PartNumber -ne $firstModule.PartNumber -and $currentModule.PartNumber -ne "Unknown" -and $firstModule.PartNumber -ne "Unknown") {
                    $allIdentical = $false
                    $mismatchDetails += "Module $($currentModule.Index) part number ($($currentModule.PartNumber)) differs from Module 1 ($($firstModule.PartNumber))"
                }
                if ($currentModule.Capacity -ne $firstModule.Capacity) {
                    $allIdentical = $false
                    $mismatchDetails += "Module $($currentModule.Index) capacity ($([math]::Round($currentModule.Capacity / 1GB, 0))GB) differs from Module 1 ($([math]::Round($firstModule.Capacity / 1GB, 0))GB)"
                }
                if ($currentModule.Speed -ne $firstModule.Speed) {
                    $allIdentical = $false
                    $mismatchDetails += "Module $($currentModule.Index) speed ($($currentModule.Speed)MHz) differs from Module 1 ($($firstModule.Speed)MHz)"
                }
            }
            
            if (-not $allIdentical) {
                Write-Log "[WARNING] RAM modules are NOT identical!" "WARNING"
                foreach ($detail in $mismatchDetails) {
                    Write-Log "  - $detail" "WARNING"
                }
                Write-Log "  [IMPACT] Non-identical RAM may cause:" "WARNING"
                Write-Log "    - Reduced performance (may not run in dual channel)" "WARNING"
                Write-Log "    - System instability" "WARNING"
                Write-Log "    - RAM running at speed of slowest module" "WARNING"
                Write-Log "  [RECOMMENDATION] Use identical RAM modules for best performance" "WARNING"
                Write-Log "" "INFO"
            } else {
                Write-Log "[EXCELLENT] All RAM modules are identical - optimal configuration" "SUCCESS"
                Write-Log "" "INFO"
            }
        }
        
        # Get average configured speed
        $avgSpeed = [math]::Round(($ramSpeeds | Measure-Object -Average).Average, 0)
        Write-Log "Average RAM Speed: $avgSpeed MHz" "INFO"
        
        # Determine if RAM is running at optimal speed
        $isOptimalSpeed = $false
        $speedRating = ""
        $speedRecommendation = ""
        
        if ($avgSpeed -ge 3200) {
            $isOptimalSpeed = $true
            $speedRating = "EXCELLENT"
            Write-Log "[EXCELLENT] RAM is running at high speed ($avgSpeed MHz)" "SUCCESS"
        }
        elseif ($avgSpeed -ge 3000) {
            $isOptimalSpeed = $true
            $speedRating = "GOOD"
            Write-Log "[GOOD] RAM is running at good speed ($avgSpeed MHz)" "SUCCESS"
        }
        elseif ($avgSpeed -ge 2666) {
            $isOptimalSpeed = $false
            $speedRating = "FAIR"
            Write-Log "[FAIR] RAM speed is adequate but could be improved ($avgSpeed MHz)" "INFO"
            $speedRecommendation = "Consider enabling XMP/DOCP in BIOS to increase speed to 3200+ MHz"
        }
        else {
            $isOptimalSpeed = $false
            $speedRating = "WARNING"
            Write-Log "[WARNING] RAM is running at base speed ($avgSpeed MHz - likely 2133 or 2400)" "WARNING"
            $speedRecommendation = "Enable XMP (Intel) or DOCP/EXPO (AMD) in BIOS to unlock full RAM speed"
            Write-Log "  - Your RAM likely supports 3000-3600 MHz" "WARNING"
            Write-Log "  - Default JEDEC speed is 2133/2400 MHz - this is SLOW!" "WARNING"
            Write-Log "  - Enabling XMP/DOCP can provide 30-50% more memory bandwidth" "WARNING"
        }
        
        Write-Log "" "INFO"
        
        # Physical RAM Performance Test
        Write-Log "Testing physical RAM performance..." "INFO"
        $ramBandwidthMBps = 0
        
        try {
            # Memory bandwidth test - use Buffer.BlockCopy for accurate measurement
            $testSizeMB = 512
            $iterations = 3
            
            Write-Progress -Activity "RAM Performance Test" -Status "Testing memory bandwidth..." -PercentComplete 0
            
            $bandwidthTests = @()
            for ($i = 0; $i -lt $iterations; $i++) {
                $sourceArray = New-Object byte[] ($testSizeMB * 1MB)
                $destArray = New-Object byte[] ($testSizeMB * 1MB)
                
                # Fill source with random data
                (New-Object Random).NextBytes($sourceArray)
                
                # Copy test (measures actual memory bandwidth)
                $startTime = Get-Date
                [System.Buffer]::BlockCopy($sourceArray, 0, $destArray, 0, $sourceArray.Length)
                $copyTime = ((Get-Date) - $startTime).TotalSeconds
                
                if ($copyTime -gt 0) {
                    # Multiply by 2 because BlockCopy reads from source and writes to dest
                    $bandwidth = [math]::Round(($testSizeMB * 2 / $copyTime), 0)
                    $bandwidthTests += $bandwidth
                }
                
                $sourceArray = $null
                $destArray = $null
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                
                Write-Progress -Activity "RAM Performance Test" -Status "Testing memory bandwidth..." -PercentComplete (($i + 1) / $iterations * 100)
            }
            
            Write-Progress -Activity "RAM Performance Test" -Completed
            
            if ($bandwidthTests.Count -gt 0) {
                $ramBandwidthMBps = [math]::Round(($bandwidthTests | Measure-Object -Average).Average, 0)
                Write-Log "Physical RAM Bandwidth: $ramBandwidthMBps MB/s" "SUCCESS"
                
                # Expected bandwidth based on RAM speed and channel config
                $expectedBandwidth = $avgSpeed * 8 # MHz * 8 bytes per transfer
                if ($isDualChannel) { $expectedBandwidth *= 2 }
                
                $bandwidthPercent = [math]::Round(($ramBandwidthMBps / $expectedBandwidth) * 100, 0)
                Write-Log "Bandwidth Efficiency: $bandwidthPercent% of theoretical max ($expectedBandwidth MB/s)" "INFO"
                
                # Visual gauge
                $filledLength = [math]::Max(0, [math]::Min(50, [math]::Round($bandwidthPercent / 2, 0)))
                $emptyLength = [math]::Max(0, 50 - $filledLength)
                $gauge = ("#" * $filledLength) + ("." * $emptyLength)
                Write-Host "  Bandwidth:   [$gauge] $bandwidthPercent%" -ForegroundColor Cyan
            }
        }
        catch {
            Write-Log "RAM performance test failed: $_" "WARNING"
        }
        
        Write-Log "" "INFO"
        
        # Pagefile Performance Test
        Write-Log "Testing pagefile performance..." "INFO"
        $pagefileBandwidthMBps = 0
        
        try {
            $pagefileConfigs = @(Get-CimInstance -ClassName Win32_PageFileUsage)
            if ($pagefileConfigs.Count -gt 0) {
                $pagefilePaths = ($pagefileConfigs | ForEach-Object { $_.Name }) -join ', '
                Write-Log "Pagefile Location(s): $pagefilePaths" "INFO"
                
                $totalAllocated = ($pagefileConfigs | Measure-Object -Property AllocatedBaseSize -Sum).Sum
                $totalUsed = ($pagefileConfigs | Measure-Object -Property CurrentUsage -Sum).Sum
                Write-Log "Pagefile Size: $([math]::Round($totalAllocated / 1024, 2)) GB (Current: $([math]::Round($totalUsed / 1024, 2)) GB used)" "INFO"
                
                # Test the first pagefile's drive
                $pagefilePath = $pagefileConfigs[0].Name
                
                # Test pagefile disk performance (since pagefile is on disk)
                $pagefileDrive = $pagefilePath.Substring(0, 2)
                $testFile = "$pagefileDrive\pagefile-perf-test.tmp"
                $testSizeMB = 64
                
                Write-Progress -Activity "Pagefile Performance Test" -Status "Testing pagefile backing storage..." -PercentComplete 0
                
                # Write test
                $testData = New-Object byte[] ($testSizeMB * 1MB)
                $startTime = Get-Date
                [System.IO.File]::WriteAllBytes($testFile, $testData)
                $writeTime = ((Get-Date) - $startTime).TotalSeconds
                
                # Read test
                $startTime = Get-Date
                $null = [System.IO.File]::ReadAllBytes($testFile)
                $readTime = ((Get-Date) - $startTime).TotalSeconds
                
                # Cleanup
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                
                Write-Progress -Activity "Pagefile Performance Test" -Completed
                
                $avgTime = ($writeTime + $readTime) / 2
                if ($avgTime -gt 0) {
                    $pagefileBandwidthMBps = [math]::Round(($testSizeMB / $avgTime), 0)
                    Write-Log "Pagefile Storage Speed: $pagefileBandwidthMBps MB/s" "SUCCESS"
                    
                    if ($pagefileBandwidthMBps -ge 2000) {
                        Write-Log "[EXCELLENT] Pagefile on fast NVMe/SSD" "SUCCESS"
                    }
                    elseif ($pagefileBandwidthMBps -ge 500) {
                        Write-Log "[GOOD] Pagefile on SSD" "SUCCESS"
                    }
                    elseif ($pagefileBandwidthMBps -ge 100) {
                        Write-Log "[FAIR] Pagefile on HDD - consider moving to SSD" "INFO"
                    }
                    else {
                        Write-Log "[WARNING] Slow pagefile storage detected" "WARNING"
                    }
                }
            }
            else {
                Write-Log "No pagefile configured" "INFO"
            }
        }
        catch {
            Write-Log "Pagefile performance test failed: $_" "WARNING"
        }
        
        Write-Log "" "INFO"
        
        # Overall RAM rating
        $rating = ""
        if ($totalRAMGB -ge 32 -and $isDualChannel -and $avgSpeed -ge 3200) {
            $rating = "EXCELLENT"
            Write-Log "[EXCELLENT] RAM configuration is excellent for gaming" "SUCCESS"
        }
        elseif ($totalRAMGB -ge 16 -and $isDualChannel -and $avgSpeed -ge 3000) {
            $rating = "GOOD"
            Write-Log "[GOOD] RAM configuration is good for gaming" "SUCCESS"
        }
        elseif ($totalRAMGB -ge 16) {
            $rating = "FAIR"
            Write-Log "[FAIR] RAM configuration is adequate but has room for improvement" "INFO"
        }
        else {
            $rating = "WARNING"
            Write-Log "[WARNING] RAM configuration may limit gaming performance" "WARNING"
        }
        
        # Pagefile size validation
        if ($pagefileConfigs -and $pagefileConfigs.Count -gt 0) {
            $totalPagefileSizeMB = ($pagefileConfigs | Measure-Object -Property AllocatedBaseSize -Sum).Sum
            $totalPagefileSizeGB = [math]::Round($totalPagefileSizeMB / 1024, 1)
            $recommendedMinGB = [math]::Round($totalRAMGB * 1.5, 1)
            $recommendedMaxGB = [math]::Round($totalRAMGB * 2, 1)
            
            if ($totalPagefileSizeGB -lt $recommendedMinGB) {
                Write-Log "  [WARNING] Pagefile size ($totalPagefileSizeGB GB) is below recommended minimum" "WARNING"
                Write-Log "    - Recommended: $recommendedMinGB - $recommendedMaxGB GB (1.5-2x physical RAM)" "INFO"
                Write-Log "    - Current physical RAM: $totalRAMGB GB" "INFO"
                Write-Log "    - Run 'Optimize-PageFile' for configuration guidance" "INFO"
            }
            elseif ($totalPagefileSizeGB -gt $recommendedMaxGB * 1.5) {
                Write-Log "  [INFO] Pagefile size ($totalPagefileSizeGB GB) is larger than typical recommendation" "INFO"
                Write-Log "    - Recommended: $recommendedMinGB - $recommendedMaxGB GB (1.5-2x physical RAM)" "INFO"
                Write-Log "    - Large pagefile is fine but may use unnecessary disk space" "INFO"
            }
            else {
                Write-Log "  [OK] Pagefile size ($totalPagefileSizeGB GB) is within recommended range" "SUCCESS"
                Write-Log "    - Recommended: $recommendedMinGB - $recommendedMaxGB GB (1.5-2x physical RAM)" "INFO"
            }
        }
        else {
            if ($totalRAMGB -lt 32) {
                Write-Log "  [WARNING] No pagefile detected - this may cause issues with less than 32GB RAM" "WARNING"
                Write-Log "    - Recommended: $([math]::Round($totalRAMGB * 1.5, 1)) - $([math]::Round($totalRAMGB * 2, 1)) GB pagefile" "INFO"
            }
        }
        
        # Return structured data if requested
        if ($ReturnData) {
            return @{
                TotalRAMGB = $totalRAMGB
                ModuleCount = $ramCount
                IsDualChannel = $isDualChannel
                ChannelStatus = $channelStatus
                AverageSpeed = $avgSpeed
                IsOptimalSpeed = $isOptimalSpeed
                SpeedRating = $speedRating
                BandwidthMBps = $ramBandwidthMBps
                PagefileBandwidthMBps = $pagefileBandwidthMBps
                Rating = $rating
                Recommendation = $speedRecommendation
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to benchmark RAM: $_" "ERROR"
        return $false
    }
}

# Benchmark rendering performance with frame rate testing (CPU-based GDI+)
# NOTE: This is NOT a GPU benchmark - it uses System.Drawing (GDI+) which is CPU-rendered
# For GPU benchmarks, use: 3DMark, Unigine, GravityMark, or game-specific benchmarks
function Invoke-RenderingBenchmark {
    param(
        [switch]$ReturnData,
        [int]$TargetRefreshRate = 60
    )
    
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Rendering Performance Benchmark (CPU-Based)" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Target Refresh Rate: $TargetRefreshRate Hz" "INFO"
    Write-Log "" "INFO"
    Write-Log "[NOTE] This test uses GDI+ (CPU rendering), not GPU-accelerated rendering." "INFO"
    Write-Log "For GPU-specific performance, use dedicated tools like:" "INFO"
    Write-Log "  - 3DMark (Time Spy, Fire Strike, Speed Way)" "INFO"
    Write-Log "  - Unigine Superposition / Heaven" "INFO"
    Write-Log "  - GravityMark" "INFO"
    Write-Log "  - Game-specific benchmarks (built into many modern games)" "INFO"
    Write-Log "" "INFO"
    
    try {
        # Test parameters
        $testDurationSeconds = 30  # Increased for better accuracy
        $frameCount = 0
        $frameTimes = @()
        
        Write-Log "Running $testDurationSeconds-second rendering test..." "INFO"
        Write-Log "This simulates continuous frame rendering for gaming workloads." "INFO"
        Write-Log "" "INFO"
        
        # Add required assemblies for graphics
        Add-Type -AssemblyName System.Drawing
        Add-Type -AssemblyName System.Windows.Forms
        
        # Create bitmap for rendering (simulates game rendering buffer)
        $width = 1920
        $height = 1080
        $bitmap = New-Object System.Drawing.Bitmap($width, $height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        
        # Random number generator for varied rendering
        $random = New-Object System.Random
        
        # Rendering loop
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($testDurationSeconds)
        $lastProgressUpdate = $startTime
        $recentFrameTimes = @()
        
        Write-Log "Rendering frames..." "INFO"
        
        while ((Get-Date) -lt $endTime) {
            $frameStart = Get-Date
            
            # Simulate game rendering workload
            # 1. Clear buffer (every game does this)
            $graphics.Clear([System.Drawing.Color]::Black)
            
            # 2. Draw multiple objects (simulates game scene)
            for ($i = 0; $i -lt 100; $i++) {
                $x = $random.Next(0, $width)
                $y = $random.Next(0, $height)
                $size = $random.Next(10, 50)
                $color = [System.Drawing.Color]::FromArgb(
                    $random.Next(0, 255),
                    $random.Next(0, 255),
                    $random.Next(0, 255)
                )
                $brush = New-Object System.Drawing.SolidBrush($color)
                $graphics.FillEllipse($brush, $x, $y, $size, $size)
                $brush.Dispose()
            }
            
            # 3. Draw text overlays (simulates HUD)
            $font = New-Object System.Drawing.Font("Arial", 16)
            $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
            $graphics.DrawString("Frame: $frameCount", $font, $textBrush, 10, 10)
            $font.Dispose()
            $textBrush.Dispose()
            
            # 4. Simulate buffer flush (Force GDI+ to complete rendering)
            $graphics.Flush([System.Drawing.Drawing2D.FlushIntention]::Sync)
            
            $frameEnd = Get-Date
            $frameTime = ($frameEnd - $frameStart).TotalMilliseconds
            $frameTimes += $frameTime
            $frameCount++
            
            # Update progress every 0.25 seconds - two bars: test progress + dynamic FPS gauge
            $timeSinceUpdate = ($frameEnd - $lastProgressUpdate).TotalSeconds
            if ($timeSinceUpdate -ge 0.25) {
                try {
                    $elapsed = ($frameEnd - $startTime).TotalSeconds
                    $currentFPS = [math]::Round($frameCount / $elapsed, 1)
                    $percentComplete = [math]::Round(($elapsed / $testDurationSeconds) * 100, 0)
                    $recentFrameTimes = $frameTimes | Select-Object -Last 100
                    
                    # Calculate instantaneous FPS from recent frames
                    $instantFPS = 0
                    if ($recentFrameTimes.Count -gt 0) {
                        $recentAvg = ($recentFrameTimes | Measure-Object -Average).Average
                        $instantFPS = if ($recentAvg -gt 0) { [math]::Round(1000 / $recentAvg, 0) } else { 0 }
                    }
                    
                    # Create RPM-style gauge showing current FPS vs target (can go up/down)
                    $fpsPercent = [math]::Min([math]::Round(($instantFPS / $TargetRefreshRate) * 100, 0), 150)
                    $filledLength = [math]::Min([math]::Round($fpsPercent / 3, 0), 50)
                    $emptyLength = 50 - $filledLength
                    $gaugeBar = "#" * $filledLength + "." * $emptyLength
                    
                    # Primary: test completion progress
                    Write-Progress -Id 2001 -Activity "Rendering Performance Test" -Status "Progress: $percentComplete%" -PercentComplete $percentComplete
                    
                    # Secondary: dynamic FPS gauge (progress API caps at 100%)
                    $fpsPercentForProgress = [math]::Min($fpsPercent, 100)
                    Write-Progress -Id 2002 -Activity "FPS Gauge" -Status "Inst: $instantFPS FPS | Avg: $currentFPS FPS" -CurrentOperation "[$gaugeBar] Target: $TargetRefreshRate Hz" -PercentComplete $fpsPercentForProgress
                    $lastProgressUpdate = $frameEnd
                } catch {
                    # Silently skip progress update if there's an issue; rendering continues
                    Write-Debug "Rendering progress update failed (non-fatal): $_"
                }
            }
        }
        
        Write-Progress -Id 2001 -Activity "Rendering Performance Test" -Completed
        Write-Progress -Id 2002 -Activity "FPS Gauge" -Completed
        
        # Cleanup
        $graphics.Dispose()
        $bitmap.Dispose()
        
        $actualDuration = ((Get-Date) - $startTime).TotalSeconds
        
        # Calculate statistics
        $averageFPS = [math]::Round($frameCount / $actualDuration, 2)
        $averageFrameTime = [math]::Round(($frameTimes | Measure-Object -Average).Average, 2)
        $minFrameTime = [math]::Round(($frameTimes | Measure-Object -Minimum).Minimum, 2)
        $maxFrameTime = [math]::Round(($frameTimes | Measure-Object -Maximum).Maximum, 2)
        
        # Calculate 1% low and 0.1% low (industry standard metrics)
        $sortedFrameTimes = $frameTimes | Sort-Object -Descending
        $onePercentIndex = [math]::Floor($frameCount * 0.01)
        $pointOnePercentIndex = [math]::Floor($frameCount * 0.001)
        
        if ($onePercentIndex -lt $sortedFrameTimes.Count -and $onePercentIndex -ge 0) {
            $onePercentLowFrameTime = $sortedFrameTimes[$onePercentIndex]
            $onePercentLowFPS = [math]::Round(1000 / $onePercentLowFrameTime, 2)
        } else {
            $onePercentLowFrameTime = $maxFrameTime
            $onePercentLowFPS = [math]::Round(1000 / $maxFrameTime, 2)
        }
        
        if ($pointOnePercentIndex -lt $sortedFrameTimes.Count -and $pointOnePercentIndex -ge 0) {
            $pointOnePercentLowFrameTime = $sortedFrameTimes[$pointOnePercentIndex]
            $pointOnePercentLowFPS = [math]::Round(1000 / $pointOnePercentLowFrameTime, 2)
        } else {
            $pointOnePercentLowFrameTime = $maxFrameTime
            $pointOnePercentLowFPS = [math]::Round(1000 / $maxFrameTime, 2)
        }
        
        # Calculate max/min FPS
        $maxFPS = [math]::Round(1000 / $minFrameTime, 2)
        $minFPS = [math]::Round(1000 / $maxFrameTime, 2)
        
        # Display results
        Write-Log "" "INFO"
        Write-Log "Rendering Test Results ($frameCount frames rendered):" "INFO"
        Write-Log "  Average FPS: $averageFPS" "SUCCESS"
        Write-Log "  Max FPS: $maxFPS" "SUCCESS"
        Write-Log "  Min FPS: $minFPS" "SUCCESS"
        Write-Log "" "INFO"
        Write-Log "Frame Time Consistency:" "INFO"
        Write-Log "  Average: ${averageFrameTime}ms" "SUCCESS"
        Write-Log "  Best: ${minFrameTime}ms" "SUCCESS"
        Write-Log "  Worst: ${maxFrameTime}ms" "SUCCESS"
        Write-Log "" "INFO"
        Write-Log "1% Low Metrics (critical for gaming smoothness):" "INFO"
        Write-Log "  1% Low FPS: $onePercentLowFPS (${onePercentLowFrameTime}ms)" "SUCCESS"
        Write-Log "  0.1% Low FPS: $pointOnePercentLowFPS (${pointOnePercentLowFrameTime}ms)" "SUCCESS"
        
        # Visual FPS performance bars
        Write-Log "" "INFO"
        Write-Host "  FPS Performance Visualization (vs $TargetRefreshRate Hz target):" -ForegroundColor Yellow
        
        # Average FPS bar (compare against monitor refresh rate)
        $avgFPSPercent = [math]::Min([math]::Round(($averageFPS / $TargetRefreshRate) * 100, 0), 150)  # Allow up to 150% for displays that exceed target
        $avgFPSBarLength = [math]::Min([math]::Round($avgFPSPercent / 3, 0), 50)  # Scale to 50 char max
        $avgFPSBar = "#" * $avgFPSBarLength + "." * (50 - $avgFPSBarLength)
        $avgColor = if ($averageFPS -ge $TargetRefreshRate) { "Green" } elseif ($averageFPS -ge ($TargetRefreshRate * 0.8)) { "Yellow" } else { "Red" }
        Write-Host "  Avg FPS:  [$avgFPSBar] $averageFPS FPS ($([math]::Round(($averageFPS / $TargetRefreshRate) * 100, 0))% of target)" -ForegroundColor $avgColor
        
        # 1% Low bar (should be close to refresh rate for smooth experience)
        $lowTarget = [math]::Max($TargetRefreshRate * 0.85, 60)  # Target 85% of refresh rate or 60 FPS minimum
        $lowPercent = [math]::Min([math]::Round(($onePercentLowFPS / $lowTarget) * 100, 0), 150)
        $lowBarLength = [math]::Min([math]::Round($lowPercent / 3, 0), 50)
        $lowBar = "#" * $lowBarLength + "." * (50 - $lowBarLength)
        $lowColor = if ($onePercentLowFPS -ge $lowTarget) { "Green" } elseif ($onePercentLowFPS -ge ($lowTarget * 0.75)) { "Yellow" } else { "Red" }
        Write-Host "  1% Low:   [$lowBar] $onePercentLowFPS FPS ($([math]::Round(($onePercentLowFPS / $lowTarget) * 100, 0))% of $([math]::Round($lowTarget, 0)) target)" -ForegroundColor $lowColor
        
        # 0.1% Low bar
        $pointOneLowTarget = [math]::Max($TargetRefreshRate * 0.75, 50)  # Target 75% of refresh rate or 50 FPS minimum
        $pointOneLowPercent = [math]::Min([math]::Round(($pointOnePercentLowFPS / $pointOneLowTarget) * 100, 0), 150)
        $pointOneLowBarLength = [math]::Min([math]::Round($pointOneLowPercent / 3, 0), 50)
        $pointOneLowBar = "#" * $pointOneLowBarLength + "." * (50 - $pointOneLowBarLength)
        $pointOneLowColor = if ($pointOnePercentLowFPS -ge $pointOneLowTarget) { "Green" } elseif ($pointOnePercentLowFPS -ge ($pointOneLowTarget * 0.75)) { "Yellow" } else { "Red" }
        Write-Host "  0.1% Low: [$pointOneLowBar] $pointOnePercentLowFPS FPS ($([math]::Round(($pointOnePercentLowFPS / $pointOneLowTarget) * 100, 0))% of $([math]::Round($pointOneLowTarget, 0)) target)" -ForegroundColor $pointOneLowColor
        
        # Rating
        Write-Log "" "INFO"
        $rating = ""
        
        # Rating based on refresh rate target and 1% lows
        if ($averageFPS -ge $TargetRefreshRate -and $onePercentLowFPS -ge ($TargetRefreshRate * 0.85)) {
            $rating = "EXCELLENT"
            Write-Log "[EXCELLENT] Performance matches your $TargetRefreshRate Hz display - smooth high-refresh gaming" "SUCCESS"
        } elseif ($averageFPS -ge ($TargetRefreshRate * 0.85) -and $onePercentLowFPS -ge ($TargetRefreshRate * 0.70)) {
            $rating = "GOOD"
            Write-Log "[GOOD] Performance is close to your $TargetRefreshRate Hz target - mostly smooth" "SUCCESS"
        } elseif ($averageFPS -ge 60 -and $onePercentLowFPS -ge 50) {
            $rating = "FAIR"
            Write-Log "[FAIR] Performance is acceptable but not utilizing your $TargetRefreshRate Hz display fully" "INFO"
        } else {
            $rating = "WARNING"
            Write-Log "[WARNING] Performance below $TargetRefreshRate Hz target - consider optimization or settings adjustment" "WARNING"
        }
        
        if ($ReturnData) {
            return @{
                FramesRendered = $frameCount
                TestDuration = [math]::Round($actualDuration, 2)
                AverageFPS = $averageFPS
                MaxFPS = $maxFPS
                MinFPS = $minFPS
                AverageFrameTime = $averageFrameTime
                MinFrameTime = $minFrameTime
                MaxFrameTime = $maxFrameTime
                OnePercentLowFPS = $onePercentLowFPS
                PointOnePercentLowFPS = $pointOnePercentLowFPS
                Rating = $rating
            }
        }
        return $true
    }
    catch {
        Write-Log "Failed to benchmark rendering: $_" "ERROR"
        # If ReturnData was requested, return at least placeholder data so results object isn't null
        if ($ReturnData) {
            return @{
                FramesRendered = 0
                TestDuration = 0
                AverageFPS = 0
                MaxFPS = 0
                MinFPS = 0
                AverageFrameTime = 0
                MinFrameTime = 0
                MaxFrameTime = 0
                OnePercentLowFPS = 0
                PointOnePercentLowFPS = 0
                Rating = "ERROR"
            }
        }
        return $false
    }
}

# Load benchmark results from JSON file
function Import-BenchmarkResults {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Log "No baseline benchmark results found at: $FilePath" "WARNING"
            return $null
        }
        
        $json = Get-Content -Path $FilePath -Raw
        $results = $json | ConvertFrom-Json
        Write-Log "Loaded benchmark results from: $FilePath" "SUCCESS"
        return $results
    }
    catch {
        Write-Log "Failed to load benchmark results: $_" "ERROR"
        return $null
    }
}

# Compare before and after benchmark results
function Compare-BenchmarkResults {
    param(
        [Parameter(Mandatory=$true)]
        $BeforeResults,
        [Parameter(Mandatory=$true)]
        $AfterResults
    )
    
    Write-Log "" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "BENCHMARK COMPARISON REPORT" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "" "INFO"
    Write-Log "Baseline: $($BeforeResults.Timestamp) on $($BeforeResults.ComputerName)" "INFO"
    Write-Log "Current:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME" "INFO"
    Write-Log "" "INFO"
    
    # Extract Results from both before and after
    # BeforeResults comes from JSON (PSCustomObject with Results property)
    # AfterResults comes from Invoke-PerformanceBenchmark (hashtable, no Results wrapper)
    $before = $BeforeResults.Results
    $after = if ($AfterResults -is [hashtable]) { 
        $AfterResults  # Already flat structure
    } elseif ($AfterResults.PSObject.Properties.Name -contains 'Results') { 
        $AfterResults.Results  # Has Results wrapper
    } else { 
        $AfterResults  # Fallback
    }
    
    Write-Debug "AfterResults type: $($AfterResults.GetType().FullName)"
    Write-Debug "after type: $($after.GetType().FullName)"

    # Track GPU delta metrics for summary
    $gmFpsChange = $null
    $gmScoreChange = $null
    $gmOneLowChange = $null
    $gmPointOneLowChange = $null

    # Normalize rendering objects (support legacy key name and both PSCustomObject and Hashtable)
    # Check both with PSObject (for PSCustomObject) and ContainsKey (for hashtable)
    $beforeRendering = $null
    if ($before -is [hashtable] -and $before.ContainsKey('GPURendering')) { 
        $beforeRendering = $before['GPURendering'] 
    } elseif ($before -is [hashtable] -and $before.ContainsKey('Rendering')) { 
        $beforeRendering = $before['Rendering'] 
    } elseif ($before.PSObject.Properties.Name -contains 'GPURendering') { 
        $beforeRendering = $before.GPURendering 
    } elseif ($before.PSObject.Properties.Name -contains 'Rendering') { 
        $beforeRendering = $before.Rendering 
    }
    
    $afterRendering = $null
    if ($after -is [hashtable] -and $after.ContainsKey('GPURendering')) { 
        $afterRendering = $after['GPURendering'] 
    } elseif ($after -is [hashtable] -and $after.ContainsKey('Rendering')) { 
        $afterRendering = $after['Rendering'] 
    } elseif ($after.PSObject.Properties.Name -contains 'GPURendering') { 
        $afterRendering = $after.GPURendering 
    } elseif ($after.PSObject.Properties.Name -contains 'Rendering') { 
        $afterRendering = $after.Rendering 
    }
    
    Write-Debug "beforeRendering exists: $($null -ne $beforeRendering)"
    Write-Debug "afterRendering exists: $($null -ne $afterRendering)"
    if ($beforeRendering) { Write-Debug "beforeRendering type: $($beforeRendering.GetType().FullName)" }
    if ($afterRendering) { Write-Debug "afterRendering type: $($afterRendering.GetType().FullName)" }
    
    # CPU Comparison
    Write-Log "========================================" "INFO"
    Write-Log "CPU Performance" "INFO"
    Write-Log "========================================" "INFO"
    
    $cpuHashChange = (($after.CPU.HashesPerSecond - $before.CPU.HashesPerSecond) / $before.CPU.HashesPerSecond) * 100
    $cpuOpsChange = (($after.CPU.MathOpsPerSecond - $before.CPU.MathOpsPerSecond) / $before.CPU.MathOpsPerSecond) * 100
    
    Write-Log "Hash Performance:" "INFO"
    Write-Log "  Before: $($before.CPU.HashesPerSecond) hashes/sec" "INFO"
    Write-Log "  After:  $($after.CPU.HashesPerSecond) hashes/sec" "INFO"
    Write-Log "  Change: $([math]::Round($cpuHashChange, 2))%" $(if ($cpuHashChange -gt 0) { "SUCCESS" } elseif ($cpuHashChange -lt -5) { "WARNING" } else { "INFO" })
    
    Write-Log "Math Operations:" "INFO"
    Write-Log "  Before: $($before.CPU.MathOpsPerSecond) ops/sec" "INFO"
    Write-Log "  After:  $($after.CPU.MathOpsPerSecond) ops/sec" "INFO"
    Write-Log "  Change: $([math]::Round($cpuOpsChange, 2))%" $(if ($cpuOpsChange -gt 0) { "SUCCESS" } elseif ($cpuOpsChange -lt -5) { "WARNING" } else { "INFO" })
    Write-Log "" "INFO"
    
    # Disk Comparison
    Write-Log "========================================" "INFO"
    Write-Log "Disk Performance" "INFO"
    Write-Log "========================================" "INFO"
    
    $diskReadChange = (($after.Disk.ReadMBps - $before.Disk.ReadMBps) / $before.Disk.ReadMBps) * 100
    $diskWriteChange = (($after.Disk.WriteMBps - $before.Disk.WriteMBps) / $before.Disk.WriteMBps) * 100
    
    Write-Log "Read Speed:" "INFO"
    Write-Log "  Before: $($before.Disk.ReadMBps) MB/s" "INFO"
    Write-Log "  After:  $($after.Disk.ReadMBps) MB/s" "INFO"
    Write-Log "  Change: $([math]::Round($diskReadChange, 2))%" $(if ($diskReadChange -gt 0) { "SUCCESS" } elseif ($diskReadChange -lt -5) { "WARNING" } else { "INFO" })
    
    Write-Log "Write Speed:" "INFO"
    Write-Log "  Before: $($before.Disk.WriteMBps) MB/s" "INFO"
    Write-Log "  After:  $($after.Disk.WriteMBps) MB/s" "INFO"
    Write-Log "  Change: $([math]::Round($diskWriteChange, 2))%" $(if ($diskWriteChange -gt 0) { "SUCCESS" } elseif ($diskWriteChange -lt -5) { "WARNING" } else { "INFO" })
    Write-Log "" "INFO"
    
    # Network Comparison
    Write-Log "========================================" "INFO"
    Write-Log "Network Performance" "INFO"
    Write-Log "========================================" "INFO"
    
    # For latency, lower is better, so we invert the change percentage
    $latencyChange = (($before.Network.AvgLatency - $after.Network.AvgLatency) / $before.Network.AvgLatency) * 100
    $dnsChange = (($before.Network.AvgDNSResolution - $after.Network.AvgDNSResolution) / $before.Network.AvgDNSResolution) * 100
    
    Write-Log "Network Latency:" "INFO"
    Write-Log "  Before: $($before.Network.AvgLatency) ms" "INFO"
    Write-Log "  After:  $($after.Network.AvgLatency) ms" "INFO"
    $latencyText = if ($latencyChange -eq 0) { '(no change)' } elseif ($latencyChange -gt 0) { '(lower is better)' } else { '(higher latency)' }
    Write-Log "  Change: $([math]::Round($latencyChange, 2))% $latencyText" $(if ($latencyChange -gt 0) { "SUCCESS" } elseif ($latencyChange -lt -10) { "WARNING" } else { "INFO" })
    
    Write-Log "DNS Resolution:" "INFO"
    Write-Log "  Before: $($before.Network.AvgDNSResolution) ms" "INFO"
    Write-Log "  After:  $($after.Network.AvgDNSResolution) ms" "INFO"
    $dnsText = if ($dnsChange -eq 0) { '(no change)' } elseif ($dnsChange -gt 0) { '(faster)' } else { '(slower)' }
    Write-Log "  Change: $([math]::Round($dnsChange, 2))% $dnsText" $(if ($dnsChange -gt 0) { "SUCCESS" } elseif ($dnsChange -lt -10) { "WARNING" } else { "INFO" })
    
    # Internet speed comparison (if available)
    if ($before.Network.PSObject.Properties.Name -contains 'DownloadSpeed' -and $after.Network.DownloadSpeed -gt 0) {
        $downloadChange = (($after.Network.DownloadSpeed - $before.Network.DownloadSpeed) / $before.Network.DownloadSpeed) * 100
        Write-Log "Download Speed:" "INFO"
        Write-Log "  Before: $($before.Network.DownloadSpeed) Mbps" "INFO"
        Write-Log "  After:  $($after.Network.DownloadSpeed) Mbps" "INFO"
        Write-Log "  Change: $([math]::Round($downloadChange, 2))%" $(if ($downloadChange -gt 5) { "SUCCESS" } elseif ($downloadChange -lt -5) { "WARNING" } else { "INFO" })
    }
    
    if ($before.Network.PSObject.Properties.Name -contains 'UploadSpeed' -and $after.Network.UploadSpeed -gt 0) {
        $uploadChange = (($after.Network.UploadSpeed - $before.Network.UploadSpeed) / $before.Network.UploadSpeed) * 100
        Write-Log "Upload Speed:" "INFO"
        Write-Log "  Before: $($before.Network.UploadSpeed) Mbps" "INFO"
        Write-Log "  After:  $($after.Network.UploadSpeed) Mbps" "INFO"
        Write-Log "  Change: $([math]::Round($uploadChange, 2))%" $(if ($uploadChange -gt 5) { "SUCCESS" } elseif ($uploadChange -lt -5) { "WARNING" } else { "INFO" })
    }
    Write-Log "" "INFO"
    
    # GPU Comparison
    Write-Log "========================================" "INFO"
    Write-Log "GPU Performance & Configuration" "INFO"
    Write-Log "========================================" "INFO"

    # Performance (GravityMark) if captured
    $beforePointOne = if ($beforeRendering) { $beforeRendering.PointOnePercentLowFPS } else { $null }
    $afterPointOne = if ($afterRendering) { $afterRendering.PointOnePercentLowFPS } else { $null }

    # Debug: Log what we have
    Write-Debug "beforeRendering exists: $($null -ne $beforeRendering)"
    Write-Debug "afterRendering exists: $($null -ne $afterRendering)"
    if ($beforeRendering) {
        Write-Debug "beforeRendering.TestRun: $($beforeRendering.TestRun)"
        Write-Debug "beforeRendering.FPS: $($beforeRendering.FPS)"
    }
    if ($afterRendering) {
        Write-Debug "afterRendering.TestRun: $($afterRendering.TestRun)"
        Write-Debug "afterRendering.FPS: $($afterRendering.FPS)"
    }

    # Check if GPU performance data exists - support both hashtable and PSCustomObject
    $hasGpuPerf = $false
    if ($beforeRendering -and $afterRendering) {
        # Check if either benchmark was run (TestRun flag OR FPS data exists)
        # Handle both hashtable and PSCustomObject
        $beforeHasData = $false
        $afterHasData = $false
        
        if ($beforeRendering -is [hashtable]) {
            $beforeHasData = ($beforeRendering.ContainsKey('TestRun') -and $beforeRendering['TestRun']) -or 
                             ($beforeRendering.ContainsKey('FPS') -and $beforeRendering['FPS'] -gt 0)
        } else {
            $beforeHasData = ($beforeRendering.PSObject.Properties.Name -contains 'TestRun' -and $beforeRendering.TestRun) -or 
                             ($beforeRendering.PSObject.Properties.Name -contains 'FPS' -and $beforeRendering.FPS -gt 0)
        }
        
        if ($afterRendering -is [hashtable]) {
            $afterHasData = ($afterRendering.ContainsKey('TestRun') -and $afterRendering['TestRun']) -or 
                            ($afterRendering.ContainsKey('FPS') -and $afterRendering['FPS'] -gt 0)
        } else {
            $afterHasData = ($afterRendering.PSObject.Properties.Name -contains 'TestRun' -and $afterRendering.TestRun) -or 
                            ($afterRendering.PSObject.Properties.Name -contains 'FPS' -and $afterRendering.FPS -gt 0)
        }
        
        Write-Debug "beforeHasData: $beforeHasData | afterHasData: $afterHasData"
        $hasGpuPerf = $beforeHasData -or $afterHasData
    }
    
    Write-Debug "hasGpuPerf final: $hasGpuPerf"

    if ($hasGpuPerf) {
        # Helper function to safely get values from hashtable or PSCustomObject
        function Get-SafeValue($obj, $key) {
            if ($obj -is [hashtable]) { return $obj[$key] }
            else { return $obj.$key }
        }
        
        # Calculate changes
        $beforeFps = Get-SafeValue $beforeRendering 'FPS'
        $afterFps = Get-SafeValue $afterRendering 'FPS'
        $beforeScore = Get-SafeValue $beforeRendering 'Score'
        $afterScore = Get-SafeValue $afterRendering 'Score'
        $beforeOneLow = Get-SafeValue $beforeRendering 'OnePercentLowFPS'
        $afterOneLow = Get-SafeValue $afterRendering 'OnePercentLowFPS'
        
        if ($beforeFps -gt 0) { $gmFpsChange = (($afterFps - $beforeFps) / $beforeFps) * 100 }
        if ($beforeScore -gt 0) { $gmScoreChange = (($afterScore - $beforeScore) / $beforeScore) * 100 }
        if ($beforeOneLow -gt 0) { $gmOneLowChange = (($afterOneLow - $beforeOneLow) / $beforeOneLow) * 100 }
        if ($beforePointOne -gt 0) { $gmPointOneLowChange = (($afterPointOne - $beforePointOne) / $beforePointOne) * 100 }

        Write-Log "GravityMark FPS:" "INFO"
        Write-Log "  Before: $beforeFps" "INFO"
        Write-Log "  After:  $afterFps" "INFO"
        $gmFpsChangeText = "N/A (no baseline)"
        if ($gmFpsChange -is [double]) { $gmFpsChangeText = "$([math]::Round($gmFpsChange, 2))%" }
        Write-Log "  Change: $gmFpsChangeText" $(if ($gmFpsChange -gt 0) { "SUCCESS" } elseif ($gmFpsChange -lt -5) { "WARNING" } else { "INFO" })

        if ($beforeScore -gt 0 -or $afterScore -gt 0) {
            Write-Log "GravityMark Score:" "INFO"
            Write-Log "  Before: $beforeScore" "INFO"
            Write-Log "  After:  $afterScore" "INFO"
            $gmScoreChangeText = "N/A (no baseline)"
            if ($gmScoreChange -is [double]) { $gmScoreChangeText = "$([math]::Round($gmScoreChange, 2))%" }
            Write-Log "  Change: $gmScoreChangeText" $(if ($gmScoreChange -gt 0) { "SUCCESS" } elseif ($gmScoreChange -lt -5) { "WARNING" } else { "INFO" })
        }

        if ($beforeOneLow -gt 0 -or $afterOneLow -gt 0) {
            Write-Log "GravityMark 1% Low:" "INFO"
            Write-Log "  Before: $beforeOneLow" "INFO"
            Write-Log "  After:  $afterOneLow" "INFO"
            $gmOneLowChangeText = "N/A (no baseline)"
            if ($gmOneLowChange -is [double]) { $gmOneLowChangeText = "$([math]::Round($gmOneLowChange, 2))%" }
            Write-Log "  Change: $gmOneLowChangeText" $(if ($gmOneLowChange -gt 0) { "SUCCESS" } elseif ($gmOneLowChange -lt -5) { "WARNING" } else { "INFO" })
        }

        if ($beforePointOne -gt 0 -or $afterPointOne -gt 0) {
            Write-Log "GravityMark 0.1% Low:" "INFO"
            Write-Log "  Before: $beforePointOne" "INFO"
            Write-Log "  After:  $afterPointOne" "INFO"
            $gmPointOneChangeText = "N/A (no baseline)"
            if ($gmPointOneLowChange -is [double]) { $gmPointOneChangeText = "$([math]::Round($gmPointOneLowChange, 2))%" }
            Write-Log "  Change: $gmPointOneChangeText" $(if ($gmPointOneLowChange -gt 0) { "SUCCESS" } elseif ($gmPointOneLowChange -lt -5) { "WARNING" } else { "INFO" })
        }

        Write-Log "" "INFO"
    }
    
    Write-Log "Hardware-Accelerated GPU Scheduling (HAGS):" "INFO"
    Write-Log "  Before: $(if ($before.GPU.HAGSEnabled) { 'ENABLED' } else { 'DISABLED' })" "INFO"
    Write-Log "  After:  $(if ($after.GPU.HAGSEnabled) { 'ENABLED' } else { 'DISABLED' })" "INFO"
    if ($before.GPU.HAGSEnabled -ne $after.GPU.HAGSEnabled) {
        if ($after.GPU.HAGSEnabled) {
            Write-Log "  Change: HAGS was enabled" "SUCCESS"
        } else {
            Write-Log "  Change: HAGS was disabled" "WARNING"
        }
    } else {
        Write-Log "  Change: No change" "INFO"
    }
    Write-Log "" "INFO"
    
    # Summary
    Write-Log "==========================================" "INFO"
    Write-Log "SUMMARY" "INFO"
    Write-Log "==========================================" "INFO"
    
    $improvements = @()
    $degradations = @()
    
    if ($cpuHashChange -gt 2) { $improvements += "CPU Hash: +$([math]::Round($cpuHashChange, 1))%" }
    elseif ($cpuHashChange -lt -2) { $degradations += "CPU Hash: $([math]::Round($cpuHashChange, 1))%" }
    
    if ($cpuOpsChange -gt 2) { $improvements += "CPU Math: +$([math]::Round($cpuOpsChange, 1))%" }
    elseif ($cpuOpsChange -lt -2) { $degradations += "CPU Math: $([math]::Round($cpuOpsChange, 1))%" }
    
    if ($diskReadChange -gt 2) { $improvements += "Disk Read: +$([math]::Round($diskReadChange, 1))%" }
    elseif ($diskReadChange -lt -2) { $degradations += "Disk Read: $([math]::Round($diskReadChange, 1))%" }
    
    if ($diskWriteChange -gt 2) { $improvements += "Disk Write: +$([math]::Round($diskWriteChange, 1))%" }
    elseif ($diskWriteChange -lt -2) { $degradations += "Disk Write: $([math]::Round($diskWriteChange, 1))%" }
    
    if ($latencyChange -gt 2) { $improvements += "Network Latency: -$([math]::Round($latencyChange, 1))%" }
    elseif ($latencyChange -lt -2) { $degradations += "Network Latency: +$([math]::Abs([math]::Round($latencyChange, 1)))%" }
    
    if ($dnsChange -gt 2) { $improvements += "DNS Resolution: -$([math]::Round($dnsChange, 1))%" }
    elseif ($dnsChange -lt -2) { $degradations += "DNS Resolution: +$([math]::Abs([math]::Round($dnsChange, 1)))%" }
    
    if ($downloadChange -gt 2) { $improvements += "Download Speed: +$([math]::Round($downloadChange, 1))%" }
    elseif ($downloadChange -lt -2) { $degradations += "Download Speed: $([math]::Round($downloadChange, 1))%" }
    
    if ($uploadChange -gt 2) { $improvements += "Upload Speed: +$([math]::Round($uploadChange, 1))%" }
    elseif ($uploadChange -lt -2) { $degradations += "Upload Speed: $([math]::Round($uploadChange, 1))%" }
    
    # GravityMark GPU benchmark improvements (lower threshold since GPU benchmarks are highly consistent)
    if ($gmFpsChange -is [double]) {
        if ($gmFpsChange -gt 0.5) { $improvements += "GravityMark FPS: +$([math]::Round($gmFpsChange, 1))%" }
        elseif ($gmFpsChange -lt -0.5) { $degradations += "GravityMark FPS: $([math]::Round($gmFpsChange, 1))%" }
    }
    
    if ($gmScoreChange -is [double]) {
        if ($gmScoreChange -gt 0.5) { $improvements += "GravityMark Score: +$([math]::Round($gmScoreChange, 1))%" }
        elseif ($gmScoreChange -lt -0.5) { $degradations += "GravityMark Score: $([math]::Round($gmScoreChange, 1))%" }
    }
    
    if ($gmOneLowChange -is [double]) {
        if ($gmOneLowChange -gt 0.5) { $improvements += "GravityMark 1% Low: +$([math]::Round($gmOneLowChange, 1))%" }
        elseif ($gmOneLowChange -lt -0.5) { $degradations += "GravityMark 1% Low: $([math]::Round($gmOneLowChange, 1))%" }
    }
    
    if ($gmPointOneLowChange -is [double]) {
        if ($gmPointOneLowChange -gt 0.5) { $improvements += "GravityMark 0.1% Low: +$([math]::Round($gmPointOneLowChange, 1))%" }
        elseif ($gmPointOneLowChange -lt -0.5) { $degradations += "GravityMark 0.1% Low: $([math]::Round($gmPointOneLowChange, 1))%" }
    }
    
    if ($after.GPU.HAGSEnabled -and -not $before.GPU.HAGSEnabled) {
        $improvements += "HAGS Enabled"
    }
    
    if ($improvements.Count -gt 0) {
        Write-Log "Improvements:" "SUCCESS"
        foreach ($improvement in $improvements) {
            Write-Log "  + $improvement" "SUCCESS"
        }
    }
    
    if ($degradations.Count -gt 0) {
        Write-Log "" "INFO"
        Write-Log "Degradations:" "WARNING"
        foreach ($degradation in $degradations) {
            Write-Log "  - $degradation" "WARNING"
        }
    }
    
    if ($improvements.Count -eq 0 -and $degradations.Count -eq 0) {
        Write-Log "No significant changes detected (< 2% variance)" "INFO"
    }
    
    Write-Log "" "INFO"
    Write-Log "==========================================" "INFO"
}

# Run all performance benchmarks
function Invoke-PerformanceBenchmark {
    param([switch]$ReturnData)
    
    Write-Log "" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "GAMING SYSTEM PERFORMANCE BENCHMARK" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "" "INFO"
    
    # Determine which benchmarks to run
    $runAll = -not ($script:BenchmarkCPU -or $script:BenchmarkDisk -or $script:BenchmarkNetwork -or $script:BenchmarkGPU -or $script:BenchmarkRAM)
    $runCPU = $runAll -or $script:BenchmarkCPU
    $runDisk = $runAll -or $script:BenchmarkDisk
    $runNetwork = $runAll -or $script:BenchmarkNetwork
    $runGPU = $runAll -or $script:BenchmarkGPU
    $runRAM = $runAll -or $script:BenchmarkRAM
    
    if (-not $runAll) {
        Write-Log "Running selected benchmarks only:" "INFO"
        if ($runCPU) { Write-Log "  - CPU" "INFO" }
        if ($runRAM) { Write-Log "  - RAM" "INFO" }
        if ($runDisk) { Write-Log "  - Disk" "INFO" }
        if ($runNetwork) { Write-Log "  - Network" "INFO" }
        if ($runGPU) { Write-Log "  - GPU" "INFO" }
        Write-Log "" "INFO"
    }
    
    $startTime = Get-Date
    
    # Run all benchmarks
    if ($ReturnData) {
        $results = @{}
        
        if ($runCPU) {
            $results['CPU'] = Invoke-CPUBenchmark -ReturnData
        }
        if ($runRAM) {
            $results['RAM'] = Invoke-RAMBenchmark -ReturnData
        }
        if ($runDisk) {
            $results['Disk'] = Invoke-DiskBenchmark -ReturnData
        }
        if ($runNetwork) {
            $results['Network'] = Invoke-NetworkBenchmark -ReturnData
        }
        
        # GPU Analysis and Rendering Benchmark (grouped together)
        if ($runGPU) {
            $gpuData = Invoke-GPUBenchmark -ReturnData
            $results['GPU'] = $gpuData
            
            Write-Host "`n" -NoNewline
            Write-Host "===============================================" -ForegroundColor Yellow
            Write-Host "Optional: GPU Rendering Benchmark (3D Stress Test)" -ForegroundColor Yellow
            Write-Host "===============================================" -ForegroundColor Yellow
            $results['GPURendering'] = Invoke-GPURenderingBenchmark -ReturnData -SkipPrompt:(-not $runAll)
        }

        # If we captured NVIDIA telemetry during GravityMark, use it for the GPU "under load" fields.
        try {
            $gr = $results['GPURendering']
            if ($gr -and $gr.TestRun -and $results['GPU']) {
                if ($gr.GpuClockAvgMHz -and [int]$gr.GpuClockAvgMHz -gt 0) {
                    $results['GPU']['ClockSpeedUnderLoad'] = [int]$gr.GpuClockAvgMHz
                }
                if ($gr.GpuMaxClockMHz -and [int]$gr.GpuMaxClockMHz -gt 0) {
                    $results['GPU']['MaxClockSpeed'] = [int]$gr.GpuMaxClockMHz
                }
                if ($gr.GpuUtilMax -and [int]$gr.GpuUtilMax -gt 0) {
                    $results['GPU']['Utilization'] = [math]::Max([int]$results['GPU']['Utilization'], [int]$gr.GpuUtilMax)
                }
                if ($gr.GpuTempMax -and [int]$gr.GpuTempMax -gt 0) {
                    $results['GPU']['Temperature'] = [math]::Max([int]$results['GPU']['Temperature'], [int]$gr.GpuTempMax)
                }
                if ($gr.GpuPowerMaxW -and [double]$gr.GpuPowerMaxW -gt 0) {
                    $results['GPU']['PowerDraw'] = [math]::Max([double]$results['GPU']['PowerDraw'], [double]$gr.GpuPowerMaxW)
                }
            }
        } catch {}
        
        $endTime = Get-Date
        $totalDuration = ($endTime - $startTime).TotalSeconds
        
        Write-Log "" "INFO"
        Write-Log "==========================================" "INFO"
        Write-Log "Benchmark completed in $([math]::Round($totalDuration, 1)) seconds" "SUCCESS"
        Write-Log "==========================================" "INFO"
        Write-Log "" "INFO"
        
        # Display comprehensive results summary
        Show-PerformanceSummary -Results $results

        # Persist benchmark results for later comparison
        try {
            $timestamp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format "yyyyMMdd-HHmmss" }
            $outDir = $ResultsPath
            if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
            $outFile = Join-Path $outDir "Gaming-Optimization-Benchmark-$timestamp.json"
            $results | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8
            Write-Log "Benchmark results saved to $outFile" "INFO"
        }
        catch {
            Write-Log "Could not write benchmark results: $_" "WARNING"
        }
        
        return $results
    }
    else {
        $cpuResult = if ($runCPU) { Invoke-CPUBenchmark -ReturnData } else { $null }
        $ramResult = if ($runRAM) { Invoke-RAMBenchmark -ReturnData } else { $null }
        $diskResult = if ($runDisk) { Invoke-DiskBenchmark -ReturnData } else { $null }
        $networkResult = if ($runNetwork) { Invoke-NetworkBenchmark -ReturnData } else { $null }
        
        # GPU Analysis and Rendering Benchmark (grouped together)
        $gpuResult = if ($runGPU) { Invoke-GPUBenchmark -ReturnData } else { $null }
        $gpuRenderResult = if ($runGPU) { Invoke-GPURenderingBenchmark -ReturnData -SkipPrompt:(-not $runAll) } else { $null }
        
        $endTime = Get-Date
        $totalDuration = ($endTime - $startTime).TotalSeconds
        
        Write-Log "" "INFO"
        Write-Log "==========================================" "INFO"
        Write-Log "Benchmark completed in $([math]::Round($totalDuration, 1)) seconds" "SUCCESS"
        Write-Log "==========================================" "INFO"
        Write-Log "" "INFO"
        
        # Display comprehensive results summary
        $allResults = @{
            CPU = $cpuResult
            GPU = $gpuResult
            RAM = $ramResult
            Disk = $diskResult
            Network = $networkResult
            GPURendering = $gpuRenderResult
        }

        # Propagate in-run NVIDIA telemetry into the GPU summary
        try {
            if ($gpuRenderResult -and $gpuRenderResult.TestRun -and $gpuResult) {
                if ($gpuRenderResult.GpuClockAvgMHz -and [int]$gpuRenderResult.GpuClockAvgMHz -gt 0) {
                    $gpuResult.ClockSpeedUnderLoad = [int]$gpuRenderResult.GpuClockAvgMHz
                }
                if ($gpuRenderResult.GpuMaxClockMHz -and [int]$gpuRenderResult.GpuMaxClockMHz -gt 0) {
                    $gpuResult.MaxClockSpeed = [int]$gpuRenderResult.GpuMaxClockMHz
                }
                if ($gpuRenderResult.GpuUtilMax -and [int]$gpuRenderResult.GpuUtilMax -gt 0) {
                    $gpuResult.Utilization = [math]::Max([int]$gpuResult.Utilization, [int]$gpuRenderResult.GpuUtilMax)
                }
                if ($gpuRenderResult.GpuTempMax -and [int]$gpuRenderResult.GpuTempMax -gt 0) {
                    $gpuResult.Temperature = [math]::Max([int]$gpuResult.Temperature, [int]$gpuRenderResult.GpuTempMax)
                }
                if ($gpuRenderResult.GpuPowerMaxW -and [double]$gpuRenderResult.GpuPowerMaxW -gt 0) {
                    $gpuResult.PowerDraw = [math]::Max([double]$gpuResult.PowerDraw, [double]$gpuRenderResult.GpuPowerMaxW)
                }
            }
        } catch {}

        Show-PerformanceSummary -Results $allResults

        # Persist benchmark results for later comparison
        try {
            $timestamp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format "yyyyMMdd-HHmmss" }
            $outDir = $ResultsPath
            if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
            $outFile = Join-Path $outDir "Gaming-Optimization-Benchmark-$timestamp.json"
            $allResults | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8
            Write-Log "Benchmark results saved to $outFile" "INFO"
        }
        catch {
            Write-Log "Could not write benchmark results: $_" "WARNING"
        }
    }
}

# Display comprehensive performance summary
function Show-PerformanceSummary {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Results
    )
    
    Write-Log "" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Log "PERFORMANCE SUMMARY" "INFO"
    Write-Log "==========================================" "INFO"
    Write-Host ""
    
    # Helper function to create properly padded box line
    function Format-BoxLine {
        param([string]$Text, [int]$Width = 62)
        $padded = $Text.PadRight($Width)
        if ($padded.Length -gt $Width) {
            $padded = $padded.Substring(0, $Width)
        }
        return "| $padded |"
    }
    
    # Two-column layout: GPU Config (left) and Rendering Performance (right)
    # Only show GPU section if GPU was tested
    if ($Results.GPU) {
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host "|          GPU CONFIGURATION                   |        GPU RENDERING BENCHMARK              |" -ForegroundColor Cyan
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        
        # GPU and Rendering side by side
        $gpuLines = @(
            @{Text = "GPU:          $($Results.GPU.GPUName.Substring(0, [Math]::Min(31, $Results.GPU.GPUName.Length)))"; Color = "White"},
            @{Text = "VRAM:         $($Results.GPU.VRAMGB) GB (Used: $($Results.GPU.MemoryUsed) GB)"; Color = "White"},
            @{Text = "Resolution:   $($Results.GPU.Resolution) @ $($Results.GPU.RefreshRate)Hz"; Color = "White"}
        )
    
    # Add clock speed info - show boost if available
    if ($Results.GPU.MaxClockSpeed -gt 0 -and $Results.GPU.ClockSpeed -gt 0) {
        $idlePercent = [math]::Round(($Results.GPU.ClockSpeed / $Results.GPU.MaxClockSpeed) * 100, 0)
        $gpuLines += @{Text = "Clock Idle:   $($Results.GPU.ClockSpeed) MHz ($idlePercent% of max)"; Color = "White"}
    } else {
        $gpuLines += @{Text = "Clock Idle:   $(if ($Results.GPU.ClockSpeed -gt 0) { "$($Results.GPU.ClockSpeed) MHz" } else { "N/A" })"; Color = "White"}
    }

    # "Under load" clock - only show if GPU benchmark was actually run
    if ($Results.GPU.BenchmarkRan -and $Results.GPU.ClockSpeedUnderLoad -gt 0 -and $Results.GPU.MaxClockSpeed -gt 0) {
        $loadPercent = [math]::Round(($Results.GPU.ClockSpeedUnderLoad / $Results.GPU.MaxClockSpeed) * 100, 0)
        $gpuLines += @{Text = "Clock Load:   $($Results.GPU.ClockSpeedUnderLoad) MHz ($loadPercent% of max)"; Color = $(if ($loadPercent -ge 80) { "Green" } elseif ($loadPercent -ge 50) { "Yellow" } else { "Red" })}
    } elseif (-not $Results.GPU.BenchmarkRan) {
        $gpuLines += @{Text = "Clock Load:   (test skipped)"; Color = "Gray"}
    } else {
        $gpuLines += @{Text = "Clock Load:   N/A"; Color = "Yellow"}
    }
    
    $gpuLines += @(
        @{Text = "Temp:         $($Results.GPU.Temperature)C | Power: $($Results.GPU.PowerDraw)W"; Color = $(if ($Results.GPU.Temperature -lt 70) { "Green" } elseif ($Results.GPU.Temperature -lt 80) { "Yellow" } else { "Red" })},
        @{Text = "HAGS:         $(if ($Results.GPU.HAGSEnabled) { 'ENABLED' } else { 'DISABLED' })"; Color = $(if ($Results.GPU.HAGSEnabled) { "Green" } else { "Yellow" })},
        @{Text = "GameMode:     $(if ($Results.GPU.GameModeOptimized) { 'On' } else { 'Off' })"; Color = $(if ($Results.GPU.GameModeOptimized) { "Green" } else { "Yellow" })},
        @{Text = "GameDVR:      $(if ($Results.GPU.GameDVROptimized) { 'Off' } else { 'On' })"; Color = $(if ($Results.GPU.GameDVROptimized) { "Green" } else { "Yellow" })},
        @{Text = "Fullscreen:   $(if ($Results.GPU.FullscreenOptimizationsOptimized) { 'Set' } else { 'Default' })"; Color = $(if ($Results.GPU.FullscreenOptimizationsOptimized) { "Green" } else { "Yellow" })},
        @{Text = "Rating:       $($Results.GPU.Rating)"; Color = $(if ($Results.GPU.Rating -eq "EXCELLENT") { "Green" } elseif ($Results.GPU.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
    )
    
    $gr = $Results.GPURendering
    $renderLines = @()
    if ($gr -and ($gr.Tool -or $gr.TestRun)) {
        $ratingTargetHz = if ($gr.RatingTargetHz) { $gr.RatingTargetHz } elseif ($gr.TargetRefreshRate) { $gr.TargetRefreshRate } else { $null }
        $displayHz = if ($gr.DisplayRefreshRateHz) { $gr.DisplayRefreshRateHz } elseif ($ratingTargetHz) { $ratingTargetHz } else { $null }
        $ratingNote = $gr.RatingNote
        $targetText = if ($ratingTargetHz -or $displayHz) {
            if ($displayHz) { "${ratingTargetHz} Hz (display ${displayHz} Hz)" }
            else { "${ratingTargetHz} Hz" }
        } else { "N/A" }

        $renderLines = @(
            @{Text = "Tool:         $($gr.Tool)"; Color = "White"},
            @{Text = "Resolution:   $(if ($gr.Width -and $gr.Height) { "$($gr.Width)x$($gr.Height)" } else { "(fullscreen)" })"; Color = "White"},
            @{Text = "Target:       $targetText"; Color = "White"},
            @{Text = "FPS:          $($gr.FPS)"; Color = $(if ($gr.FPS -ge 60) { "Green" } elseif ($gr.FPS -ge 30) { "Yellow" } else { "Red" })},
            @{Text = "1% Low:       $(if ($gr.OnePercentLowFPS -gt 0) { $gr.OnePercentLowFPS } else { 'N/A' })"; Color = $(if ($gr.OnePercentLowFPS -ge 60) { "Green" } elseif ($gr.OnePercentLowFPS -ge 30) { "Yellow" } else { "Red" })},
            @{Text = "0.1% Low:     $(if ($gr.PointOnePercentLowFPS -gt 0) { $gr.PointOnePercentLowFPS } else { 'N/A' })"; Color = $(if ($gr.PointOnePercentLowFPS -ge 60) { "Green" } elseif ($gr.PointOnePercentLowFPS -ge 30) { "Yellow" } else { "Red" })},
            @{Text = "Score:        $($gr.Score)"; Color = "White"},
            @{Text = "Rating:       $($gr.Rating)"; Color = $(if ($gr.Rating -eq "EXCELLENT" -or $gr.Rating -eq "VERY_GOOD") { "Green" } elseif ($gr.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
        )

        if ($ratingNote) {
            $renderLines += @{Text = "Note:         $ratingNote"; Color = "White"}
        }
    } else {
        $renderLines = @(
            @{Text = "Tool:        (not run)"; Color = "Yellow"},
            @{Text = "FPS:         N/A"; Color = "Yellow"},
            @{Text = "Score:       N/A"; Color = "Yellow"},
            @{Text = "Rating:      NOT_TESTED"; Color = "Yellow"}
        )
    }
    
    for ($i = 0; $i -lt [Math]::Max($gpuLines.Count, $renderLines.Count); $i++) {
        $leftText = if ($i -lt $gpuLines.Count) { $gpuLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
        $leftColor = if ($i -lt $gpuLines.Count) { $gpuLines[$i].Color } else { "White" }
        $rightText = if ($i -lt $renderLines.Count) { $renderLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
        $rightColor = if ($i -lt $renderLines.Count) { $renderLines[$i].Color } else { "White" }
        
        Write-Host "| " -ForegroundColor Cyan -NoNewline
        Write-Host $leftText -ForegroundColor $leftColor -NoNewline
        Write-Host " | " -ForegroundColor Cyan -NoNewline
        Write-Host $rightText -ForegroundColor $rightColor -NoNewline
        Write-Host " |" -ForegroundColor Cyan
    }
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host ""
    }
    
    # CPU and RAM Summary side by side
    if ($Results.CPU -or $Results.RAM) {
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host "|          CPU PERFORMANCE                     |            RAM CONFIGURATION                 |" -ForegroundColor Cyan
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        
        # CPU and RAM side by side
        $cpuLines = @()
        if ($Results.CPU) {
            # Truncate CPU name to fit in column width (44 chars total with label)
            $cpuNameDisplay = if ($Results.CPU.CPUName.Length -gt 27) { 
                $Results.CPU.CPUName.Substring(0, 24) + "..." 
            } else { 
                $Results.CPU.CPUName 
            }
            
            $cpuLines = @(
                @{Text = "CPU:          $cpuNameDisplay"; Color = "White"},
                @{Text = "Cores:        $($Results.CPU.Cores) cores / $($Results.CPU.LogicalProcessors) threads"; Color = "White"}
            )
            
            # Add clock speed info - show boost if available
            if ($Results.CPU.ClockSpeedUnderLoad -gt 0 -and $Results.CPU.MaxClockSpeed -gt 0) {
                $idlePercent = [math]::Round(($Results.CPU.CurrentClockSpeed / $Results.CPU.MaxClockSpeed) * 100, 0)
                $loadPercent = [math]::Round(($Results.CPU.ClockSpeedUnderLoad / $Results.CPU.MaxClockSpeed) * 100, 0)
                $cpuLines += @{Text = "Clock Idle:   $($Results.CPU.CurrentClockSpeed) MHz ($idlePercent%)"; Color = "White"}
                $cpuLines += @{Text = "Clock Load:   $($Results.CPU.ClockSpeedUnderLoad) MHz ($loadPercent%)"; Color = $(if ($loadPercent -ge 90) { "Green" } elseif ($loadPercent -ge 70) { "Yellow" } else { "Red" })}
            }
            
            $cpuLines += @(
                @{Text = "CPU Load:     $(([double]$Results.CPU.HashesPerSecond).ToString('N0')) ops/s"; Color = "Green"},
                @{Text = "Math Speed:   $(([double]$Results.CPU.MathOpsPerSecond).ToString('N0')) ops/s"; Color = "Green"},
                @{Text = "PwrThrottle:  $(if ($Results.CPU.PowerThrottlingOptimized) { 'Off' } else { 'On' })"; Color = $(if ($Results.CPU.PowerThrottlingOptimized) { "Green" } else { "Yellow" })},
                @{Text = "Win32Prio:    $(if ($Results.CPU.Win32PriorityOptimized) { 'Opt' } else { 'Def' })"; Color = $(if ($Results.CPU.Win32PriorityOptimized) { "Green" } else { "Yellow" })},
                @{Text = "SysResp:      $(if ($Results.CPU.SystemResponsivenessOptimized) { 'Opt' } else { 'Def' })"; Color = $(if ($Results.CPU.SystemResponsivenessOptimized) { "Green" } else { "Yellow" })},
                @{Text = "TimerRes:     $(if ($Results.CPU.TimerResolutionOptimized) { 'Enh' } else { 'Def' })"; Color = $(if ($Results.CPU.TimerResolutionOptimized) { "Green" } else { "Yellow" })},
                @{Text = "Rating:       $($Results.CPU.Rating)"; Color = $(if ($Results.CPU.Rating -eq "EXCELLENT") { "Green" } elseif ($Results.CPU.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
            )
        }
        
        $ramLines = @()
        if ($Results.RAM) {
            $ramLines = @(
            @{Text = "Total RAM:    $($Results.RAM.TotalRAMGB) GB ($($Results.RAM.ModuleCount) sticks)"; Color = "White"},
                @{Text = "Config:       $(if ($Results.RAM.IsDualChannel) { 'Dual Channel' } else { 'Single Channel' })"; Color = $(if ($Results.RAM.IsDualChannel) { "Green" } else { "Red" })},
                @{Text = "Speed:        $($Results.RAM.AverageSpeed) MHz ($($Results.RAM.SpeedRating))"; Color = $(if ($Results.RAM.IsOptimalSpeed) { "Green" } else { "Yellow" })},
                @{Text = "Bandwidth:    $($Results.RAM.BandwidthMBps) MB/s"; Color = "Green"},
                @{Text = "Pagefile:     $($Results.RAM.PagefileBandwidthMBps) MB/s"; Color = $(if ($Results.RAM.PagefileBandwidthMBps -ge 500) { "Green" } elseif ($Results.RAM.PagefileBandwidthMBps -ge 100) { "Yellow" } else { "Red" })},
                @{Text = "Rating:       $($Results.RAM.Rating)"; Color = $(if ($Results.RAM.Rating -eq "EXCELLENT") { "Green" } elseif ($Results.RAM.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
            )
        }
        
        for ($i = 0; $i -lt [Math]::Max($cpuLines.Count, $ramLines.Count); $i++) {
        $leftText = if ($i -lt $cpuLines.Count) { $cpuLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
        $leftColor = if ($i -lt $cpuLines.Count) { $cpuLines[$i].Color } else { "White" }
        $rightText = if ($i -lt $ramLines.Count) { $ramLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
        $rightColor = if ($i -lt $ramLines.Count) { $ramLines[$i].Color } else { "White" }
        
        Write-Host "| " -ForegroundColor Cyan -NoNewline
        Write-Host $leftText -ForegroundColor $leftColor -NoNewline
        Write-Host " | " -ForegroundColor Cyan -NoNewline
        Write-Host $rightText -ForegroundColor $rightColor -NoNewline
            Write-Host " |" -ForegroundColor Cyan
        }
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host ""
    }
    
    # Disk and Network Summary side by side
    if ($Results.Disk -or $Results.Network) {
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host "|          DISK PERFORMANCE                    |        NETWORK PERFORMANCE                   |" -ForegroundColor Cyan
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        
        # Disk section
        $diskLines = @()
        if ($Results.Disk) {
            # Truncate disk name to fit in column width (44 chars total with label)
            $diskNameDisplay = if ($Results.Disk.DiskName.Length -gt 27) { 
                $Results.Disk.DiskName.Substring(0, 24) + "..." 
            } else { 
                $Results.Disk.DiskName 
            }
            
            $diskLines = @(
                @{Text = "Disk:         $diskNameDisplay"; Color = "White"},
                @{Text = "Type:         $($Results.Disk.DiskType)"; Color = "White"},
                @{Text = "Read Speed:   $($Results.Disk.ReadMBps) MB/s"; Color = "Green"},
                @{Text = "Write Speed:  $($Results.Disk.WriteMBps) MB/s"; Color = "Green"},
                @{Text = "Average:      $($Results.Disk.AverageSpeed) MB/s"; Color = "Green"},
                @{Text = "4K Read:      $(if ($Results.Disk.Random4KReadIOPS) { "$($Results.Disk.Random4KReadIOPS) IOPS" } else { 'N/A' })"; Color = "Green"},
                @{Text = "4K Write:     $(if ($Results.Disk.Random4KWriteIOPS) { "$($Results.Disk.Random4KWriteIOPS) IOPS" } else { 'N/A' })"; Color = "Green"},
                @{Text = "Rating:       $($Results.Disk.Rating)"; Color = $(if ($Results.Disk.Rating -eq "EXCELLENT") { "Green" } elseif ($Results.Disk.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
            )
        }
    
        # Network section  
        $networkLines = @()
        if ($Results.Network) {
            # Truncate adapter name to fit in column width (44 chars total with label)
            $adapterNameDisplay = if ($Results.Network.AdapterName.Length -gt 27) { 
                $Results.Network.AdapterName.Substring(0, 24) + "..." 
            } else { 
                $Results.Network.AdapterName 
            }
            
            $downloadMbps = 0
            $uploadMbps = 0
            try {
                if ($Results.Network -and ($Results.Network -is [hashtable])) {
                    if ($Results.Network.ContainsKey('DownloadMbps')) { $downloadMbps = [double]$Results.Network.DownloadMbps }
                    elseif ($Results.Network.ContainsKey('DownloadSpeed')) { $downloadMbps = [double]$Results.Network.DownloadSpeed }
                    if ($Results.Network.ContainsKey('UploadMbps')) { $uploadMbps = [double]$Results.Network.UploadMbps }
                    elseif ($Results.Network.ContainsKey('UploadSpeed')) { $uploadMbps = [double]$Results.Network.UploadSpeed }
                } else {
                    if ($null -ne $Results.Network.DownloadMbps) { $downloadMbps = [double]$Results.Network.DownloadMbps }
                    elseif ($null -ne $Results.Network.DownloadSpeed) { $downloadMbps = [double]$Results.Network.DownloadSpeed }
                    if ($null -ne $Results.Network.UploadMbps) { $uploadMbps = [double]$Results.Network.UploadMbps }
                    elseif ($null -ne $Results.Network.UploadSpeed) { $uploadMbps = [double]$Results.Network.UploadSpeed }
                }
            } catch {}

            $networkLines = @(
                @{Text = "Adapter:      $adapterNameDisplay"; Color = "White"},
                @{Text = "Link Speed:   $($Results.Network.LinkSpeed)"; Color = "White"},
                @{Text = "Avg Latency:  $($Results.Network.AvgLatency)ms"; Color = $(if ($Results.Network.AvgLatency -lt 20) { "Green" } elseif ($Results.Network.AvgLatency -lt 50) { "Yellow" } else { "Red" })},
                @{Text = "DNS Speed:    $($Results.Network.AvgDNSResolution)ms"; Color = $(if ($Results.Network.AvgDNSResolution -lt 30) { "Green" } elseif ($Results.Network.AvgDNSResolution -lt 100) { "Yellow" } else { "Red" })},
                @{Text = "Download:     $(if ($downloadMbps -gt 0) { $downloadMbps } else { 'N/A' }) Mbps"; Color = $(if ($downloadMbps -gt 50) { "Green" } elseif ($downloadMbps -gt 0) { "Yellow" } else { "Yellow" })},
                @{Text = "Upload:       $(if ($uploadMbps -gt 0) { $uploadMbps } else { 'N/A' }) Mbps"; Color = $(if ($uploadMbps -gt 20) { "Green" } elseif ($uploadMbps -gt 0) { "Yellow" } else { "Yellow" })},
                @{Text = "Rating:       $($Results.Network.Rating)"; Color = $(if ($Results.Network.Rating -eq "EXCELLENT") { "Green" } elseif ($Results.Network.Rating -eq "GOOD") { "Yellow" } else { "Red" })}
            )
        }
    
        for ($i = 0; $i -lt [Math]::Max($diskLines.Count, $networkLines.Count); $i++) {
            $leftText = if ($i -lt $diskLines.Count) { $diskLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
            $leftColor = if ($i -lt $diskLines.Count) { $diskLines[$i].Color } else { "White" }
            $rightText = if ($i -lt $networkLines.Count) { $networkLines[$i].Text.PadRight(44) } else { "".PadRight(44) }
            $rightColor = if ($i -lt $networkLines.Count) { $networkLines[$i].Color } else { "White" }
            
            Write-Host "| " -ForegroundColor Cyan -NoNewline
            Write-Host $leftText -ForegroundColor $leftColor -NoNewline
            Write-Host " | " -ForegroundColor Cyan -NoNewline
            Write-Host $rightText -ForegroundColor $rightColor -NoNewline
            Write-Host " |" -ForegroundColor Cyan
        }
        Write-Host "+------------------------------------------------+------------------------------------------------+" -ForegroundColor Cyan
        Write-Host ""
    }
}

# Run pre-optimization diagnostics in WhatIf mode
function Invoke-PreOptimizationDiagnostics {
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Pre-Optimization System Diagnostics" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Running in WhatIf mode - no changes will be made" "INFO"
    
    try {
        # Temporarily enable WhatIf for diagnostic run
        $originalWhatIf = $WhatIfPreference
        $WhatIfPreference = $true
        
        Write-Log "`nChecking current optimization status..." "INFO"
        Test-OptimizationSettings
        
        Write-Log "`nVBS/Memory Integrity Status:" "INFO"
        Test-VBSStatus
        
        Write-Log "`nGPU Hardware Recommendations:" "INFO"
        Show-GPURecommendations
        
        Write-Log "" "INFO"
        Write-Log "Disk and Storage Analysis:" "INFO"
        Optimize-PageFile
        
        # Restore original WhatIf preference
        $WhatIfPreference = $originalWhatIf
        
        Write-Log "" "INFO"
        Write-Log "========================================" "INFO"
        Write-Log "Diagnostics Complete" "INFO"
        Write-Log "========================================" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Error running diagnostics: $_" "ERROR"
        return $false
    }
}

# Rollback function
function Invoke-Rollback {
    param([string]$BackupFile)
    
    Write-Log "Rolling back changes from backup file: $BackupFile"
    
    if (-not (Test-Path $BackupFile)) {
        Write-Log "Backup file not found: $BackupFile" "ERROR"
        return $false
    }
    
    try {
        # Import the registry backup
        & reg import $BackupFile
        Write-Log "Registry values restored from backup" "SUCCESS"
        
        # Remove any keys that were newly created (didn't exist before)
        Write-Log "Checking for newly-created keys to remove..." "INFO"
        $newKeysToRemove = Get-TrackedNewKeys $BackupFile
        
        if ($newKeysToRemove.Count -gt 0) {
            Write-Log "" "INFO"
            Write-Log "Removing keys that were created during optimization..." "INFO"
            Remove-NewlyCreatedKeys $newKeysToRemove
            Write-Log "" "INFO"
        }
        
        Write-Log "Rollback completed successfully - system restored to pre-optimization state" "SUCCESS"
        Write-Log "Please restart your computer for changes to take effect" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to rollback: $_" "ERROR"
        return $false
    }
}

# Main execution
function Invoke-OptimizationScript {
    Write-Log "========================================" "INFO"
    Write-Log "Windows 11 Gaming Optimization Script" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Action: $Action" "INFO"
    
    if ($WhatIfPreference) {
        Write-Log "WhatIf Mode: No changes will be made" "INFO"
    }
    
    if ($VerbosePreference -eq 'Continue') {
        Write-Log "Verbose Mode: Detailed output enabled" "INFO"
    }
    
    if ($DebugMode) {
        Write-Log "Debug Mode: Debug information enabled" "INFO"
    }
    
    if (-not (Test-Administrator)) {
        Write-Log "ERROR: This script must be run as Administrator!" "ERROR"
        exit 1
    }
    
    # Check PC uptime and warn if too recent (benchmark results may be inaccurate)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os -and $os.LastBootUpTime) {
            $uptime = (Get-Date) - $os.LastBootUpTime
            if ($uptime.TotalMinutes -lt 10) {
                $uptimeMin = [math]::Round($uptime.TotalMinutes, 1)
                Write-Log "" "WARNING"
                Write-Log "WARNING: PC uptime is only ${uptimeMin} minutes!" "WARNING"
                Write-Log "Benchmark results may be inaccurate if run before system stabilizes (~10 min)." "WARNING"
                Write-Log "Consider waiting a few more minutes for optimal results." "WARNING"
                Write-Log "" "WARNING"
            }
        }
    } catch {
        # Silently ignore uptime check failures
    }
    
    # Optional: Run pre-optimization diagnostics first
    if ($Action -eq 'Apply') {
        # Ask user interactively (unless in WhatIf mode)
        $shouldRunDiag = $null
        if (-not $WhatIfPreference) {
            Write-Host "`nWould you like to run pre-optimization diagnostics first? (Y/N): " -NoNewline -ForegroundColor Cyan
            $runDiag = Read-Host
            $shouldRunDiag = ($runDiag -eq 'Y' -or $runDiag -eq 'y')
        }
        
        if ($shouldRunDiag) {
            Invoke-PreOptimizationDiagnostics
            Write-Host "`nContinue with optimization? (Y/N): " -NoNewline -ForegroundColor Cyan
            $continueOpt = Read-Host
            if ($continueOpt -ne 'Y' -and $continueOpt -ne 'y') {
                Write-Log "Optimization cancelled by user" "INFO"
                return
            }
        }
    }
    
    # Get Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Log "Windows Version: $($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)"
    
    if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 22000)) {
        Write-Log "WARNING: This script is designed for Windows 11. Some features may not work on older versions." "WARNING"
    }
    
    # BACKUP PROTECTION: Check all existing backups before proceeding
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Backup Safety Check" "INFO"
    Write-Log "========================================" "INFO"
    $null = Protect-RegistryBackups
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    
    # Auto-detect action based on whether baseline exists
    # This makes the workflow intuitive: just run the script and it does the right thing
    if ($Action -eq 'Auto') {
        $script:ResolvedBaselinePath = Resolve-BaselineResultsPath
        if ($script:ResolvedBaselinePath) {
            # Baseline (or latest results) exists - automatically run comparison
            Write-Log "Baseline benchmark results detected!" "SUCCESS"
            Write-Log "Using baseline at: $script:ResolvedBaselinePath" "INFO"
            Write-Log "Automatically running comparison mode..." "INFO"
            Write-Log "" "INFO"
            $Action = 'CompareBaseline'
        } else {
            # No baseline - automatically create one
            Write-Log "No baseline found." "INFO"
            Write-Log "Automatically creating performance baseline..." "INFO"
            Write-Log "" "INFO"
            $Action = 'CreateBaseline'
        }
    }
    
    switch ($Action) {
        'Apply' {
            # Ensure WhatIf is disabled for Apply mode (even if user passed -WhatIf to script)
            $WhatIfPreference = $false
            
            Write-Log "Starting optimization process..."
            
            # Run baseline benchmarks if -BenchmarkBeforeAfter is enabled
            $baselineResults = $null
            if ($BenchmarkBeforeAfter) {
                Write-Log "" "INFO"
                Write-Log "========================================" "INFO"
                Write-Log "BASELINE PERFORMANCE BENCHMARKS" "INFO"
                Write-Log "========================================" "INFO"
                Write-Log "Running baseline benchmarks before applying optimizations..." "INFO"
                
                # Tag telemetry files created during this baseline run as pre-optimization
                $script:CurrentTelemetryTag = '-preopt'
                $baselineResults = Invoke-PerformanceBenchmark -ReturnData
                $script:CurrentTelemetryTag = $null
                if ($baselineResults) {
                    $bp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format 'yyyyMMdd-HHmmss' }
                    $timestampedPath = Join-Path $ResultsPath "Gaming-Optimization-Benchmark-$bp.json"
                    $saved = Save-BenchmarkResults -Results $baselineResults -FilePath $timestampedPath
                    if ($saved) {
                        # Track saved baseline path so we can optionally rename it later
                        $script:BaselineSavedPath = $timestampedPath
                    }
                    else {
                        Write-Log "WARNING: Failed to save baseline results. Comparison will not be available." "WARNING"
                        $baselineResults = $null
                    }
                }
                
                Write-Log "" "INFO"
                Write-Log "Baseline benchmarks completed. Proceeding with optimizations..." "INFO"
                Start-Sleep -Seconds 2
            }
            
            # Create backup (always create, even in WhatIf mode - this is important for safety)
            # Temporarily disable WhatIf for backup to ensure it always runs
            $originalWhatIf = $WhatIfPreference
            $WhatIfPreference = $false
            
            $backupSuccess = $true
            if (-not $SkipBackup) {
                $backupSuccess = Backup-RegistryKeys
            } else {
                Write-Log "Skipping backup as requested (not recommended!)" "WARNING"
                $backupSuccess = $false
            }
            
            # Restore WhatIf preference
            $WhatIfPreference = $originalWhatIf
            
            # CRITICAL SAFETY: Stop if backup failed
            if (-not $backupSuccess) {
                Write-Log "" "ERROR"
                Write-Log "[CRITICAL] Backup failed or validation did not complete successfully!" "ERROR"
                Write-Log "Registry optimizations will NOT proceed to prevent leaving system unbackedup." "ERROR"
                Write-Log "Please fix the backup issue and try again." "ERROR"
                Write-Log "" "ERROR"
                return
            }
            
            # Check Windows version
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "System Information" "INFO"
            Write-Log "========================================" "INFO"
            $winVersion = Get-WindowsVersionInfo
            Write-Log "Windows Version: $($winVersion.VersionName)" "INFO"
            Write-Log "Build Number: $($winVersion.Build)" "INFO"
            
            # Detect hardware
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "Hardware Detection" "INFO"
            Write-Log "========================================" "INFO"
            $null = Get-CPUManufacturer
            $null = Get-GPUManufacturers
            
            # Show feature requirements and compatibility
            Show-FeatureRequirements
            
            # Apply optimizations
            $results = @{
                Win32Priority = Set-Win32Priority
                PowerThrottling = Disable-PowerThrottling
                DwmMpo = Set-DwmMpoFix
                NetworkThrottling = Disable-NetworkThrottling
                SystemResponsiveness = Set-SystemResponsiveness
                GamesPriority = Set-GamesPriority
                InputLatency = Set-InputLatencyOptimizations
                MemoryManagement = Set-MemoryManagementOptimizations
                WindowsUpdateP2P = Disable-WindowsUpdateP2P
                TcpOptimization = Optimize-TcpSettings
                NaglesAlgorithm = Disable-NaglesAlgorithm
                GameMode = Enable-GameMode
                HAGS = Enable-HAGS
                GameDVR = Disable-GameDVR
                FullscreenOpt = Set-FullscreenOptimizations
                TimerResolution = Set-TimerResolution
                SystemCache = Set-SystemCache
                BackgroundApps = Optimize-BackgroundApps
                VisualEffects = Optimize-VisualEffects
            }
            
            # Apply hardware-specific optimizations
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "Hardware-Specific Optimizations" "INFO"
            Write-Log "========================================" "INFO"
            
            if ($cpuManufacturer -eq 'AMD') {
                $results['AMDOptimizations'] = Set-AMDRyzenOptimizations
            }
            elseif ($cpuManufacturer -eq 'Intel') {
                $results['IntelOptimizations'] = Set-IntelOptimizations
            }
            
            # Experimental NVMe Support (optional)
            if ($EnableNativeNVMe) {
                Write-Log "" "INFO"
                Write-Log "========================================" "INFO"
                Write-Log "Experimental NVMe Support" "INFO"
                Write-Log "========================================" "INFO"
                $results['NativeNVMe'] = Enable-ExperimentalNVMe
            }
            
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "Optimization Summary:" "INFO"
            Write-Log "========================================" "INFO"
            
            $successCount = ($results.Values | Where-Object { $_ -eq $true }).Count
            $totalCount = $results.Count
            
            Write-Log "Successfully applied: $successCount/$totalCount optimizations" "INFO"
            
            if ($successCount -eq $totalCount) {
                Write-Log "`nAll optimizations applied successfully!" "SUCCESS"
            } else {
                Write-Log "`nSome optimizations failed. Check the log for details." "WARNING"
            }
            
            Write-Log "`nBackup saved to: $BackupPath" "INFO"
            Write-Log "Log saved to: $LogPath" "INFO"
            
            # Check VBS status
            Test-VBSStatus
            
            # Show hardware-specific recommendations
            Show-GPURecommendations
            
            # Show MSI Mode information
            Show-MSIModeInfo
            
            # Analyze disk space and pagefile configuration
            Optimize-PageFile
            
            # Inform user about post-restart benchmarking if -BenchmarkBeforeAfter is enabled
            if ($BenchmarkBeforeAfter -and $baselineResults) {
                Write-Log "" "INFO"
                Write-Log "========================================" "INFO"
                Write-Log "BENCHMARK BASELINE SAVED" "INFO"
                Write-Log "========================================" "INFO"
                Write-Log "Baseline benchmark results have been saved." "SUCCESS"
                Write-Log "" "INFO"
                Write-Log "[IMPORTANT] The optimizations require a system restart to take effect." "WARNING"
                Write-Log "After restarting, run the following command to measure improvements:" "INFO"
                Write-Log "" "INFO"
                Write-Log "  .\Windows-Gaming-Optimization.ps1 -Action CompareBaseline" "INFO"
                Write-Log "" "INFO"
                Write-Log "This will run new benchmarks and compare them to your baseline." "INFO"
            }

            # If we saved a baseline before applying optimizations and some optimizations failed,
            # rename the baseline file to include '-preopt' so users can easily identify it.
            if ($BenchmarkBeforeAfter -and $script:BaselineSavedPath -and (Test-Path $script:BaselineSavedPath) -and ($successCount -ne $totalCount)) {
                try {
                    $preoptPath = $script:BaselineSavedPath.Replace('.json','-preopt.json')
                    Move-Item -Path $script:BaselineSavedPath -Destination $preoptPath -Force
                    Write-Log "Baseline contained failed optimizations; renamed baseline to: $preoptPath" "INFO"
                    # Update the saved baseline reference
                    $script:BaselineSavedPath = $preoptPath
                }
                catch {
                    Write-Log "Warning: could not rename baseline file to include -preopt: $_" "WARNING"
                }
            }
            
            Write-Log "`n[ALERT] IMPORTANT: Restart your computer for all changes to take effect!" "WARNING"
            
            # Offer to test (skip in WhatIf mode)
            if (-not $WhatIfPreference) {
                Write-Host "`nWould you like to test the applied settings now? (Y/N): " -NoNewline
                $response = Read-Host
                if ($response -eq 'Y' -or $response -eq 'y') {
                    Test-OptimizationSettings
                }
            } else {
                Write-Log "Skipping settings test in WhatIf mode" "INFO"
            }
        }
        
        'Test' {
            Test-OptimizationSettings
        }
        
        'Benchmark' {
            Invoke-PerformanceBenchmark
        }
        
        'CreateBaseline' {
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "CREATE PERFORMANCE BASELINE" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "" "INFO"
            Write-Log "This will establish a baseline of your system's current performance." "INFO"
            Write-Log "No optimizations will be applied." "INFO"
            Write-Log "" "INFO"
            
            Write-Log "Running comprehensive performance benchmarks..." "INFO"
            Write-Log "" "INFO"
            
            # Run benchmarks
            # Tag telemetry files created during this baseline creation as pre-optimization
            $script:CurrentTelemetryTag = '-preopt'
            $baselineResults = Invoke-PerformanceBenchmark -ReturnData
            $script:CurrentTelemetryTag = $null
            
            if ($baselineResults) {
                # Save baseline with timestamp
                    $bp = if ($script:RunTimestamp) { $script:RunTimestamp } else { Get-Date -Format 'yyyyMMdd-HHmmss' }
                    $timestampedPath = Join-Path $ResultsPath "Gaming-Optimization-Benchmark-$bp.json"
                $saved = Save-BenchmarkResults -Results $baselineResults -FilePath $timestampedPath
                
                if ($saved) {
                    Write-Log "" "INFO"
                    Write-Log "========================================" "INFO"
                    Write-Log "BASELINE CREATED SUCCESSFULLY" "INFO"
                    Write-Log "========================================" "INFO"
                    Write-Log "" "INFO"
                    Write-Log "Baseline saved to: $timestampedPath" "SUCCESS"
                    Write-Log "" "INFO"
                    Write-Log "Next steps:" "INFO"
                    Write-Log "1. Run optimizations:\" "INFO"
                    Write-Log "   .\\Windows-Gaming-Optimization.ps1 -Action Apply" "INFO"
                    Write-Log "2. Restart your computer" "INFO"
                    Write-Log "3. Run comparison:\" "INFO"
                    Write-Log "   .\\Windows-Gaming-Optimization.ps1 -Action CompareBaseline" "INFO"
                    Write-Log "" "INFO"
                } else {
                    Write-Log "Failed to save baseline results" "ERROR"
                }
            } else {
                Write-Log "Failed to run benchmarks" "ERROR"
            }
        }
        
        'CompareBaseline' {
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "POST-RESTART BENCHMARK COMPARISON" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "" "INFO"
            
            # Resolve baseline path (supports archived or latest timestamped results)
            $baselinePath = if ($script:ResolvedBaselinePath) { $script:ResolvedBaselinePath } else { Resolve-BaselineResultsPath }
            if (-not $baselinePath) {
                Write-Log "No baseline benchmark results found!" "ERROR"
                Write-Log "Run the script with -Action CreateBaseline or -Action Apply -BenchmarkBeforeAfter to create a baseline first." "ERROR"
                return
            }
            Write-Log "Using baseline at: $baselinePath" "INFO"
            
            Write-Log "Running post-optimization benchmarks..." "INFO"
            Write-Log "This will compare current performance to your baseline." "INFO"
            Write-Log "" "INFO"
            
            # Run benchmarks
            # Tag telemetry files created during this post-optimization comparison as -postopt
            $script:CurrentTelemetryTag = '-postopt'
            $afterResults = Invoke-PerformanceBenchmark -ReturnData
            $script:CurrentTelemetryTag = $null
            
            if ($afterResults) {
                # Load baseline and compare
                $baseline = Import-BenchmarkResults -FilePath $baselinePath
                if ($baseline) {
                    Compare-BenchmarkResults -BeforeResults $baseline -AfterResults $afterResults
                    
                    # Save after results next to baseline. If the baseline was renamed to -preopt,
                    # save the post-optimization results with -postopt so the pair is obvious.
                    if ($baselinePath -match "-preopt\.json$") {
                        $afterPath = $baselinePath.Replace('-preopt.json','-postopt.json')
                    }
                    else {
                        $afterPath = $baselinePath.Replace('.json', '-after.json')
                    }
                    Save-BenchmarkResults -Results $afterResults -FilePath $afterPath | Out-Null

                    Write-Log "" "INFO"
                    Write-Log "After-optimization results saved to: $afterPath" "SUCCESS"
                } else {
                    Write-Log "Failed to load baseline results for comparison" "ERROR"
                }
            } else {
                Write-Log "Failed to run benchmarks" "ERROR"
            }
        }
        
        'Rollback' {
            Write-Log "" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "Registry Rollback" "INFO"
            Write-Log "========================================" "INFO"
            Write-Log "" "INFO"
            
            # Show all available backups
            $availableBackups = Get-ExistingBackups
            
            if ($availableBackups.Count -eq 0) {
                Write-Log "No backup files found! Cannot perform rollback." "ERROR"
            }
            else {
                Write-Log "" "INFO"
                Write-Log "Available backup files:" "INFO"
                for ($i = 0; $i -lt $availableBackups.Count; $i++) {
                    Write-Log "  [$($i + 1)] $($availableBackups[$i].Name)" "INFO"
                }
                Write-Log "" "INFO"
                
                # Prompt user to select or enter path
                Write-Host "Enter backup file number [1-$($availableBackups.Count)] or full path: " -NoNewline
                $userInput = Read-Host
                
                $backupFile = $null
                if ($userInput -match '^\d+$' -and [int]$userInput -ge 1 -and [int]$userInput -le $availableBackups.Count) {
                    $backupFile = $availableBackups[[int]$userInput - 1].FullName
                } else {
                    $backupFile = $userInput
                }
                
                if (Test-Path $backupFile) {
                    Invoke-Rollback -BackupFile $backupFile
                } else {
                    Write-Log "Backup file not found: $backupFile" "ERROR"
                }
            }
        }
    }
    
    Write-Log "`nScript completed." "INFO"
}

# Run the script
Invoke-OptimizationScript
