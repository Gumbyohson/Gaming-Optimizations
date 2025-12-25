# WhatIf and Debug Mode Guide

## Overview
The gaming optimization script now supports PowerShell's built-in `-WhatIf`, `-Verbose`, and a custom `-DebugMode` parameter for safe testing and troubleshooting.

## Usage Examples

### 1. WhatIf Mode (Preview Changes)
See what changes would be made **without actually applying them**:

```powershell
.\Windows-Gaming-Optimization.ps1 -Action Apply -WhatIf
```

**What it does:**
- Shows all optimizations that would be applied
- No registry changes are made
- No system modifications occur
- Safe to run anytime

**Output example:**
```
WhatIf: Would set Win32PrioritySeparation to 40
WhatIf: Would disable Power Throttling
WhatIf: Would set HKCU:\Software\Microsoft\GameBar\AutoGameModeEnabled = 1
```

### 2. Verbose Mode (Detailed Output)
Get detailed information about each operation:

```powershell
.\Windows-Gaming-Optimization.ps1 -Action Apply -Verbose
```

**What it does:**
- Shows detailed progress for each step
- Displays SUCCESS, WARNING, and ERROR messages in PowerShell streams
- Helps understand what the script is doing
- Still makes actual changes

### 3. Debug Mode (Troubleshooting)
Enable deep diagnostic output for troubleshooting:

```powershell
.\Windows-Gaming-Optimization.ps1 -Action Apply -DebugMode
```

**What it does:**
- Enables PowerShell debug stream
- Shows registry paths being modified
- Displays variable values and logic flow
- Useful for diagnosing issues
- Still makes actual changes

### 4. Combine Modes
You can combine these parameters:

```powershell
# Preview with detailed output
.\Windows-Gaming-Optimization.ps1 -Action Apply -WhatIf -Verbose

# Apply with full diagnostics
.\Windows-Gaming-Optimization.ps1 -Action Apply -Verbose -DebugMode

# Test mode with debug info
.\Windows-Gaming-Optimization.ps1 -Action Test -DebugMode
```

## When to Use Each Mode

| Mode | Use Case | Makes Changes? |
|------|----------|----------------|
| **-WhatIf** | Preview before running | ❌ No |
| **-Verbose** | Understand what's happening | ✅ Yes |
| **-DebugMode** | Troubleshoot issues | ✅ Yes |
| **-WhatIf -Verbose** | Detailed preview | ❌ No |

## Common Scenarios

### Scenario 1: First Time Running
```powershell
# First, preview what will happen
.\Windows-Gaming-Optimization.ps1 -Action Apply -WhatIf

# If satisfied, run with verbose output
.\Windows-Gaming-Optimization.ps1 -Action Apply -Verbose
```

### Scenario 2: Something Isn't Working
```powershell
# Run test mode with debug output
.\Windows-Gaming-Optimization.ps1 -Action Test -DebugMode

# Try applying with full diagnostics
.\Windows-Gaming-Optimization.ps1 -Action Apply -Verbose -DebugMode
```

### Scenario 3: Reporting an Issue
```powershell
# Capture full debug output
.\Windows-Gaming-Optimization.ps1 -Action Apply -DebugMode -Verbose *> debug-output.txt
```

## Output Streams

The script uses PowerShell's standard output streams:

- **Write-Host**: Always visible (colored console output)
- **Write-Verbose**: Only visible with `-Verbose`
- **Write-Debug**: Only visible with `-DebugMode`
- **Write-Warning**: Always visible for warnings
- **Write-Error**: Always visible for errors
- **Log File**: Everything is saved to desktop log file

## Technical Details

### WhatIf Support
Functions that modify the system now include:
```powershell
[CmdletBinding(SupportsShouldProcess=$true)]
```

And check before making changes:
```powershell
if ($PSCmdlet.ShouldProcess("TargetName", "Operation")) {
    # Make actual changes
}
```

### Debug Output
Debug messages show:
- Registry paths being accessed
- Values being set
- User context information
- Conditional logic decisions

Example debug output:
```
DEBUG: Setting registry: HKLM:\SYSTEM\...\PowerThrottling\PowerThrottlingOff = 1 (Type: DWord)
DEBUG: Detected logged-in user: CurrentUser
DEBUG: Using HKCU path for user context
```

## Safety Features

1. **WhatIf is completely safe**: No system changes are made
2. **All modes create log files**: Check Desktop for timestamped logs
3. **Backup still created**: Registry backup is made before applying changes (unless -SkipBackup)
4. **Administrator check**: Script verifies admin privileges before starting

## Tips

- **Always test with -WhatIf first** if you're unsure
- Use **-Verbose for transparency** when making actual changes
- Use **-DebugMode only when troubleshooting** (very verbose output)
- **Check the log file** on your Desktop for complete history
- **Combine with -SkipBackup** if testing repeatedly: `-WhatIf -SkipBackup`

## Version History
- **v2.1**: Added `-WhatIf`, `-Verbose`, and `-DebugMode` support
- **v2.0**: Added HKCU user context fix
