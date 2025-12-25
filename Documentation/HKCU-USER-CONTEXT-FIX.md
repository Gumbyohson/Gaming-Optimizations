# HKCU Registry Fix for Elevated Script Execution

## Problem
When the gaming optimization script runs with elevated (administrator) privileges, any HKCU (HKEY_CURRENT_USER) registry modifications are applied to the admin user's registry, not the actual logged-in user's registry. This means the optimizations don't take effect for the regular user account.

## Solution Implemented
Three new helper functions have been added to handle HKCU registry access properly:

### 1. **Get-LoggedInUser()**
Detects the actual logged-in user when the script runs elevated.
- First tries to get the user from the explorer.exe process (most reliable)
- Falls back to checking WMI process information
- Ensures we're applying changes to the correct user, not the admin

### 2. **Set-UserRegistryValue()**
Wrapper function for setting registry values that works across user contexts.
- Automatically detects if running elevated
- If elevated and HKCU path doesn't exist in current context, uses the logged-in user's registry
- Falls back to standard `Set-ItemProperty` for HKLM paths
- Uses `reg.exe` for cross-context registry access when needed

### 3. **Get-UserRegistryValue()**
Wrapper function for reading registry values from the correct user context.
- Tries normal HKCU access first
- Falls back to the logged-in user's hive if needed
- Returns null if value doesn't exist

### 4. **Get-UserSID()**
Helper function to convert a username to its SID for registry hive access.

## Updated Functions
The following functions now use the new helpers instead of direct `Set-ItemProperty` calls:

| Function | HKCU Settings Modified |
|----------|------------------------|
| **Enable-GameMode** | AutoGameModeEnabled |
| **Disable-GameDVR** | GameDVR_Enabled, AppCaptureEnabled, HistoricalCaptureEnabled, ShowStartupPanel, UseNexusForGameBarEnabled |
| **Set-FullscreenOptimizations** | GameDVR_DXGIHonorFSEWindowsCompatible, GameDVR_FSEBehaviorMode, GameDVR_HonorUserFSEBehaviorMode |
| **Optimize-BackgroundApps** | GlobalUserDisabled |
| **Optimize-VisualEffects** | VisualFXSetting, UserPreferencesMask, MenuShowDelay, MinAnimate |

## Testing
The test function in `Test-AppliedOptimizations` now uses `Get-UserRegistryValue` to verify that settings were applied to the correct user account.

## How It Works
1. Script runs with administrator privileges
2. Calls to registry are made via the new helper functions
3. If the script is running elevated (admin), the helpers detect the actual logged-in user
4. Registry changes are applied to the logged-in user's hive using their SID
5. Both admin and non-admin users get the correct optimizations applied

## Backwards Compatibility
- The fix is transparent and maintains full backwards compatibility
- If the script runs in a non-elevated context, everything works normally
- If there's any issue detecting the logged-in user, it falls back to standard behavior

## Testing the Fix
Run the script as an elevated process while logged in as a regular (non-admin) user:
```powershell
# Run as admin
powershell -NoProfile -ExecutionPolicy Bypass -File "Windows-Gaming-Optimization.ps1" -Action Apply
```

The HKCU settings will now be correctly applied to your user account, not the admin account.
