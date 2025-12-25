# Windows 11 Gaming Optimization Suite - Consolidated Version

## 🎮 All-In-One Gaming Optimization Script

This is the **consolidated, all-in-one** Windows 11 gaming optimization suite. Everything you need in a single PowerShell script.

---

## ✨ What's Included

### 📊 Benchmarking (Built-In)
- CPU Performance Tests (single & multi-thread)
- GPU Information & Capabilities
- Network Latency Tests (ping to multiple servers)
- Storage Speed Tests (read/write performance)
- Export results to JSON for comparison

### ⚙️ Optimizations (14+)
1. **Win32 Priority Separation** - Gaming process priority boost
2. **Power Throttling Disabled** - Maximum performance
3. **DWM MPO Fix** - Display rendering optimization
4. **Network Throttling Disabled** - Lower latency
5. **System Responsiveness** - Multimedia thread priority
6. **Games Priority Boost** - Background/foreground priority
7. **TCP Optimization** - Network stack tweaks
8. **Nagle's Algorithm Disabled** - Reduced packet delays
9. **Game Mode Enabled** - Windows gaming features
10. **HAGS (Hardware GPU Scheduling)** - Reduced input lag
11. **Game DVR Disabled** - No background recording
12. **Fullscreen Optimizations** - Better compatibility
13. **Timer Resolution** - Improved frame pacing
14. **System Cache Optimization** - More RAM for games
15. **Native NVMe Support** - Experimental storage boost (optional)

### 🖥️ Hardware-Specific
- **Intel CPU**: Power plan recommendations, ParkControl guidance
- **AMD Ryzen**: CPPC enabled, chipset driver reminders
- **NVIDIA GPU**: G-SYNC, DLSS, Reflex tips
- **AMD GPU**: FreeSync, FSR, Anti-Lag+ guidance

### ℹ️ Additional Guidance
- MSI Mode configuration information
- VBS/Memory Integrity disable guidance
- Virtual Machine Platform disable option
- Resizable BAR (ReBAR) checks

---

## 🚀 Quick Start

### Basic Optimization (with diagnostics)
```powershell
# Run as Administrator
.\Windows-Gaming-Optimization.ps1 -Action Apply -RunDiagnostics Yes
```

### Apply + Capture Before/After Benchmarks Automatically
```powershell
.\Windows-Gaming-Optimization.ps1 -Action Apply -BenchmarkBeforeAfter
```

### Native NVMe (Windows 11 24H2/25H2 + NVMe + Microsoft driver)
```powershell
.\Windows-Gaming-Optimization.ps1 -Action Apply -EnableNativeNVMe
```

### Create a Baseline (manual)
```powershell
.\Windows-Gaming-Optimization.ps1 -Action CreateBaseline
```

### Compare Against Latest Baseline
```powershell
.\Windows-Gaming-Optimization.ps1 -Action CompareBaseline
```

### Benchmark Only
```powershell
.\Windows-Gaming-Optimization.ps1 -Action Benchmark
```

### Test Applied Settings
```powershell
.\Windows-Gaming-Optimization.ps1 -Action Test
```

### Rollback Changes
```powershell
.\Windows-Gaming-Optimization.ps1 -Action Rollback
```

---

## 📋 Complete Usage

### Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `-Action` | `Apply`, `Rollback`, `Test`, `Benchmark`, `CreateBaseline`, `CompareBaseline`, `Auto` | Workflow selector |
| `-EnableNativeNVMe` | Switch | Experimental Native NVMe (24H2+ with NVMe + Microsoft driver; skips if not supported) |
| `-SkipBackup` | Switch | Skip registry backup (not recommended) |
| `-RunDiagnostics` | `Y`, `N`, `Yes`, `No` | Run prechecks before Apply; prompts if omitted |
| `-BenchmarkBeforeAfter` | Switch | Run a pre-apply benchmark and prompt for post-apply comparison |
| `-GravityMarkPath` | Path | Use an existing GravityMark installer/exe/zip instead of downloading |
| `-DebugMode` | Switch | Extra debug logging to console and log file |

### Examples

```powershell
# Full optimization with NVMe
.\Windows-Gaming-Optimization.ps1 -Action Apply -EnableNativeNVMe

# Run diagnostics before apply
.\Windows-Gaming-Optimization.ps1 -Action Apply -RunDiagnostics Yes

# Test without changing anything
.\Windows-Gaming-Optimization.ps1 -Action Test

# Rollback using backup file
.\Windows-Gaming-Optimization.ps1 -Action Rollback
```

---

## 📊 Benchmark Workflow

### Recommended Testing Process

1. **Create Baseline (choose one)**
   - Automatic with Apply: `-Action Apply -BenchmarkBeforeAfter`
   - Manual: `-Action CreateBaseline`
   - Baseline saved as `Gaming-Optimization-Benchmark-Results.json` (most recent timestamped copies go to the script folder and `Archive/`).

2. **Apply Optimizations**
   ```powershell
   .\Windows-Gaming-Optimization.ps1 -Action Apply
   ```
   - Backup created automatically (unless `-SkipBackup`)
   - Guardrails for build/hardware (HAGS, Native NVMe)
   - Restart recommended/required for some tweaks

3. **After Restart**
   - If you used `-BenchmarkBeforeAfter`, rerun the script when prompted to capture the "after" benchmark.
   - Or run: `.\Windows-Gaming-Optimization.ps1 -Action Benchmark`

4. **Compare Results**
   - `.\Windows-Gaming-Optimization.ps1 -Action CompareBaseline`
   - Baseline is auto-resolved (current folder then `Archive/`).

---

## 🎯 What Gets Optimized

### Registry Keys Modified

**HKLM (System-Wide)**
- `\SYSTEM\CurrentControlSet\Control\PriorityControl`
- `\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling`
- `\SOFTWARE\Microsoft\Windows\Dwm`
- `\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile`
- `\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
- `\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`
- `\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`
- `\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
- `\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides` (NVMe)

**HKCU (User-Specific)**
- `\System\GameConfigStore`
- `\Software\Microsoft\Windows\CurrentVersion\GameDVR`
- `\Software\Microsoft\GameBar`

### Network Interfaces Modified
- All active network adapters
- TcpAckFrequency = 1
- TCPNoDelay = 1

---

## ⚠️ Important Notes

### Restart Required
After applying optimizations, a restart is **mandatory** for changes to take effect:
- Registry changes
- HAGS (Hardware Accelerated GPU Scheduling)
- Native NVMe (if enabled)
- Power plan changes

### Manual Configuration Needed

**MSI Mode** (Optional but Recommended)
- Requires: MSI Utility v3 or MSI Mode Utility
- Download: https://forums.guru3d.com/threads/windows-line-based-vs-message-signaled-based-interrupts-msi-tool.378044/
- Enable for: GPU, NVMe drives
- **AVOID**: SATA controllers, audio devices
- Risk: System instability if misconfigured

**GPU Control Panel Settings**
- **NVIDIA**: Configure G-SYNC, Low Latency Mode, Reflex
- **AMD**: Configure FreeSync, Anti-Lag+, Radeon Chill

### Security Trade-offs

Some optimizations reduce security for performance:
- **Memory Integrity (VBS)** - Disabling improves FPS by 8-15%
- **Virtual Machine Platform** - Disabling frees CPU resources
- **Recommendation**: Only disable on dedicated gaming PCs

---

## 📁 Files Created/Modified

### Backup Files (script folder)
- `Gaming-Optimization-Backup-[timestamp].reg` - Full registry backup (never deleted by the script)

### Log Files (script folder)
- `Gaming-Optimization-Log-[timestamp].txt` - Detailed operation log

### Benchmark Results (script folder + Archive/)
- `Gaming-Optimization-Benchmark-Results.json` (latest) and `Gaming-Optimization-Benchmark-[timestamp].json` snapshots
- `Archive/` keeps older timestamped baselines automatically

---

## 🔧 Troubleshooting

### "Access Denied" Errors
- **Solution**: Run PowerShell as Administrator
- Right-click PowerShell → "Run as Administrator"

### "Execution Policy" Error
- **Solution**: Allow script execution
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

### Native NVMe Not Applying
- **Check**: Windows 11 24H2+ (Build 26100+)
- **Check**: NVMe drive present
- **Solution**: Reboot after applying

### Game Stuttering After Optimization
1. Disable HAGS: Settings → System → Display → Graphics → Change default graphics settings
2. Re-enable VBS if disabled: Settings → Privacy & security → Windows Security → Device security → Core isolation
3. Check GPU drivers are up to date
4. Try rollback and reapply one optimization at a time

### AMD X3D Performance Regression
- **DO NOT** disable Xbox Game Bar on AMD X3D CPUs
- Game Bar is required for proper thread scheduling
- Keep Game Mode enabled

---

## 📖 Research Sources

This script is based on verified optimizations from:
- P40L0's PC Gaming Optimization Guide (Patreon)
- Microsoft Windows Server 2025 Native NVMe documentation
- ElevenForum Native NVMe announcement
- Community-verified tweaks (2024-2025)
- Hardware manufacturer recommendations (NVIDIA, AMD, Intel)

### Additional Research (2025)
- ElectronicsIdeas.com - Windows 11 25H2 gaming guide
- Windows-Tweaks.info - Windows 11 25H2 gaming review
- TheGamersMall.com - Windows 11 optimization guide
- XDA-Developers.com - Windows 11 gaming tweaks
- WinGeek.org - Windows 11 gaming optimization

---

## 🆚 vs. Separate Scripts

### Why Consolidate?

**Before (3 Scripts)**
- Windows-Gaming-Optimization.ps1
- Windows-Gaming-Benchmarking.ps1  
- Windows-NVMe-Optimizer.ps1

**After (1 Script)**
- Windows-Gaming-Optimization.ps1 (All-in-one)

**Benefits**:
- ✅ Simpler deployment (one file)
- ✅ Integrated workflow (benchmark → optimize → test)
- ✅ Consistent logging
- ✅ Single backup/rollback system
- ✅ Easier to maintain and update

---

## 🎓 Performance Expectations

### Realistic Improvements
- **CPU-bound games**: 2-5% FPS increase, better frame pacing
- **Input lag**: 5-10ms reduction (HAGS + optimizations)
- **Network**: 5-15ms latency reduction
- **Storage (with Native NVMe)**: Up to 80% IOPS increase

### Don't Expect Miracles
- ❌ Won't fix low-end hardware limitations
- ❌ Won't replace proper driver updates
- ❌ Won't fix game-specific bugs
- ✅ Best combined with proper GPU settings

---

## 🛡️ Safety & Reversibility

### All Changes Are Reversible
- ✅ Registry backup created automatically
- ✅ Rollback option via `-Action Rollback`
- ✅ Manual registry restore available
- ✅ System Restore compatible

### Tested & Safe
- ✅ Registry-only changes (no system files modified)
- ✅ No driver replacements (except optional Native NVMe)
- ✅ Based on reputable sources
- ✅ Backup/restore functionality included

---

## 📞 Support

### Before Asking for Help
1. ✅ Check the log file: `Desktop\Gaming-Optimization-Log-[timestamp].txt`
2. ✅ Verify administrator rights
3. ✅ Review error messages
4. ✅ Check Windows version compatibility

### Providing Feedback
Include:
- Windows version (11 22H2/23H2/24H2/25H2)
- Hardware (CPU, GPU, storage type)
- Log file contents
- Specific errors or issues

---

## ✅ Changelog

### Version 2.0 (Current - All-in-One)
- ➕ **Consolidated**: Merged 3 scripts into 1
- ➕ **Integrated Benchmarking**: Built-in testing suite
- ➕ Added HAGS, Game DVR disable, Timer Resolution, System Cache
- ➕ Integrated Native NVMe (optional with `-EnableNativeNVMe`)
- ➕ Added MSI Mode guidance
- 🔧 Enhanced backup system (12 registry keys)
- 🔧 Updated parameter system
- 📚 Expanded documentation

### Version 1.0 (Legacy - Separate Scripts)
- Initial release with 9 optimizations
- Separate benchmarking script
- Separate NVMe script
- Basic hardware detection

---

**Enjoy your optimized gaming experience! 🎮🚀**

*Remember: Always benchmark before and after to verify improvements!*
