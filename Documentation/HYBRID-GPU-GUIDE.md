Hybrid GPU Guide
================

Overview
--------
Many laptops include both an integrated GPU (iGPU, e.g. Intel) and a discrete GPU (dGPU, e.g. NVIDIA/AMD). Windows, plus vendor technologies (Optimus, AMD Switchable Graphics), will automatically choose the dGPU for demanding apps in most cases — but per-app settings, power state, or drivers can prevent the dGPU from activating for benchmarks or games.

What the script does
--------------------
- Detects all video adapters using `Win32_VideoController`.
- Classifies adapters heuristically as integrated (Intel / Microsoft basic) or discrete (NVIDIA / AMD / Radeon).
- Provides guidance and quick actions: list per-app GPU preferences, set a preference for an app, or open Windows Graphics Settings.
- Provides helper functions: `Get-UserGPUPreferences`, `Set-UserGPUPreference`, `Remove-UserGPUPreference`, `Test-HybridGPU`, and `Show-HybridGPUGuidance`.

How to ensure a game/benchmark uses the dGPU
--------------------------------------------
1. Plug in to AC power and use a high-performance power profile.
2. Use Windows Settings -> System -> Display -> Graphics -> add the game executable and set it to "High performance".
3. Use the GPU vendor control panel (NVIDIA Control Panel, AMD Adrenalin, Intel Graphics Command Center) to force the app to use the dGPU.
4. Confirm by observing GPU activity in Task Manager (Performance -> GPU engine) or vendor tools like `nvidia-smi` (if present).

Using the script helpers (notes & caveats)
----------------------------------------
- The script reads/writes `HKCU:\Software\Microsoft\DirectX\UserGpuPreferences` entries as simple `REG_SZ` values like `GpuPreference=2` (2 = HighPerformance). Windows and OEM driver behavior can vary across Windows builds and laptop OEMs.
- Prefer the Settings UI or vendor control panel for production changes. The script's registry helpers are provided for convenience and automation but include confirmations to avoid accidental changes.
- After changing per-app GPU preferences you may need to restart the application or sign out/sign in for the change to take effect.

Recommendations for benchmarking
--------------------------------
- Ensure the laptop is on AC power and the power plan is set to High Performance (or the OEM's performance plan).
- Close background apps and OEM utilities that may interfere with GPU switching.
- If the dGPU still doesn't activate, update both iGPU and dGPU drivers and check BIOS/UEFI settings (some systems allow forcing discrete-only mode).

Further reading
---------------
- Windows Graphics Settings (ms-settings:display-graphics)
- NVIDIA Optimus / NVIDIA Control Panel
- AMD Switchable Graphics / AMD Adrenalin
- Intel Graphics Command Center

Contact
-------
This guide is distributed with the `Windows-Gaming-Optimization.ps1` script. Use the script's `Show-HybridGPUGuidance` to interactively list and set preferences.
