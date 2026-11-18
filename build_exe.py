#!/usr/bin/env python3
"""Build script for AntiSuspended standalone Windows executable (.exe)."""
import subprocess
import sys
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    script = root / "claude_profile_win.py"
    icon = root / "app_icon.ico"
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        "--uac-admin",
        "--icon", str(icon),
        "--name", "AntiSuspended",
        "--collect-data", "tzdata",
        "--hidden-import", "curses",
        "--hidden-import", "_curses",
        "--add-data", f"{icon};.",
        str(script)
    ]
    
    print("Building AntiSuspended.exe with PyInstaller (UAC Admin + Embedded Icon)...")
    res = subprocess.run(cmd, cwd=str(root))
    if res.returncode == 0:
        exe_path = root / "dist" / "AntiSuspended.exe"
        print(f"\n[OK] Executable built successfully: {exe_path}")
    else:
        print("\n[FAIL] Build failed.", file=sys.stderr)
        sys.exit(res.returncode)

if __name__ == "__main__":
    main()
