#!/usr/bin/env python3
"""
CyberGuardian Dependency Installer
===================================
Automatically installs compatible dependencies based on Python version.
"""

import sys
import subprocess
from pathlib import Path


def get_python_version():
    """Get Python version as tuple."""
    return sys.version_info[:2]


def install_package(package):
    """Install a package using pip."""
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', package],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Warning: Failed to install {package}")
        print(f"  Error: {e.stderr.decode() if e.stderr else 'Unknown error'}")
        return False


def main():
    print("=" * 60)
    print("  CyberGuardian Dependency Installer")
    print("=" * 60)
    print()

    py_version = get_python_version()
    print(f"Python Version: {py_version[0]}.{py_version[1]}")
    print()

    # Core dependencies (always required)
    core_deps = [
        "PyQt5>=5.15.0",
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "urllib3>=1.26.0",
        "yara-python>=4.3.0",
        "keyring>=23.9.0",
        "cryptography>=38.0.0",
        "Pillow>=9.0.0",
    ]

    # Windows-specific dependencies
    windows_deps = [
        "pywin32>=305",
        "WMI>=1.5.1",
    ]

    # Optional dependencies based on Python version
    optional_deps = []

    # pythonnet is only compatible with Python < 3.13
    if py_version < (3, 13):
        optional_deps.append("pythonnet>=3.0.0")
    else:
        print("Note: pythonnet is not available for Python 3.13+")
        print("Some advanced Windows features may be limited.")
        print()

    print("Installing core dependencies...")
    for dep in core_deps:
        print(f"  Installing: {dep}")
        if install_package(dep):
            print(f"  ✓ {dep.split('>=')[0]}")
        else:
            print(f"  ✗ Failed: {dep}")

    # Install Windows-specific dependencies
    if sys.platform == 'win32':
        print()
        print("Installing Windows-specific dependencies...")
        for dep in windows_deps:
            print(f"  Installing: {dep}")
            if install_package(dep):
                print(f"  ✓ {dep.split('>=')[0]}")
            else:
                print(f"  ✗ Failed: {dep}")

    # Install optional dependencies
    if optional_deps:
        print()
        print("Installing optional dependencies...")
        for dep in optional_deps:
            print(f"  Installing: {dep}")
            if install_package(dep):
                print(f"  ✓ {dep.split('>=')[0]}")
            else:
                print(f"  ✗ Failed: {dep}")

    print()
    print("=" * 60)
    print("  Installation complete!")
    print("=" * 60)
    print()
    print("To run CyberGuardian:")
    print("  python main.py")
    print()
    print("For full functionality, run as Administrator.")
    print()


if __name__ == "__main__":
    main()
