# CyberGuardian

**Advanced Malware & Anomaly Detection Tool for Windows**

CyberGuardian is a comprehensive cybersecurity application that provides real-time threat detection, malware scanning, and AI-powered analysis capabilities. Built with Python and PyQt5, it offers a modern cyberpunk-themed interface with powerful detection engines.

![CyberGuardian Screenshot](docs/screenshots/main_interface.png)

---

## Features

### Core Scanning Capabilities

- **Process Analysis** - Scan running processes for malware signatures, behavioral anomalies, suspicious command lines, and resource abuse patterns
- **File Analysis** - Detect malware in files using Yara rules, entropy analysis, PE inspection, and hash reputation lookup
- **Registry Analysis** - Identify persistence mechanisms, suspicious autoruns, and registry-based attack indicators
- **Network Analysis** - Monitor network connections, detect beaconing behavior, and identify malicious IPs/domains

### Advanced Features

- **Real-Time Monitoring** - Continuous monitoring of process creation, file changes, and network activity
- **AI-Powered Analysis** - Integration with DeepSeek, OpenAI GPT-4, and Google Gemini for intelligent threat assessment
- **Deep Analysis Mode** - Forensic artifact collection including Windows Event Logs, PowerShell history, DNS cache, and more
- **Yara Rules Engine** - Customizable malware detection rules with automatic updates
- **Whitelist Management** - Exclude trusted applications and files from scans
- **Comprehensive Reporting** - Export findings in multiple formats (HTML, JSON, CSV)

### Security Features

- **PCI DSS & GDPR Compliant** - No personal information sent to AI providers
- **Secure API Key Storage** - Uses Windows Credential Manager for sensitive data
- **Admin Mode Detection** - Clear indication of privilege level and feature availability
- **Quarantine System** - Safely isolate detected threats

---

## Screenshots

| Main Interface | Detections Tab | AI Analysis |
|----------------|----------------|-------------|
| ![Main](docs/screenshots/main.png) | ![Detections](docs/screenshots/detections.png) | ![AI](docs/screenshots/ai_analysis.png) |

---

## System Requirements

### Minimum Requirements

- **Operating System**: Windows 10/11 (64-bit)
- **Python**: 3.9 or higher
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk Space**: 500 MB for installation + space for quarantine

### Recommended

- **Administrator Privileges**: Required for full functionality
- **Internet Connection**: For threat intelligence lookups and AI analysis

---

## Installation

### Option 1: Quick Install (Recommended for Most Users)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyberguardian.git
cd cyberguardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Option 2: Using the Executable (No Python Required)

1. Download the latest release from the [Releases](https://github.com/YOUR_USERNAME/cyberguardian/releases) page
2. Extract `CyberGuardian.zip` to your preferred location
3. Run `CyberGuardian.exe` as Administrator for full functionality

### Option 3: Development Installation

```bash
# Clone with development dependencies
git clone https://github.com/YOUR_USERNAME/cyberguardian.git
cd cyberguardian

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
python -m pytest tests/

# Run the application
python main.py
```

---

## Configuration

### First-Time Setup

1. **Launch as Administrator** - Right-click and select "Run as Administrator"
2. **Configure AI Provider** (Optional):
   - Go to Settings > AI Analysis
   - Enter your API key (DeepSeek, OpenAI, or Gemini)
   - Select preferred model
3. **Update Yara Rules** - Click "Update Rules" in Settings to get latest detection rules
4. **Configure Whitelist** - Add trusted applications to prevent false positives

### API Key Configuration

CyberGuardian supports multiple AI providers for enhanced threat analysis:

| Provider | Get API Key | Cost |
|----------|-------------|------|
| DeepSeek | [platform.deepseek.com](https://platform.deepseek.com) | Most affordable |
| OpenAI | [platform.openai.com](https://platform.openai.com) | High quality |
| Google Gemini | [ai.google.dev](https://ai.google.dev) | Free tier available |

API keys are stored securely using Windows Credential Manager.

---

## Usage Guide

### Running a Scan

1. **Select Scan Type**:
   - **Process Analysis**: Scan all running processes
   - **File Analysis**: Scan a specific file or folder
   - **Registry Analysis**: Check for persistence mechanisms
   - **Network Analysis**: Analyze active network connections

2. **Enable Deep Analysis** (Optional, Admin only):
   - Check "Deep Analysis Mode" for forensic-level scanning
   - Includes Windows Event Logs, PowerShell history, etc.

3. **Review Results**:
   - Check the "Detections" tab for all findings
   - Click "View Details" for detailed information
   - Use "Analyze with AI" for intelligent assessment

### Understanding Risk Levels

| Level | Color | Description |
|-------|-------|-------------|
| CRITICAL | Red | Confirmed malware or critical threat |
| HIGH | Orange | Strong indicators of malicious activity |
| MEDIUM | Yellow | Suspicious behavior requiring investigation |
| LOW | Green | Minor concerns or potential false positives |
| INFO | Blue | Informational findings |

### Responding to Detections

For each detection, you can:
- **Terminate Process** - Kill the suspicious process
- **Delete File** - Remove the malicious file
- **Quarantine** - Move to secure isolation
- **Add to Whitelist** - Mark as trusted

---

## Project Structure

```
cyberguardian/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── setup.py               # Installation script
├── build.py               # Build executable script
├── assets/                # Icons and images
│   └── icon.png
├── data/                  # Application data
│   ├── config.json        # User configuration
│   ├── whitelist.json     # Whitelisted items
│   └── yara_rules/        # Yara detection rules
├── scanners/              # Detection engines
│   ├── base_scanner.py    # Base scanner class
│   ├── process_scanner.py # Process analysis
│   ├── file_scanner.py    # File scanning
│   ├── registry_scanner.py# Registry analysis
│   ├── network_scanner.py # Network monitoring
│   ├── realtime_monitor.py# Real-time protection
│   ├── deep_analysis.py   # Forensic analysis
│   └── yara_manager.py    # Yara rules engine
├── ai_analysis/           # AI integration
│   └── analyzer.py        # Multi-provider AI analyzer
├── threat_intel/          # Threat intelligence
│   └── intel.py           # VirusTotal, AbuseIPDB, etc.
├── reporting/             # Report generation
│   └── generator.py       # HTML, JSON, CSV exports
├── ui/                    # User interface
│   └── main_window.py     # Main application window
└── utils/                 # Utilities
    ├── config.py          # Configuration management
    ├── logging_utils.py   # Logging system
    ├── secure_storage.py  # Secure credential storage
    └── whitelist.py       # Whitelist management
```

---

## Building from Source

### Prerequisites

```bash
# Install build dependencies
pip install pyinstaller

# Or install all development dependencies
pip install -e ".[dev]"
```

### Build Executable

```bash
# Build standalone executable
python build.py

# Output will be in dist/CyberGuardian.exe
```

### Create Distribution Package

```bash
# Build and create ZIP package
python build.py --package

# Output: dist/CyberGuardian_v1.0.0.zip
```

---

## Troubleshooting

### Common Issues

**"Access Denied" errors:**
- Run CyberGuardian as Administrator
- Right-click > "Run as Administrator"

**Deep Analysis Mode disabled:**
- Requires Administrator privileges
- Check status bar shows "ADMIN" in green

**AI Analysis not working:**
- Verify API key in Settings > AI Analysis
- Check internet connection
- Try different AI provider

**No detections shown:**
- Detections are filtered by risk level
- Check if scan completed successfully
- Review logs for errors

**Application won't start:**
- Ensure Python 3.9+ is installed
- Run `pip install -r requirements.txt`
- Check for missing dependencies

### Getting Help

1. Check the [Wiki](https://github.com/YOUR_USERNAME/cyberguardian/wiki) for detailed guides
2. Search [Issues](https://github.com/YOUR_USERNAME/cyberguardian/issues) for similar problems
3. Create a new issue with:
   - Windows version
   - Python version
   - Error messages
   - Steps to reproduce

---

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Use type hints for function parameters
- Add docstrings to all public functions
- Write unit tests for new features

---

## Security Considerations

### Data Privacy

- **No personal information** is sent to AI providers
- File paths are sanitized to remove usernames
- Only Indicators of Compromise (IOCs) are analyzed
- PCI DSS and GDPR compliant design

### API Key Security

- Keys stored in Windows Credential Manager
- Never logged or displayed in plain text
- Encrypted in memory during use

### Quarantine System

- Files are moved to isolated directory
- Original location recorded for restoration
- Quarantined files renamed with .quarantine extension

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Yara](https://virustotal.github.io/yara/) - Pattern matching for malware detection
- [VirusTotal](https://www.virustotal.com/) - Hash reputation lookup
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation database
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework reference

---

## Disclaimer

CyberGuardian is a security tool intended for legitimate security analysis and system administration purposes. Users are responsible for ensuring compliance with applicable laws and regulations. The developers are not responsible for any misuse or damage caused by this tool.

**Use responsibly and only on systems you own or have authorization to analyze.**

---

## Changelog

### Version 1.0.0
- Initial release
- Process, File, Registry, and Network scanning
- AI-powered analysis (DeepSeek, OpenAI, Gemini)
- Deep Analysis mode for forensic investigation
- Real-time monitoring
- Yara rules engine
- Whitelist management
- Comprehensive reporting

---

**Made with ❤️ by the CyberGuardian Team**
