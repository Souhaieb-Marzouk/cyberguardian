"""
CyberGuardian Process Scanner Module
====================================
Scans running processes for malicious indicators
using Yara, behavioral heuristics, hash lookup, and signature verification.
"""

import os
import sys
import psutil
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import hashlib
import threading

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
from scanners.yara_manager import get_yara_manager, YaraMatch
from utils.whitelist import get_whitelist
from utils.config import get_config
from utils.logging_utils import get_logger, log_scan_start, log_scan_complete, log_detection
from threat_intel.intel import get_threat_intel

logger = get_logger('scanners.process_scanner')


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    path: str
    command_line: str
    username: str
    parent_pid: int
    parent_name: str
    create_time: float
    cpu_percent: float
    memory_percent: float
    memory_bytes: int
    status: str
    num_threads: int
    num_handles: int
    is_signed: bool = False
    signer: str = ""
    sha256: str = ""
    is_whitelisted: bool = False


class ProcessScanner(BaseScanner):
    """
    Scanner for analyzing running processes.
    
    Detection Methods:
    - Yara memory scanning
    - Behavioral heuristics (parent-child, CPU/RAM spikes)
    - Hash lookup (VirusTotal)
    - Digital signature verification
    - Whitelist checking
    """
    
    # Suspicious parent-child process relationships
    SUSPICIOUS_RELATIONSHIPS = {
        # Office applications spawning shells
        ('winword.exe', 'powershell.exe'): 'Office app spawning PowerShell',
        ('winword.exe', 'cmd.exe'): 'Office app spawning CMD',
        ('excel.exe', 'powershell.exe'): 'Excel spawning PowerShell',
        ('excel.exe', 'cmd.exe'): 'Excel spawning CMD',
        ('powerpnt.exe', 'powershell.exe'): 'PowerPoint spawning PowerShell',
        ('powerpnt.exe', 'cmd.exe'): 'PowerPoint spawning CMD',
        ('outlook.exe', 'powershell.exe'): 'Outlook spawning PowerShell',
        ('outlook.exe', 'cmd.exe'): 'Outlook spawning CMD',
        
        # Browser spawning shells
        ('chrome.exe', 'cmd.exe'): 'Browser spawning CMD',
        ('firefox.exe', 'cmd.exe'): 'Browser spawning CMD',
        ('msedge.exe', 'cmd.exe'): 'Browser spawning CMD',
        
        # Script interpreters
        ('wscript.exe', 'powershell.exe'): 'Script spawning PowerShell',
        ('cscript.exe', 'powershell.exe'): 'Script spawning PowerShell',
        
        # Unusual system process children
        ('svchost.exe', 'powershell.exe'): 'Service host spawning PowerShell',
        ('explorer.exe', 'powershell.exe'): 'Explorer spawning PowerShell (unusual)',
    }
    
    # Processes that should not have children
    PROCESSES_NO_CHILDREN = {
        'notepad.exe',
        'calc.exe',
        'mspaint.exe',
        'wordpad.exe',
    }
    
    # Suspicious command line patterns
    SUSPICIOUS_CMD_PATTERNS = [
        (r'-enc[odedcommand]?\s+[A-Za-z0-9+/=]{20,}', 'Encoded PowerShell command'),
        (r'-w\s*hidden', 'Hidden PowerShell window'),
        (r'-windowstyle\s+hidden', 'Hidden window style'),
        (r'iex\s*\(', 'PowerShell Invoke-Expression'),
        (r'FromBase64String', 'Base64 decoding'),
        (r'Net\.WebClient', 'Web client usage'),
        (r'DownloadString', 'File download'),
        (r'Invoke-Expression', 'Dynamic code execution'),
        (r'Start-BitsTransfer', 'BITS transfer'),
        (r'certutil.*-urlcache', 'Certutil download'),
        (r'certutil.*-decode', 'Certutil decode'),
        (r'bitsadmin.*/transfer', 'BITSAdmin download'),
        (r'wmic.*process.*call.*create', 'WMI process creation'),
        (r'mshta.*http', 'HTA remote execution'),
        (r'regsvr32.*/i:.*http', 'Regsvr32 remote execution'),
        (r'rundll32.*javascript', 'Rundll32 JavaScript execution'),
        (r'cmd\.exe.*/c.*powershell', 'CMD chaining to PowerShell'),
    ]
    
    # CPU/Memory thresholds for crypto miner detection
    CPU_THRESHOLD_PERCENT = 50.0
    MEMORY_THRESHOLD_PERCENT = 30.0
    HIGH_RESOURCE_DURATION_SECONDS = 30
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.yara_manager = get_yara_manager()
        self.threat_intel = get_threat_intel()
        
        self._process_cache: Dict[int, ProcessInfo] = {}
        self._resource_history: Dict[int, List[Tuple[float, float, float]]] = {}
        self._scanned_hashes: Set[str] = set()  # Track scanned hashes to avoid duplicates within same scan
    
    def _reset_scan_state(self):
        """Reset internal state before a new scan."""
        self._process_cache.clear()
        self._resource_history.clear()
        self._scanned_hashes.clear()
    
    @property
    def scanner_name(self) -> str:
        return "Process Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "process"
    
    def scan(self, target: Optional[int] = None) -> ScanResult:
        """
        Scan running processes.
        
        Args:
            target: Optional specific PID to scan
        
        Returns:
            ScanResult with process analysis findings
        """
        log_scan_start('process', f'PID {target}' if target else 'all processes')
        
        # Reset internal state for fresh scan
        self._reset_scan_state()
        
        result = ScanResult(
            scan_type='process',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target='all' if target is None else f'pid:{target}'
        )
        
        self.reset_cancel()
        
        try:
            # Get process list
            processes = self._enumerate_processes(target)
            result.total_items = len(processes)
            
            self.logger.info(f"Scanning {len(processes)} processes")
            
            # Analyze each process
            for i, proc_info in enumerate(processes):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                self._report_progress(i + 1, len(processes), f"Analyzing {proc_info.name}")
                
                # Skip whitelisted system processes early
                if proc_info.is_whitelisted and self.whitelist.is_system_process(proc_info.name):
                    result.clean_items += 1
                    continue
                
                # Run detection checks
                detections = self._analyze_process(proc_info)
                
                for detection in detections:
                    result.add_detection(detection)
                    self._report_detection(detection)
                    log_detection(
                        detection_type=detection.detection_type,
                        indicator=detection.indicator,
                        risk_level=detection.risk_level.value,
                        description=detection.description
                    )
                
                if not detections:
                    result.clean_items += 1
            
            result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Process scan error: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('process', result.scan_target, len(result.detections))
        
        return result
    
    def _enumerate_processes(self, target_pid: Optional[int] = None) -> List[ProcessInfo]:
        """Enumerate all running processes and gather info."""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username',
                                         'ppid', 'create_time', 'cpu_percent',
                                         'memory_percent', 'memory_info', 'status',
                                         'num_threads', 'num_handles']):
            try:
                info = proc.info
                
                # Skip if target specified and not matching
                if target_pid and info['pid'] != target_pid:
                    continue
                
                # Get parent info
                parent_name = ""
                try:
                    parent = psutil.Process(info['ppid'])
                    parent_name = parent.name()
                except:
                    pass
                
                # Get path
                path = info.get('exe') or ""
                
                # Get command line
                cmdline = info.get('cmdline') or []
                cmdline_str = ' '.join(cmdline) if cmdline else ""
                
                # Get memory info
                mem_info = info.get('memory_info')
                mem_bytes = mem_info.rss if mem_info else 0
                
                # Check whitelist
                is_whitelisted = self.whitelist.is_whitelisted(info['name'], 'name')
                
                proc_info = ProcessInfo(
                    pid=info['pid'],
                    name=info.get('name', 'unknown'),
                    path=path,
                    command_line=cmdline_str,
                    username=info.get('username') or '',
                    parent_pid=info.get('ppid', 0),
                    parent_name=parent_name,
                    create_time=info.get('create_time', 0),
                    cpu_percent=info.get('cpu_percent') or 0,
                    memory_percent=info.get('memory_percent') or 0,
                    memory_bytes=mem_bytes,
                    status=info.get('status', 'unknown'),
                    num_threads=info.get('num_threads', 0),
                    num_handles=info.get('num_handles', 0),
                    is_whitelisted=is_whitelisted
                )
                
                # Cache for later lookups
                self._process_cache[proc_info.pid] = proc_info
                processes.append(proc_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return processes
    
    def _analyze_process(self, proc_info: ProcessInfo) -> List[Detection]:
        """Run all detection checks on a process."""
        detections = []
        
        # Skip system processes that are whitelisted
        if self.whitelist.is_system_process(proc_info.name):
            return detections
        
        detection_methods = [
            self._check_yara_rules,
            self._check_behavioral_heuristics,
            self._check_hash_reputation,
            self._check_digital_signature,
            self._check_resource_usage,
            self._check_command_line,
        ]
        
        for method in detection_methods:
            if self.is_cancelled():
                break
            
            try:
                method_detections = method(proc_info)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        return detections
    
    def _check_yara_rules(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check process executable against Yara rules."""
        detections = []
        
        if not proc_info.path or not Path(proc_info.path).exists():
            return detections
        
        # Scan the executable file
        yara_matches = self.yara_manager.scan_file(Path(proc_info.path))
        
        if yara_matches:
            # Group by severity
            critical_matches = [m for m in yara_matches if m.severity == 'critical']
            high_matches = [m for m in yara_matches if m.severity == 'high']
            medium_matches = [m for m in yara_matches if m.severity == 'medium']
            
            if critical_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_critical',
                    indicator=proc_info.name,
                    indicator_type='process',
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    description=f"Critical Yara rule match: {', '.join(m.rule for m in critical_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in critical_matches)}",
                    remediation=[
                        f"Terminate process with PID {proc_info.pid}",
                        f"Quarantine file: {proc_info.path}",
                        "Run full system scan with anti-malware",
                        "Investigate process origin and parent process"
                    ],
                    process_name=proc_info.name,
                    process_id=proc_info.pid,
                    file_path=proc_info.path,
                    command_line=proc_info.command_line,
                    user=proc_info.username,
                    evidence={'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in critical_matches]}
                )
                detections.append(detection)
            
            elif high_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_high',
                    indicator=proc_info.name,
                    indicator_type='process',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description=f"High severity Yara match: {', '.join(m.rule for m in high_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in high_matches)}",
                    remediation=[
                        f"Terminate process with PID {proc_info.pid}",
                        f"Analyze file: {proc_info.path}",
                        "Monitor process behavior"
                    ],
                    process_name=proc_info.name,
                    process_id=proc_info.pid,
                    file_path=proc_info.path,
                    command_line=proc_info.command_line,
                    user=proc_info.username,
                    evidence={'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in high_matches]}
                )
                detections.append(detection)
            
            elif medium_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_medium',
                    indicator=proc_info.name,
                    indicator_type='process',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.7,
                    description=f"Suspicious patterns detected: {', '.join(m.rule for m in medium_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in medium_matches)}",
                    remediation=[
                        "Investigate process behavior",
                        "Check if process is legitimate"
                    ],
                    process_name=proc_info.name,
                    process_id=proc_info.pid,
                    file_path=proc_info.path,
                    command_line=proc_info.command_line,
                    user=proc_info.username,
                    evidence={'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in medium_matches]}
                )
                detections.append(detection)
        
        return detections
    
    def _check_behavioral_heuristics(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check for suspicious behavioral patterns."""
        detections = []
        
        # Check parent-child relationship
        parent_child = (proc_info.parent_name.lower(), proc_info.name.lower())
        
        if parent_child in self.SUSPICIOUS_RELATIONSHIPS:
            description = self.SUSPICIOUS_RELATIONSHIPS[parent_child]
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='behavioral_parent_child',
                indicator=f"{proc_info.parent_name} -> {proc_info.name}",
                indicator_type='process',
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                description=f"Suspicious process relationship: {description}",
                detection_reason=description,
                remediation=[
                    f"Terminate suspicious process (PID: {proc_info.pid})",
                    f"Check parent process (PID: {proc_info.parent_pid})",
                    "Investigate source of parent process execution",
                    "Check for document or script that triggered this"
                ],
                process_name=proc_info.name,
                process_id=proc_info.pid,
                command_line=proc_info.command_line,
                user=proc_info.username,
                evidence={
                    'parent_name': proc_info.parent_name,
                    'parent_pid': proc_info.parent_pid,
                    'relationship': description
                }
            )
            detections.append(detection)
        
        # Check for processes that shouldn't have children
        if proc_info.parent_name.lower() in self.PROCESSES_NO_CHILDREN:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='behavioral_unexpected_child',
                indicator=proc_info.name,
                indicator_type='process',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                description=f"Unexpected child process from {proc_info.parent_name}",
                detection_reason=f"{proc_info.parent_name} should not spawn child processes",
                remediation=[
                    f"Investigate process (PID: {proc_info.pid})",
                    f"Check parent process {proc_info.parent_name}",
                    "Terminate if suspicious"
                ],
                process_name=proc_info.name,
                process_id=proc_info.pid,
                command_line=proc_info.command_line,
                user=proc_info.username,
                evidence={'parent_name': proc_info.parent_name}
            )
            detections.append(detection)
        
        return detections
    
    def _check_hash_reputation(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check process hash against threat intelligence."""
        detections = []
        
        if not proc_info.path or not Path(proc_info.path).exists():
            return detections
        
        # Calculate hash
        try:
            sha256 = self.threat_intel.calculate_file_hash(Path(proc_info.path), 'sha256')
            if not sha256:
                return detections
            
            proc_info.sha256 = sha256
            
            # Check whitelist first
            if self.whitelist.is_whitelisted(sha256, 'hash'):
                return detections
            
            # Lookup hash
            hash_result = self.threat_intel.lookup_hash(sha256, use_online=True)
            
            if hash_result.is_malicious and hash_result.confidence in ['high', 'medium']:
                risk_level = RiskLevel.CRITICAL if hash_result.confidence == 'high' else RiskLevel.HIGH
                
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='hash_malicious',
                    indicator=proc_info.name,
                    indicator_type='process',
                    risk_level=risk_level,
                    confidence=0.9 if hash_result.confidence == 'high' else 0.7,
                    description=f"Malicious hash detected: {hash_result.detection_ratio}",
                    detection_reason=f"Hash found in threat intelligence: {', '.join(hash_result.threat_names[:3])}",
                    remediation=[
                        f"Terminate process immediately (PID: {proc_info.pid})",
                        f"Quarantine file: {proc_info.path}",
                        "Run full anti-malware scan",
                        "Isolate system if critical"
                    ],
                    process_name=proc_info.name,
                    process_id=proc_info.pid,
                    file_path=proc_info.path,
                    command_line=proc_info.command_line,
                    user=proc_info.username,
                    evidence={
                        'sha256': sha256,
                        'detection_ratio': hash_result.detection_ratio,
                        'threat_names': hash_result.threat_names,
                        'source': hash_result.source
                    }
                )
                detections.append(detection)
        
        except Exception as e:
            self.logger.debug(f"Hash check error for {proc_info.name}: {e}")
        
        return detections
    
    def _check_digital_signature(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check if process executable has valid digital signature."""
        detections = []
        
        if not proc_info.path or not Path(proc_info.path).exists():
            return detections
        
        # Skip system paths - they're trusted
        if self.whitelist.is_whitelisted(proc_info.path, 'path'):
            return detections
        
        # Try to verify signature on Windows
        if sys.platform == 'win32':
            try:
                import win32security
                import win32api
                
                # Get signature info
                sig_verified = False
                signer_name = ""
                
                try:
                    # Use Windows trust verification
                    wintrust = __import__('win32ctypes.pywin32.wintrust', fromlist=[''])
                    # Simplified check - actual implementation would use WinVerifyTrust
                    
                    # For now, use a basic check
                    import subprocess
                    result = subprocess.run(
                        ['powershell', '-Command', 
                         f"(Get-AuthenticodeSignature '{proc_info.path}').Status"],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        status = result.stdout.strip()
                        sig_verified = (status == 'Valid')
                        
                        # Get signer name
                        result2 = subprocess.run(
                            ['powershell', '-Command',
                             f"(Get-AuthenticodeSignature '{proc_info.path}').SignerCertificate.Subject"],
                            capture_output=True, text=True, timeout=10
                        )
                        if result2.returncode == 0:
                            # Parse CN= from subject
                            subject = result2.stdout.strip()
                            if 'CN=' in subject:
                                signer_name = subject.split('CN=')[1].split(',')[0].strip()
                
                except Exception as e:
                    self.logger.debug(f"Signature check error: {e}")
                
                proc_info.is_signed = sig_verified
                proc_info.signer = signer_name
                
                # Flag unsigned processes from non-system locations
                if not sig_verified:
                    # Check if signer is trusted
                    if signer_name and self.whitelist.is_trusted_signature(signer_name):
                        return detections
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type='signature_unsigned',
                        indicator=proc_info.name,
                        indicator_type='process',
                        risk_level=RiskLevel.LOW,
                        confidence=0.5,
                        description=f"Unsigned executable: {proc_info.path}",
                        detection_reason="Process executable lacks valid digital signature",
                        remediation=[
                            "Verify software source and legitimacy",
                            "Consider obtaining signed version of software",
                            f"Scan file with anti-malware: {proc_info.path}"
                        ],
                        process_name=proc_info.name,
                        process_id=proc_info.pid,
                        file_path=proc_info.path,
                        command_line=proc_info.command_line,
                        user=proc_info.username,
                        evidence={
                            'signed': False,
                            'signer': signer_name
                        }
                    )
                    detections.append(detection)
            
            except ImportError:
                self.logger.debug("win32security not available for signature check")
        
        return detections
    
    def _check_resource_usage(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check for abnormal resource usage (crypto miner indicator)."""
        detections = []
        
        # Track resource usage over time
        current_time = time.time()
        
        if proc_info.pid not in self._resource_history:
            self._resource_history[proc_info.pid] = []
        
        self._resource_history[proc_info.pid].append(
            (current_time, proc_info.cpu_percent, proc_info.memory_percent)
        )
        
        # Keep only last 60 seconds of data
        self._resource_history[proc_info.pid] = [
            (t, c, m) for t, c, m in self._resource_history[proc_info.pid]
            if current_time - t < 60
        ]
        
        history = self._resource_history[proc_info.pid]
        
        # Need enough history
        if len(history) < 3:
            return detections
        
        # Calculate averages
        avg_cpu = sum(c for _, c, _ in history) / len(history)
        avg_mem = sum(m for _, _, m in history) / len(history)
        
        # Check for sustained high usage
        high_cpu_count = sum(1 for _, c, _ in history if c > self.CPU_THRESHOLD_PERCENT)
        high_mem_count = sum(1 for _, _, m in history if m > self.MEMORY_THRESHOLD_PERCENT)
        
        # Detect crypto miner pattern: sustained high CPU with moderate memory
        if high_cpu_count >= 3 and avg_cpu > self.CPU_THRESHOLD_PERCENT:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='resource_abuse',
                indicator=proc_info.name,
                indicator_type='process',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description=f"Sustained high CPU usage: {avg_cpu:.1f}% average",
                detection_reason="Potential crypto miner or resource abuse",
                remediation=[
                    f"Monitor process (PID: {proc_info.pid})",
                    "Verify process legitimacy",
                    "Terminate if unauthorized",
                    "Check for mining software"
                ],
                process_name=proc_info.name,
                process_id=proc_info.pid,
                file_path=proc_info.path,
                command_line=proc_info.command_line,
                user=proc_info.username,
                evidence={
                    'avg_cpu_percent': avg_cpu,
                    'avg_memory_percent': avg_mem,
                    'high_cpu_samples': high_cpu_count,
                    'sample_count': len(history)
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_command_line(self, proc_info: ProcessInfo) -> List[Detection]:
        """Check command line for suspicious patterns."""
        detections = []
        
        if not proc_info.command_line:
            return detections
        
        import re
        
        for pattern, description in self.SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, proc_info.command_line, re.IGNORECASE):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='suspicious_command',
                    indicator=proc_info.name,
                    indicator_type='process',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.8,
                    description=f"Suspicious command line: {description}",
                    detection_reason=f"Pattern matched: {description}",
                    remediation=[
                        f"Investigate process (PID: {proc_info.pid})",
                        f"Review full command line: {proc_info.command_line[:200]}",
                        "Terminate if unauthorized",
                        "Check execution source"
                    ],
                    process_name=proc_info.name,
                    process_id=proc_info.pid,
                    file_path=proc_info.path,
                    command_line=proc_info.command_line,
                    user=proc_info.username,
                    evidence={
                        'matched_pattern': pattern,
                        'description': description,
                        'command_line': proc_info.command_line[:500]
                    }
                )
                detections.append(detection)
                break  # One match per process is enough
        
        return detections
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get cached process info or enumerate fresh."""
        if pid in self._process_cache:
            return self._process_cache[pid]
        
        processes = self._enumerate_processes(pid)
        return processes[0] if processes else None
