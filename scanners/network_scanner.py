"""
CyberGuardian Network Scanner Module
====================================
Scans network connections for suspicious activity
and threat intelligence correlation.
"""

import os
import sys
import socket
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import threading
from collections import defaultdict

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
from utils.whitelist import get_whitelist
from utils.config import get_config
from utils.logging_utils import get_logger, log_scan_start, log_scan_complete, log_detection
from threat_intel.intel import get_threat_intel

logger = get_logger('scanners.network_scanner')


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    protocol: str
    pid: int
    process_name: str
    process_path: str = ""
    remote_hostname: str = ""
    is_whitelisted: bool = False
    is_suspicious: bool = False


class NetworkScanner(BaseScanner):
    """
    Scanner for analyzing network connections.
    
    Detection Methods:
    - Connection enumeration
    - IP/Domain threat intelligence lookup
    - Beaconing detection
    - Suspicious port detection
    - Process correlation
    """
    
    # Suspicious ports commonly used by malware
    SUSPICIOUS_PORTS = {
        # Common malware C2 ports
        4444: 'Metasploit default',
        5555: 'Common backdoor',
        6666: 'Common backdoor',
        6667: 'IRC (often used by botnets)',
        8888: 'Common backdoor',
        9999: 'Common backdoor',
        12345: 'NetBus',
        12346: 'NetBus',
        31337: 'Elite/Backdoor',
        4443: 'Metasploit HTTPS',
        5554: 'Common worm',
        3389: 'RDP (check for unauthorized)',
        5800: 'VNC HTTP',
        5900: 'VNC',
        5901: 'VNC',
        
        # Database ports (often targeted)
        1433: 'MSSQL',
        1434: 'MSSQL Monitor',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        
        # SMB/Windows
        445: 'SMB (check for external connections)',
        139: 'NetBIOS',
    }
    
    # Trusted ports for common services
    TRUSTED_PORTS = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        25: 'SMTP',
        587: 'SMTP TLS',
        993: 'IMAPS',
        995: 'POP3S',
        110: 'POP3',
        143: 'IMAP',
        21: 'FTP',
        22: 'SSH',
        123: 'NTP',
    }
    
    # Connection statuses to analyze
    ANALYZED_STATUSES = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'TIME_WAIT'}
    
    # Beaconing detection thresholds
    BEACON_INTERVAL_MIN = 5  # seconds
    BEACON_INTERVAL_MAX = 3600  # 1 hour
    BEACON_TOLERANCE = 0.2  # 20% tolerance in interval
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.threat_intel = get_threat_intel()
        
        # Connection history for beaconing detection
        self._connection_history: Dict[str, List[float]] = defaultdict(list)
        self._last_snapshot: Set[Tuple] = set()
    
    @property
    def scanner_name(self) -> str:
        return "Network Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "network"
    
    def scan(self, target: Optional[str] = None) -> ScanResult:
        """
        Scan network connections.
        
        Args:
            target: Optional specific IP or process to analyze
        
        Returns:
            ScanResult with network analysis findings
        """
        log_scan_start('network', target or 'all connections')
        
        result = ScanResult(
            scan_type='network',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=target or 'all'
        )
        
        self.reset_cancel()
        
        try:
            # Enumerate connections
            connections = self._enumerate_connections(target)
            result.total_items = len(connections)
            
            self.logger.info(f"Scanning {len(connections)} network connections")
            
            # Analyze each connection
            for i, conn in enumerate(connections):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                self._report_progress(i + 1, len(connections), f"Analyzing {conn.remote_ip}:{conn.remote_port}")
                
                # Skip whitelisted
                if conn.is_whitelisted:
                    result.clean_items += 1
                    continue
                
                # Run detections
                detections = self._analyze_connection(conn)
                
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
            self.logger.error(f"Network scan error: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('network', result.scan_target, len(result.detections))
        
        return result
    
    def _enumerate_connections(self, target: Optional[str] = None) -> List[ConnectionInfo]:
        """Enumerate all network connections."""
        connections = []
        
        try:
            import psutil
            
            # Get all connections
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Skip connections without remote address
                    if not conn.raddr:
                        continue
                    
                    # Skip if not in analyzed statuses
                    if conn.status not in self.ANALYZED_STATUSES:
                        continue
                    
                    local_ip, local_port = conn.laddr
                    remote_ip, remote_port = conn.raddr
                    
                    # Filter by target if specified
                    if target:
                        if target not in remote_ip and target != str(conn.pid):
                            continue
                    
                    # Get process info
                    process_name = ""
                    process_path = ""
                    
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                        process_path = proc.exe() or ""
                    except:
                        process_name = f"PID-{conn.pid}"
                    
                    # Determine protocol
                    protocol = 'TCP' if conn.family == socket.AF_INET else 'TCP6'
                    if conn.type == socket.SOCK_DGRAM:
                        protocol = 'UDP' if conn.family == socket.AF_INET else 'UDP6'
                    
                    # Check whitelist
                    is_whitelisted = (
                        self.whitelist.is_whitelisted(remote_ip, 'ip') or
                        self._is_trusted_port(remote_port)
                    )
                    
                    # Reverse DNS lookup
                    remote_hostname = ""
                    if self.config.config.scan.network_resolve_dns:
                        try:
                            remote_hostname = self.threat_intel.reverse_dns(remote_ip) or ""
                        except:
                            pass
                        
                        if remote_hostname and self.whitelist.is_whitelisted(remote_hostname, 'domain'):
                            is_whitelisted = True
                    
                    conn_info = ConnectionInfo(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        status=conn.status,
                        protocol=protocol,
                        pid=conn.pid or 0,
                        process_name=process_name,
                        process_path=process_path,
                        remote_hostname=remote_hostname,
                        is_whitelisted=is_whitelisted
                    )
                    
                    connections.append(conn_info)
                    
                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue
        
        except ImportError:
            self.logger.error("psutil not available for network scanning")
        
        return connections
    
    def _is_trusted_port(self, port: int) -> bool:
        """Check if port is a trusted service port."""
        return port in self.TRUSTED_PORTS
    
    def _analyze_connection(self, conn: ConnectionInfo) -> List[Detection]:
        """Analyze a network connection for suspicious indicators."""
        detections = []
        
        detection_methods = [
            self._check_suspicious_port,
            self._check_threat_intelligence,
            self._check_suspicious_process,
            self._check_unusual_destination,
        ]
        
        for method in detection_methods:
            if self.is_cancelled():
                break
            
            try:
                method_detections = method(conn)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        return detections
    
    def _check_suspicious_port(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for connections to suspicious ports."""
        detections = []
        
        if conn.remote_port in self.SUSPICIOUS_PORTS:
            port_desc = self.SUSPICIOUS_PORTS[conn.remote_port]
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_suspicious_port',
                indicator=f"{conn.remote_ip}:{conn.remote_port}",
                indicator_type='network',
                risk_level=RiskLevel.HIGH,
                confidence=0.7,
                description=f"Connection to suspicious port {conn.remote_port} ({port_desc})",
                detection_reason=f"Port {conn.remote_port} commonly used by malware: {port_desc}",
                remediation=[
                    f"Block IP in firewall: {conn.remote_ip}",
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    "Investigate process behavior",
                    "Check for malware on system"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'port_description': port_desc,
                    'process_name': conn.process_name,
                    'protocol': conn.protocol,
                    'hostname': conn.remote_hostname
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_threat_intelligence(self, conn: ConnectionInfo) -> List[Detection]:
        """Check IP against threat intelligence feeds."""
        detections = []
        
        # Check IP reputation
        ip_result = self.threat_intel.check_ip_reputation(conn.remote_ip, use_online=True)
        
        if ip_result.is_malicious:
            risk_level = RiskLevel.HIGH if ip_result.abuse_score >= 75 else RiskLevel.MEDIUM
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_malicious_ip',
                indicator=conn.remote_ip,
                indicator_type='network',
                risk_level=risk_level,
                confidence=0.85 if ip_result.confidence == 'high' else 0.6,
                description=f"Connection to malicious IP: {conn.remote_ip}",
                detection_reason=f"IP has abuse score {ip_result.abuse_score}%, {ip_result.reports_count} reports",
                remediation=[
                    f"Block IP in firewall: {conn.remote_ip}",
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    "Run full system scan",
                    "Check for data exfiltration"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'abuse_score': ip_result.abuse_score,
                    'threat_types': ip_result.threat_types,
                    'country': ip_result.country,
                    'reports_count': ip_result.reports_count,
                    'source': ip_result.source,
                    'hostname': conn.remote_hostname
                }
            )
            detections.append(detection)
        
        # Check domain reputation if available
        if conn.remote_hostname:
            domain_result = self.threat_intel.check_domain_reputation(conn.remote_hostname)
            
            if domain_result.is_malicious:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_malicious_domain',
                    indicator=conn.remote_hostname,
                    indicator_type='network',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.8,
                    description=f"Connection to malicious domain: {conn.remote_hostname}",
                    detection_reason=f"Domain flagged as malicious: {', '.join(domain_result.threat_types)}",
                    remediation=[
                        f"Block domain: {conn.remote_hostname}",
                        f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                        "Flush DNS cache",
                        "Check hosts file for modifications"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'domain': conn.remote_hostname,
                        'remote_ip': conn.remote_ip,
                        'threat_types': domain_result.threat_types,
                        'categories': domain_result.categories
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_suspicious_process(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for suspicious processes making network connections."""
        detections = []
        
        # Processes that shouldn't make outbound connections
        no_network_processes = {
            'notepad.exe', 'calc.exe', 'mspaint.exe', 'wordpad.exe',
            'write.exe', 'sndrec32.exe', 'charmap.exe',
        }
        
        if conn.process_name.lower() in no_network_processes:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_unexpected_process',
                indicator=conn.process_name,
                indicator_type='network',
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                description=f"Unexpected network activity from {conn.process_name}",
                detection_reason=f"{conn.process_name} should not make network connections",
                remediation=[
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    f"Quarantine executable: {conn.process_path}",
                    "Scan system for malware",
                    "Investigate process injection"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'process_name': conn.process_name,
                    'process_path': conn.process_path,
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port
                }
            )
            detections.append(detection)
        
        # Check for system processes making external connections
        system_processes = {
            'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
            'services.exe', 'smss.exe', 'wininit.exe'
        }
        
        if conn.process_name.lower() in system_processes:
            # Check if connecting to external (non-local) IP
            if not conn.remote_ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.',
                                               '172.18.', '172.19.', '172.20.', '172.21.',
                                               '172.22.', '172.23.', '172.24.', '172.25.',
                                               '172.26.', '172.27.', '172.28.', '172.29.',
                                               '172.30.', '172.31.')):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_system_process_external',
                    indicator=conn.process_name,
                    indicator_type='network',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.6,
                    description=f"System process {conn.process_name} connecting externally",
                    detection_reason=f"{conn.process_name} making external connection to {conn.remote_ip}",
                    remediation=[
                        f"Verify process legitimacy: {conn.process_name} (PID: {conn.pid})",
                        f"Check if {conn.process_name} is genuine Windows binary",
                        "Monitor connection behavior"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'process_name': conn.process_name,
                        'remote_ip': conn.remote_ip,
                        'remote_port': conn.remote_port
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_unusual_destination(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for unusual destination patterns."""
        detections = []
        
        # Check for direct IP connections (no DNS resolution)
        if not conn.remote_hostname and conn.remote_port in [80, 443]:
            # HTTP/HTTPS to direct IP is suspicious
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_direct_ip_http',
                indicator=conn.remote_ip,
                indicator_type='network',
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                description=f"HTTP connection to IP without DNS: {conn.remote_ip}",
                detection_reason="Direct IP connection bypasses DNS filtering",
                remediation=[
                    "Verify connection legitimacy",
                    f"Check process: {conn.process_name}",
                    "Consider blocking if unauthorized"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'process_name': conn.process_name
                }
            )
            detections.append(detection)
        
        # Check for high-numbered ports with significant data transfer
        if conn.remote_port > 49152:
            if conn.process_name.lower() not in ['chrome.exe', 'firefox.exe', 'msedge.exe',
                                                   'steam.exe', 'discord.exe', 'teams.exe']:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_ephemeral_port',
                    indicator=f"{conn.remote_ip}:{conn.remote_port}",
                    indicator_type='network',
                    risk_level=RiskLevel.LOW,
                    confidence=0.4,
                    description=f"Connection to ephemeral port: {conn.remote_port}",
                    detection_reason="High port number may indicate custom C2 protocol",
                    remediation=[
                        "Monitor connection behavior",
                        "Verify process legitimacy"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'remote_ip': conn.remote_ip,
                        'remote_port': conn.remote_port,
                        'process_name': conn.process_name
                    }
                )
                detections.append(detection)
        
        return detections
    
    def detect_beaconing(self, observation_window: int = 300) -> List[Detection]:
        """
        Detect beaconing behavior over time.
        Must be called repeatedly to build connection history.
        
        Args:
            observation_window: Time window in seconds to analyze
        
        Returns:
            List of detections for beaconing behavior
        """
        detections = []
        current_time = time.time()
        
        # Get current connections
        connections = self._enumerate_connections()
        current_snapshot = {
            (c.remote_ip, c.remote_port, c.pid)
            for c in connections
        }
        
        # Record timestamps for each connection
        for conn in connections:
            key = f"{conn.remote_ip}:{conn.remote_port}:{conn.pid}"
            self._connection_history[key].append(current_time)
        
        # Trim history to observation window
        for key in self._connection_history:
            self._connection_history[key] = [
                t for t in self._connection_history[key]
                if current_time - t <= observation_window
            ]
        
        # Analyze for beaconing patterns
        for key, timestamps in self._connection_history.items():
            if len(timestamps) < 5:  # Need enough samples
                continue
            
            # Sort timestamps
            timestamps = sorted(timestamps)
            
            # Calculate intervals
            intervals = [
                timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            
            if not intervals:
                continue
            
            # Calculate mean and variance
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # Check for regular intervals (low variance)
            if mean_interval >= self.BEACON_INTERVAL_MIN and mean_interval <= self.BEACON_INTERVAL_MAX:
                # Low coefficient of variation indicates beaconing
                cv = std_dev / mean_interval if mean_interval > 0 else 0
                
                if cv < self.BEACON_TOLERANCE:
                    # Parse key
                    parts = key.rsplit(':', 2)
                    remote_ip = parts[0]
                    remote_port = int(parts[1])
                    pid = int(parts[2])
                    
                    # Find process name
                    process_name = "unknown"
                    for conn in connections:
                        if conn.remote_ip == remote_ip and conn.remote_port == remote_port and conn.pid == pid:
                            process_name = conn.process_name
                            break
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type='network_beaconing',
                        indicator=f"{remote_ip}:{remote_port}",
                        indicator_type='network',
                        risk_level=RiskLevel.HIGH,
                        confidence=0.75,
                        description=f"Beaconing detected: {mean_interval:.1f}s interval",
                        detection_reason=f"Regular connection interval ({mean_interval:.1f}s) indicates C2 beaconing",
                        remediation=[
                            f"Block IP: {remote_ip}",
                            f"Terminate process: {process_name} (PID: {pid})",
                            "Investigate for malware",
                            "Check for data exfiltration"
                        ],
                        process_name=process_name,
                        process_id=pid,
                        evidence={
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'mean_interval': mean_interval,
                            'std_deviation': std_dev,
                            'sample_count': len(timestamps),
                            'intervals': intervals[:10]  # First 10 intervals
                        }
                    )
                    detections.append(detection)
        
        return detections
