"""
CyberGuardian Deep Analysis Module
===================================
Provides deep forensic analysis capabilities including:
- Windows Event Log analysis
- PowerShell logging analysis
- Registry forensic artifacts
- Network forensic artifacts
- File system artifacts

This module enhances the basic detection with contextual information
from Windows artifacts for more comprehensive AI analysis.
"""

import os
import sys
import logging
import re
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import threading

from utils.logging_utils import get_logger

logger = get_logger('scanners.deep_analysis')


@dataclass
class DeepAnalysisResult:
    """Result of deep analysis for a detection."""
    # Process context
    process_creation_event: Optional[Dict[str, Any]] = None
    parent_process_info: Optional[Dict[str, Any]] = None
    process_tree: List[Dict[str, Any]] = field(default_factory=list)
    loaded_modules: List[str] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    
    # PowerShell context
    powershell_events: List[Dict[str, Any]] = field(default_factory=list)
    script_blocks: List[str] = field(default_factory=list)
    
    # Event log context
    related_events: List[Dict[str, Any]] = field(default_factory=list)
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    
    # Registry context
    registry_changes: List[Dict[str, Any]] = field(default_factory=list)
    persistence_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    user_assist_entries: List[Dict[str, Any]] = field(default_factory=list)
    
    # File context
    alternate_data_streams: List[Dict[str, Any]] = field(default_factory=list)
    prefetch_info: Optional[Dict[str, Any]] = None
    usn_journal_entries: List[Dict[str, Any]] = field(default_factory=list)
    
    # Network context
    dns_cache: List[Dict[str, Any]] = field(default_factory=list)
    hosts_file_entries: List[Dict[str, Any]] = field(default_factory=list)
    firewall_events: List[Dict[str, Any]] = field(default_factory=list)
    
    # Timeline
    event_timeline: List[Dict[str, Any]] = field(default_factory=list)
    
    # Summary
    analysis_summary: str = ""
    risk_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for AI analysis."""
        return {
            'process_creation_event': self.process_creation_event,
            'parent_process_info': self.parent_process_info,
            'process_tree': self.process_tree,
            'loaded_modules': self.loaded_modules,
            'network_connections': self.network_connections,
            'powershell_events': self.powershell_events,
            'script_blocks': self.script_blocks,
            'related_events': self.related_events,
            'security_events': self.security_events,
            'registry_changes': self.registry_changes,
            'persistence_artifacts': self.persistence_artifacts,
            'user_assist_entries': self.user_assist_entries,
            'alternate_data_streams': self.alternate_data_streams,
            'prefetch_info': self.prefetch_info,
            'dns_cache': self.dns_cache,
            'hosts_file_entries': self.hosts_file_entries,
            'firewall_events': self.firewall_events,
            'event_timeline': self.event_timeline[:20],  # Limit timeline
            'analysis_summary': self.analysis_summary,
            'risk_indicators': self.risk_indicators,
        }


class WindowsEventLogAnalyzer:
    """Analyze Windows Event Logs for security context."""
    
    # Important Security Event IDs
    SECURITY_EVENTS = {
        4688: 'Process Creation',
        4689: 'Process Termination',
        4624: 'Successful Logon',
        4625: 'Failed Logon',
        4634: 'Logoff',
        4648: 'Explicit Credential Logon',
        4672: 'Special Privileges Assigned',
        4673: 'Privileged Service Called',
        4688: 'Process Creation',
        4689: 'Process Termination',
        4656: 'Handle to Object Requested',
        4658: 'Handle to Object Closed',
        4663: 'Object Access',
        4702: 'Scheduled Task Updated',
        4698: 'Scheduled Task Created',
        4699: 'Scheduled Task Deleted',
        4700: 'Scheduled Task Enabled',
        4701: 'Scheduled Task Disabled',
        4720: 'User Account Created',
        4722: 'User Account Enabled',
        4724: 'Password Reset Attempt',
        4728: 'User Added to Global Group',
        4732: 'User Added to Local Group',
        4738: 'User Account Changed',
        4740: 'Account Lockout',
        4768: 'Kerberos TGT Requested',
        4769: 'Kerberos Service Ticket Requested',
        4776: 'NTLM Authentication',
        5140: 'Network Share Accessed',
        5142: 'Network Share Object Added',
        5144: 'Network Share Object Deleted',
        5145: 'Network Share Object Checked',
    }
    
    # PowerShell Event IDs
    POWERSHELL_EVENTS = {
        4103: 'PowerShell Module Logging',
        4104: 'PowerShell Script Block Logging',
        4105: 'PowerShell Command Started',
        4106: 'PowerShell Command Stopped',
    }
    
    # System Event IDs
    SYSTEM_EVENTS = {
        7036: 'Service Status Change',
        7040: 'Service Start Type Changed',
        7045: 'Service Installed (Suspicious)',
        7023: 'Service Crashed',
        7024: 'Service Error',
        7031: 'Service Crashed',
        7032: 'Service Manager Error',
        7034: 'Service Crashed Unexpectedly',
    }
    
    def __init__(self):
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        """Check if Windows Event Log access is available."""
        if sys.platform != 'win32':
            return False
        try:
            import win32evtlog
            return True
        except ImportError:
            return False
    
    def query_security_events(
        self,
        event_ids: Optional[List[int]] = None,
        time_range_hours: int = 24,
        process_name: Optional[str] = None,
        process_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Query Windows Security Event Log."""
        if not self.available:
            return []
        
        events = []
        event_ids = event_ids or list(self.SECURITY_EVENTS.keys())
        
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con
            
            # Open Security log
            handle = win32evtlog.OpenEventLog(None, 'Security')
            
            # Calculate time filter
            start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
            
            # Read events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            total_read = 0
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                
                for record in records:
                    try:
                        event_id = record.EventID & 0xFFFF
                        
                        # Filter by event ID
                        if event_id not in event_ids:
                            continue
                        
                        # Time filter
                        event_time = record.TimeGenerated
                        if event_time.replace(tzinfo=None) < start_time:
                            continue
                        
                        # Parse event data
                        event_data = self._parse_event_record(record, event_id)
                        
                        # Filter by process if specified
                        if process_name and process_name.lower() not in event_data.get('process_name', '').lower():
                            continue
                        if process_id and event_data.get('process_id') != process_id:
                            continue
                        
                        events.append(event_data)
                        
                        # Limit results
                        if len(events) >= 100:
                            break
                    
                    except Exception as e:
                        logger.debug(f"Error parsing event record: {e}")
                
                total_read += len(records)
                if len(events) >= 100 or total_read > 10000:
                    break
            
            win32evtlog.CloseEventLog(handle)
        
        except Exception as e:
            logger.error(f"Error querying security events: {e}")
        
        return events
    
    def query_powershell_events(
        self,
        time_range_hours: int = 24,
        script_block_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query PowerShell operational log for script blocks."""
        if not self.available:
            return []
        
        events = []
        
        try:
            import win32evtlog
            
            # Open PowerShell operational log
            handle = win32evtlog.OpenEventLog(
                None,
                'Microsoft-Windows-PowerShell/Operational'
            )
            
            start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                
                for record in records:
                    try:
                        event_id = record.EventID & 0xFFFF
                        
                        if event_id not in self.POWERSHELL_EVENTS:
                            continue
                        
                        event_time = record.TimeGenerated
                        if event_time.replace(tzinfo=None) < start_time:
                            continue
                        
                        # Parse PowerShell event
                        event_data = self._parse_powershell_event(record, event_id)
                        
                        # Filter by script content if specified
                        if script_block_filter:
                            if script_block_filter.lower() not in event_data.get('script_block', '').lower():
                                continue
                        
                        events.append(event_data)
                        
                        if len(events) >= 50:
                            break
                    
                    except Exception as e:
                        logger.debug(f"Error parsing PowerShell event: {e}")
                
                if len(events) >= 50:
                    break
            
            win32evtlog.CloseEventLog(handle)
        
        except Exception as e:
            logger.debug(f"PowerShell log not available: {e}")
        
        return events
    
    def query_system_events(
        self,
        event_ids: Optional[List[int]] = None,
        time_range_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Query Windows System Event Log."""
        if not self.available:
            return []
        
        events = []
        event_ids = event_ids or list(self.SYSTEM_EVENTS.keys())
        
        try:
            import win32evtlog
            
            handle = win32evtlog.OpenEventLog(None, 'System')
            start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                
                for record in records:
                    try:
                        event_id = record.EventID & 0xFFFF
                        
                        if event_id not in event_ids:
                            continue
                        
                        event_time = record.TimeGenerated
                        if event_time.replace(tzinfo=None) < start_time:
                            continue
                        
                        event_data = {
                            'event_id': event_id,
                            'event_type': self.SYSTEM_EVENTS.get(event_id, 'Unknown'),
                            'time': event_time.isoformat(),
                            'source': record.SourceName,
                            'description': self._get_event_description(record),
                        }
                        
                        events.append(event_data)
                        
                        if len(events) >= 50:
                            break
                    
                    except Exception as e:
                        logger.debug(f"Error parsing system event: {e}")
                
                if len(events) >= 50:
                    break
            
            win32evtlog.CloseEventLog(handle)
        
        except Exception as e:
            logger.error(f"Error querying system events: {e}")
        
        return events
    
    def get_process_creation_event(self, process_id: int) -> Optional[Dict[str, Any]]:
        """Get process creation event (4688) for a specific PID."""
        events = self.query_security_events(
            event_ids=[4688],
            time_range_hours=72,
            process_id=process_id
        )
        return events[0] if events else None
    
    def _parse_event_record(self, record, event_id: int) -> Dict[str, Any]:
        """Parse event log record."""
        try:
            import win32evtlogutil
            description = win32evtlogutil.SafeFormatMessage(record, 'Security')
        except:
            description = str(record.StringInserts) if record.StringInserts else ""
        
        return {
            'event_id': event_id,
            'event_type': self.SECURITY_EVENTS.get(event_id, 'Unknown'),
            'time': record.TimeGenerated.isoformat() if record.TimeGenerated else "",
            'source': record.SourceName,
            'computer': record.ComputerName,
            'description': description[:500],
            'raw_data': {
                'event_category': record.EventCategory,
                'event_type': record.EventType,
                'string_inserts': list(record.StringInserts)[:10] if record.StringInserts else []
            }
        }
    
    def _parse_powershell_event(self, record, event_id: int) -> Dict[str, Any]:
        """Parse PowerShell event log record."""
        script_block = ""
        try:
            if record.StringInserts:
                for insert in record.StringInserts:
                    if insert and len(insert) > 50:
                        script_block = insert
                        break
        except:
            pass
        
        return {
            'event_id': event_id,
            'event_type': self.POWERSHELL_EVENTS.get(event_id, 'Unknown'),
            'time': record.TimeGenerated.isoformat() if record.TimeGenerated else "",
            'script_block': script_block[:1000],
            'script_length': len(script_block),
            'suspicious_patterns': self._detect_suspicious_powershell(script_block)
        }
    
    def _detect_suspicious_powershell(self, script: str) -> List[str]:
        """Detect suspicious patterns in PowerShell scripts."""
        patterns = []
        suspicious = [
            (r'IEX\s*\(', 'Invoke-Expression'),
            (r'Invoke-Expression', 'Dynamic code execution'),
            (r'DownloadString', 'File download'),
            (r'FromBase64String', 'Base64 decoding'),
            (r'-enc[odedcommand]?\s', 'Encoded command'),
            (r'-w\s*hidden', 'Hidden window'),
            (r'-windowstyle\s+hidden', 'Hidden window'),
            (r'Net\.WebClient', 'Web client usage'),
            (r'Start-BitsTransfer', 'BITS transfer'),
            (r'certutil', 'Certutil usage'),
            (r'mimikatz', 'Mimikatz reference'),
            (r'invoke-mimikatz', 'Mimikatz execution'),
            (r'Get-Clipboard', 'Clipboard access'),
            (r'Get-Keystroke', 'Keylogging'),
            (r'ScreenCapture', 'Screen capture'),
            (r'Get-Process', 'Process enumeration'),
            (r'Get-NetTCPConnection', 'Network enumeration'),
            (r'Invoke-WmiMethod', 'WMI execution'),
            (r'ScheduledTask', 'Scheduled task manipulation'),
            (r'Register-ScheduledTask', 'Persistence via scheduled task'),
            (r'New-Service', 'Service creation'),
            (r'Set-ExecutionPolicy', 'Execution policy change'),
            (r'AppLocker', 'AppLocker bypass attempt'),
            (r'AMSIBypass', 'AMSI bypass attempt'),
            (r'Disable-RealtimeMonitoring', 'Defender disable attempt'),
            (r'Set-MpPreference', 'Defender configuration change'),
        ]
        
        script_lower = script.lower()
        for pattern, desc in suspicious:
            if re.search(pattern, script_lower, re.IGNORECASE):
                patterns.append(desc)
        
        return patterns
    
    def _get_event_description(self, record) -> str:
        """Get human-readable event description."""
        try:
            import win32evtlogutil
            return win32evtlogutil.SafeFormatMessage(record)[:500]
        except:
            return ""


class ProcessDeepAnalyzer:
    """Deep analysis for process detections."""
    
    def __init__(self):
        self.event_analyzer = WindowsEventLogAnalyzer()
    
    def analyze_process(
        self,
        process_name: str,
        process_id: int,
        command_line: Optional[str] = None,
        parent_pid: Optional[int] = None
    ) -> DeepAnalysisResult:
        """Perform deep analysis on a process detection."""
        result = DeepAnalysisResult()
        
        if sys.platform != 'win32':
            result.analysis_summary = "Deep analysis only available on Windows"
            return result
        
        # Get process creation event
        try:
            result.process_creation_event = self.event_analyzer.get_process_creation_event(process_id)
        except Exception as e:
            logger.debug(f"Could not get process creation event: {e}")
        
        # Get loaded modules (DLLs)
        try:
            result.loaded_modules = self._get_loaded_modules(process_id)
        except Exception as e:
            logger.debug(f"Could not get loaded modules: {e}")
        
        # Get network connections for this process
        try:
            result.network_connections = self._get_process_network_connections(process_id)
        except Exception as e:
            logger.debug(f"Could not get network connections: {e}")
        
        # Get related PowerShell events
        if 'powershell' in process_name.lower():
            try:
                result.powershell_events = self.event_analyzer.query_powershell_events(
                    script_block_filter=command_line
                )
                result.script_blocks = [e.get('script_block', '') for e in result.powershell_events if e.get('script_block')]
            except Exception as e:
                logger.debug(f"Could not get PowerShell events: {e}")
        
        # Get related security events
        try:
            result.security_events = self.event_analyzer.query_security_events(
                time_range_hours=24,
                process_name=process_name
            )[:10]
        except Exception as e:
            logger.debug(f"Could not get security events: {e}")
        
        # Build timeline
        result.event_timeline = self._build_timeline(result)
        
        # Identify risk indicators
        result.risk_indicators = self._identify_risk_indicators(result, process_name, command_line)
        
        # Generate summary
        result.analysis_summary = self._generate_summary(result, process_name)
        
        return result
    
    def _get_loaded_modules(self, pid: int) -> List[str]:
        """Get list of loaded DLLs for a process."""
        modules = []
        try:
            import psutil
            proc = psutil.Process(pid)
            for dll in proc.memory_maps():
                if dll.path.endswith('.dll'):
                    modules.append(dll.path)
        except Exception as e:
            logger.debug(f"Error getting modules: {e}")
        return modules[:50]
    
    def _get_process_network_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Get network connections for a process."""
        connections = []
        try:
            import psutil
            proc = psutil.Process(pid)
            for conn in proc.connections():
                if conn.raddr:
                    connections.append({
                        'local': f"{conn.laddr[0]}:{conn.laddr[1]}",
                        'remote': f"{conn.raddr[0]}:{conn.raddr[1]}",
                        'status': conn.status,
                        'protocol': 'TCP' if conn.type == 1 else 'UDP'
                    })
        except Exception as e:
            logger.debug(f"Error getting connections: {e}")
        return connections[:20]
    
    def _build_timeline(self, result: DeepAnalysisResult) -> List[Dict[str, Any]]:
        """Build event timeline from all collected data."""
        timeline = []
        
        # Add process creation event
        if result.process_creation_event:
            timeline.append({
                'time': result.process_creation_event.get('time', ''),
                'event': 'Process Creation',
                'details': result.process_creation_event.get('description', '')[:100]
            })
        
        # Add security events
        for event in result.security_events[:10]:
            timeline.append({
                'time': event.get('time', ''),
                'event': event.get('event_type', 'Security Event'),
                'details': event.get('description', '')[:100]
            })
        
        # Add PowerShell events
        for event in result.powershell_events[:5]:
            timeline.append({
                'time': event.get('time', ''),
                'event': 'PowerShell Execution',
                'details': f"Script block ({event.get('script_length', 0)} chars)"
            })
        
        # Sort by time
        timeline.sort(key=lambda x: x.get('time', ''), reverse=True)
        
        return timeline[:20]
    
    def _identify_risk_indicators(
        self,
        result: DeepAnalysisResult,
        process_name: str,
        command_line: Optional[str]
    ) -> List[str]:
        """Identify risk indicators from collected data."""
        indicators = []
        
        # Check for suspicious PowerShell patterns
        for event in result.powershell_events:
            if event.get('suspicious_patterns'):
                indicators.extend(event['suspicious_patterns'])
        
        # Check for suspicious DLLs
        suspicious_dlls = [
            'inject', 'hook', 'keylog', 'capture', 'steal',
            'mimikatz', 'meterpreter', 'cobalt'
        ]
        for module in result.loaded_modules:
            module_lower = module.lower()
            for susp in suspicious_dlls:
                if susp in module_lower:
                    indicators.append(f"Suspicious DLL loaded: {os.path.basename(module)}")
        
        # Check network connections
        for conn in result.network_connections:
            remote = conn.get('remote', '')
            # Check for connections to suspicious ports
            if ':4444' in remote or ':5555' in remote or ':6666' in remote:
                indicators.append(f"Connection to backdoor port: {remote}")
        
        # Check command line
        if command_line:
            cmd_lower = command_line.lower()
            suspicious_cmd = [
                ('-enc', 'Encoded PowerShell command'),
                ('-w hidden', 'Hidden window'),
                ('iex', 'Dynamic code execution'),
                ('downloadstring', 'Download functionality'),
                ('mimikatz', 'Mimikatz reference'),
                ('bypass', 'Execution policy bypass'),
            ]
            for pattern, desc in suspicious_cmd:
                if pattern in cmd_lower:
                    indicators.append(desc)
        
        return list(set(indicators))[:15]
    
    def _generate_summary(self, result: DeepAnalysisResult, process_name: str) -> str:
        """Generate analysis summary."""
        parts = [f"Deep analysis for {process_name}:"]
        
        if result.loaded_modules:
            parts.append(f"Loaded {len(result.loaded_modules)} modules")
        
        if result.network_connections:
            parts.append(f"{len(result.network_connections)} active network connections")
        
        if result.powershell_events:
            parts.append(f"{len(result.powershell_events)} related PowerShell events")
        
        if result.risk_indicators:
            parts.append(f"{len(result.risk_indicators)} risk indicators identified")
        
        return ". ".join(parts) + "."


class FileDeepAnalyzer:
    """Deep analysis for file detections."""
    
    def __init__(self):
        self.event_analyzer = WindowsEventLogAnalyzer()
    
    def analyze_file(
        self,
        file_path: str,
        sha256: Optional[str] = None
    ) -> DeepAnalysisResult:
        """Perform deep analysis on a file detection."""
        result = DeepAnalysisResult()
        
        if sys.platform != 'win32':
            result.analysis_summary = "Deep analysis only available on Windows"
            return result
        
        path = Path(file_path)
        
        # Check for Alternate Data Streams
        try:
            result.alternate_data_streams = self._get_alternate_data_streams(file_path)
        except Exception as e:
            logger.debug(f"Could not get ADS: {e}")
        
        # Get prefetch info
        try:
            result.prefetch_info = self._get_prefetch_info(path.name)
        except Exception as e:
            logger.debug(f"Could not get prefetch info: {e}")
        
        # Check for related security events
        try:
            result.security_events = self.event_analyzer.query_security_events(
                time_range_hours=24,
                process_name=path.name
            )[:5]
        except Exception as e:
            logger.debug(f"Could not get security events: {e}")
        
        # Get USN journal entries (file system changes)
        try:
            result.usn_journal_entries = self._get_usn_entries(file_path)
        except Exception as e:
            logger.debug(f"Could not get USN entries: {e}")
        
        # Build timeline
        result.event_timeline = self._build_timeline(result)
        
        # Identify risk indicators
        result.risk_indicators = self._identify_risk_indicators(result, file_path)
        
        # Generate summary
        result.analysis_summary = self._generate_summary(result, file_path)
        
        return result
    
    def _get_alternate_data_streams(self, file_path: str) -> List[Dict[str, Any]]:
        """Get Alternate Data Streams for a file."""
        streams = []
        try:
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', f"Get-Item -Path '{file_path}' -Stream * | Select-Object Stream, Length"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[3:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] != ':$DATA':
                        streams.append({
                            'stream_name': parts[0],
                            'size': int(parts[1]) if parts[1].isdigit() else 0
                        })
        except Exception as e:
            logger.debug(f"Error getting ADS: {e}")
        
        return streams
    
    def _get_prefetch_info(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get prefetch file information for an executable."""
        prefetch_dir = Path('C:/Windows/Prefetch')
        if not prefetch_dir.exists():
            return None
        
        try:
            # Find prefetch file
            prefetch_name = filename.upper().replace('.EXE', '') + '-*.pf'
            for pf_file in prefetch_dir.glob(prefetch_name):
                stat = pf_file.stat()
                return {
                    'prefetch_file': str(pf_file),
                    'last_execution': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'size': stat.st_size
                }
        except Exception as e:
            logger.debug(f"Error getting prefetch: {e}")
        
        return None
    
    def _get_usn_entries(self, file_path: str) -> List[Dict[str, Any]]:
        """Get USN journal entries for a file (simplified)."""
        entries = []
        # This requires admin privileges and specialized tools
        # For now, return empty - full implementation would use fsutil
        return entries
    
    def _build_timeline(self, result: DeepAnalysisResult) -> List[Dict[str, Any]]:
        """Build event timeline."""
        timeline = []
        
        if result.prefetch_info:
            timeline.append({
                'time': result.prefetch_info.get('last_execution', ''),
                'event': 'Last Execution (Prefetch)',
                'details': f"File was executed"
            })
        
        for event in result.security_events[:5]:
            timeline.append({
                'time': event.get('time', ''),
                'event': event.get('event_type', 'Security Event'),
                'details': event.get('description', '')[:100]
            })
        
        return sorted(timeline, key=lambda x: x.get('time', ''), reverse=True)[:10]
    
    def _identify_risk_indicators(self, result: DeepAnalysisResult, file_path: str) -> List[str]:
        """Identify risk indicators."""
        indicators = []
        
        # Check for hidden ADS
        for ads in result.alternate_data_streams:
            if ads['stream_name'].startswith('$') or ads['stream_name'].startswith('Zone'):
                indicators.append(f"Hidden data stream: {ads['stream_name']}")
        
        # Check file location
        suspicious_paths = ['\\Temp\\', '\\AppData\\Local\\Temp\\', '\\Public\\', '\\Downloads\\']
        for susp_path in suspicious_paths:
            if susp_path.lower() in file_path.lower():
                indicators.append(f"File in suspicious location: {susp_path}")
        
        return indicators[:10]
    
    def _generate_summary(self, result: DeepAnalysisResult, file_path: str) -> str:
        """Generate analysis summary."""
        parts = [f"Deep analysis for {os.path.basename(file_path)}:"]
        
        if result.alternate_data_streams:
            parts.append(f"{len(result.alternate_data_streams)} alternate data streams found")
        
        if result.prefetch_info:
            parts.append("Has execution history in prefetch")
        
        if result.risk_indicators:
            parts.append(f"{len(result.risk_indicators)} risk indicators identified")
        
        return ". ".join(parts) + "."


class RegistryDeepAnalyzer:
    """Deep analysis for registry detections."""
    
    def __init__(self):
        self.event_analyzer = WindowsEventLogAnalyzer()
    
    def analyze_registry(
        self,
        key_path: str,
        value_data: Optional[str] = None
    ) -> DeepAnalysisResult:
        """Perform deep analysis on a registry detection."""
        result = DeepAnalysisResult()
        
        if sys.platform != 'win32':
            result.analysis_summary = "Deep analysis only available on Windows"
            return result
        
        # Get UserAssist entries (program execution history)
        try:
            result.user_assist_entries = self._get_user_assist_entries()
        except Exception as e:
            logger.debug(f"Could not get UserAssist: {e}")
        
        # Check for related persistence artifacts
        try:
            result.persistence_artifacts = self._get_persistence_artifacts(key_path)
        except Exception as e:
            logger.debug(f"Could not get persistence artifacts: {e}")
        
        # Get related security events
        try:
            result.security_events = self.event_analyzer.query_security_events(
                event_ids=[4656, 4663],  # Object access events
                time_range_hours=24
            )[:5]
        except Exception as e:
            logger.debug(f"Could not get security events: {e}")
        
        # Build timeline
        result.event_timeline = self._build_timeline(result)
        
        # Identify risk indicators
        result.risk_indicators = self._identify_risk_indicators(result, key_path, value_data)
        
        # Generate summary
        result.analysis_summary = self._generate_summary(result, key_path)
        
        return result
    
    def _get_user_assist_entries(self) -> List[Dict[str, Any]]:
        """Get UserAssist entries (program execution history)."""
        entries = []
        
        try:
            import winreg
            
            # UserAssist keys
            userassist_paths = [
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"),
            ]
            
            for hive, path in userassist_paths:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    
                    # Enumerate subkeys
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            
                            # Try to decode ROT13
                            decoded_name = self._rot13_decode(subkey_name)
                            
                            # Get value
                            try:
                                subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                                value, _ = winreg.QueryValueEx(subkey, 'Count')
                                winreg.CloseKey(subkey)
                                
                                entries.append({
                                    'encoded_name': subkey_name,
                                    'decoded_path': decoded_name,
                                    'run_count': value if isinstance(value, int) else 0
                                })
                            except:
                                pass
                            
                            i += 1
                        except OSError:
                            break
                    
                    winreg.CloseKey(key)
                    
                    if entries:
                        break
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Error getting UserAssist: {e}")
        
        return entries[:20]
    
    def _rot13_decode(self, text: str) -> str:
        """Decode ROT13 encoded text."""
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            elif 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    def _get_persistence_artifacts(self, key_path: str) -> List[Dict[str, Any]]:
        """Get related persistence artifacts."""
        artifacts = []
        
        try:
            import winreg
            
            # Check common persistence locations
            persistence_locations = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            ]
            
            for hive, path in persistence_locations:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            artifacts.append({
                                'location': f"HKLM\\{path}" if hive == winreg.HKEY_LOCAL_MACHINE else f"HKCU\\{path}",
                                'name': name,
                                'data': str(data)[:200]
                            })
                            i += 1
                        except OSError:
                            break
                    
                    winreg.CloseKey(key)
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Error getting persistence artifacts: {e}")
        
        return artifacts[:30]
    
    def _build_timeline(self, result: DeepAnalysisResult) -> List[Dict[str, Any]]:
        """Build event timeline."""
        timeline = []
        
        for event in result.security_events[:5]:
            timeline.append({
                'time': event.get('time', ''),
                'event': event.get('event_type', 'Registry Access'),
                'details': event.get('description', '')[:100]
            })
        
        return timeline[:10]
    
    def _identify_risk_indicators(
        self,
        result: DeepAnalysisResult,
        key_path: str,
        value_data: Optional[str]
    ) -> List[str]:
        """Identify risk indicators."""
        indicators = []
        
        # Check for IFEO
        if 'Image File Execution Options' in key_path:
            indicators.append('IFEO debugger injection detected - critical persistence mechanism')
        
        # Check for suspicious persistence
        if value_data:
            suspicious = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'regsvr32']
            for susp in suspicious:
                if susp in value_data.lower():
                    indicators.append(f'Suspicious execution via {susp} in registry')
        
        # Check UserAssist for recently executed suspicious programs
        for entry in result.user_assist_entries:
            path = entry.get('decoded_path', '').lower()
            if any(s in path for s in ['mimikatz', 'procdump', 'lazagne', 'meterpreter']):
                indicators.append(f"Recently executed suspicious program: {entry.get('decoded_path', '')}")
        
        return indicators[:10]
    
    def _generate_summary(self, result: DeepAnalysisResult, key_path: str) -> str:
        """Generate analysis summary."""
        parts = [f"Deep analysis for registry key:"]
        
        if result.persistence_artifacts:
            parts.append(f"{len(result.persistence_artifacts)} persistence artifacts found")
        
        if result.user_assist_entries:
            parts.append(f"{len(result.user_assist_entries)} UserAssist entries (execution history)")
        
        if result.risk_indicators:
            parts.append(f"{len(result.risk_indicators)} risk indicators identified")
        
        return ". ".join(parts) + "."


class NetworkDeepAnalyzer:
    """Deep analysis for network detections."""
    
    def __init__(self):
        self.event_analyzer = WindowsEventLogAnalyzer()
    
    def analyze_network(
        self,
        remote_ip: str,
        remote_port: Optional[int] = None,
        process_name: Optional[str] = None
    ) -> DeepAnalysisResult:
        """Perform deep analysis on a network detection."""
        result = DeepAnalysisResult()
        
        if sys.platform != 'win32':
            result.analysis_summary = "Deep analysis only available on Windows"
            return result
        
        # Get DNS cache
        try:
            result.dns_cache = self._get_dns_cache()
        except Exception as e:
            logger.debug(f"Could not get DNS cache: {e}")
        
        # Check hosts file
        try:
            result.hosts_file_entries = self._get_hosts_entries()
        except Exception as e:
            logger.debug(f"Could not get hosts file: {e}")
        
        # Get firewall events
        try:
            result.firewall_events = self._get_firewall_events()
        except Exception as e:
            logger.debug(f"Could not get firewall events: {e}")
        
        # Get related security events
        try:
            result.security_events = self.event_analyzer.query_security_events(
                event_ids=[5140, 5142, 5145],  # Network share events
                time_range_hours=24
            )[:5]
        except Exception as e:
            logger.debug(f"Could not get security events: {e}")
        
        # Build timeline
        result.event_timeline = self._build_timeline(result)
        
        # Identify risk indicators
        result.risk_indicators = self._identify_risk_indicators(result, remote_ip, remote_port)
        
        # Generate summary
        result.analysis_summary = self._generate_summary(result, remote_ip)
        
        return result
    
    def _get_dns_cache(self) -> List[Dict[str, Any]]:
        """Get DNS cache entries."""
        entries = []
        
        try:
            import subprocess
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                # Parse DNS cache output
                current_entry = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Record Name'):
                        if current_entry:
                            entries.append(current_entry)
                        current_entry = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('A (Host) Record'):
                        current_entry['type'] = 'A'
                        current_entry['ip'] = line.split(':', 1)[1].strip()
                    elif line.startswith('AAAA Record'):
                        current_entry['type'] = 'AAAA'
                        current_entry['ip'] = line.split(':', 1)[1].strip()
                
                if current_entry:
                    entries.append(current_entry)
        
        except Exception as e:
            logger.debug(f"Error getting DNS cache: {e}")
        
        return entries[:30]
    
    def _get_hosts_entries(self) -> List[Dict[str, Any]]:
        """Get suspicious hosts file entries."""
        entries = []
        hosts_path = Path('C:/Windows/System32/drivers/etc/hosts')
        
        try:
            if hosts_path.exists():
                with open(hosts_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip, *hosts = parts
                                # Flag suspicious redirects
                                if ip in ['127.0.0.1', '0.0.0.0']:
                                    entries.append({
                                        'ip': ip,
                                        'hosts': hosts,
                                        'suspicious': any(h in ['localhost'] for h in hosts) == False
                                    })
                                elif ip not in ['::1']:
                                    entries.append({
                                        'ip': ip,
                                        'hosts': hosts,
                                        'suspicious': True  # Non-local hosts entry
                                    })
        
        except Exception as e:
            logger.debug(f"Error reading hosts file: {e}")
        
        return entries[:20]
    
    def _get_firewall_events(self) -> List[Dict[str, Any]]:
        """Get Windows Firewall events."""
        events = []
        
        try:
            import win32evtlog
            
            handle = win32evtlog.OpenEventLog(
                None,
                'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
            )
            
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            
            for record in (records or [])[:20]:
                try:
                    events.append({
                        'time': record.TimeGenerated.isoformat() if record.TimeGenerated else "",
                        'event_id': record.EventID & 0xFFFF,
                        'description': str(record.StringInserts)[:200] if record.StringInserts else ""
                    })
                except:
                    pass
            
            win32evtlog.CloseEventLog(handle)
        
        except Exception as e:
            logger.debug(f"Firewall log not available: {e}")
        
        return events[:10]
    
    def _build_timeline(self, result: DeepAnalysisResult) -> List[Dict[str, Any]]:
        """Build event timeline."""
        timeline = []
        
        for event in result.firewall_events[:5]:
            timeline.append({
                'time': event.get('time', ''),
                'event': 'Firewall Event',
                'details': event.get('description', '')[:100]
            })
        
        for event in result.security_events[:5]:
            timeline.append({
                'time': event.get('time', ''),
                'event': event.get('event_type', 'Network Security Event'),
                'details': event.get('description', '')[:100]
            })
        
        return sorted(timeline, key=lambda x: x.get('time', ''), reverse=True)[:10]
    
    def _identify_risk_indicators(
        self,
        result: DeepAnalysisResult,
        remote_ip: str,
        remote_port: Optional[int]
    ) -> List[str]:
        """Identify risk indicators."""
        indicators = []
        
        # Check if IP is in hosts file (DNS hijacking)
        for entry in result.hosts_file_entries:
            if entry.get('suspicious') and entry.get('ip') == remote_ip:
                indicators.append(f"IP found in hosts file: potential DNS hijacking")
        
        # Check DNS cache for suspicious entries
        for entry in result.dns_cache:
            if entry.get('ip') == remote_ip:
                indicators.append(f"IP in DNS cache: {entry.get('name', 'unknown')}")
        
        # Check for suspicious ports
        if remote_port:
            suspicious_ports = [4444, 5555, 6666, 31337, 12345]
            if remote_port in suspicious_ports:
                indicators.append(f"Connection to known backdoor port: {remote_port}")
        
        return indicators[:10]
    
    def _generate_summary(self, result: DeepAnalysisResult, remote_ip: str) -> str:
        """Generate analysis summary."""
        parts = [f"Deep analysis for {remote_ip}:"]
        
        if result.dns_cache:
            parts.append(f"{len(result.dns_cache)} DNS cache entries")
        
        if result.hosts_file_entries:
            suspicious_hosts = sum(1 for e in result.hosts_file_entries if e.get('suspicious'))
            if suspicious_hosts:
                parts.append(f"{suspicious_hosts} suspicious hosts file entries")
        
        if result.firewall_events:
            parts.append(f"{len(result.firewall_events)} recent firewall events")
        
        if result.risk_indicators:
            parts.append(f"{len(result.risk_indicators)} risk indicators identified")
        
        return ". ".join(parts) + "."


# Main deep analysis orchestrator
class DeepAnalysisOrchestrator:
    """Orchestrates deep analysis for all detection types."""
    
    def __init__(self):
        self.process_analyzer = ProcessDeepAnalyzer()
        self.file_analyzer = FileDeepAnalyzer()
        self.registry_analyzer = RegistryDeepAnalyzer()
        self.network_analyzer = NetworkDeepAnalyzer()
    
    def analyze(
        self,
        detection_type: str,
        indicator: str,
        process_name: Optional[str] = None,
        process_id: Optional[int] = None,
        file_path: Optional[str] = None,
        command_line: Optional[str] = None,
        key_path: Optional[str] = None,
        value_data: Optional[str] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
    ) -> DeepAnalysisResult:
        """
        Perform deep analysis based on detection type.
        
        Args:
            detection_type: Type of detection
            indicator: The indicator that was detected
            process_name: Name of process (for process detections)
            process_id: PID of process (for process detections)
            file_path: File path (for file detections)
            command_line: Command line (for process detections)
            key_path: Registry key path (for registry detections)
            value_data: Registry value data (for registry detections)
            remote_ip: Remote IP (for network detections)
            remote_port: Remote port (for network detections)
        
        Returns:
            DeepAnalysisResult with forensic context
        """
        # Determine analysis type based on detection_type
        detection_lower = detection_type.lower()
        
        if 'process' in detection_lower or 'yara' in detection_lower or 'behavioral' in detection_lower:
            return self.process_analyzer.analyze_process(
                process_name=process_name or indicator,
                process_id=process_id or 0,
                command_line=command_line,
                parent_pid=None
            )
        
        elif 'file' in detection_lower or 'entropy' in detection_lower or 'pe_' in detection_lower:
            return self.file_analyzer.analyze_file(
                file_path=file_path or indicator
            )
        
        elif 'registry' in detection_lower or 'ifeo' in detection_lower:
            return self.registry_analyzer.analyze_registry(
                key_path=key_path or indicator,
                value_data=value_data
            )
        
        elif 'network' in detection_lower or 'ip' in detection_lower or 'beacon' in detection_lower:
            return self.network_analyzer.analyze_network(
                remote_ip=remote_ip or indicator,
                remote_port=remote_port,
                process_name=process_name
            )
        
        # Default: return empty result
        return DeepAnalysisResult(analysis_summary="No deep analysis available for this detection type")


# Global instance
_deep_analysis_instance: Optional[DeepAnalysisOrchestrator] = None


def get_deep_analyzer() -> DeepAnalysisOrchestrator:
    """Get the global deep analysis instance."""
    global _deep_analysis_instance
    if _deep_analysis_instance is None:
        _deep_analysis_instance = DeepAnalysisOrchestrator()
    return _deep_analysis_instance
