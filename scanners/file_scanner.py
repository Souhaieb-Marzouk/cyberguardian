"""
CyberGuardian File Scanner Module
=================================
Scans files and folders for malicious indicators
using Yara, entropy analysis, PE analysis, and steganography detection.
"""

import os
import math
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
from scanners.yara_manager import get_yara_manager, YaraMatch
from utils.whitelist import get_whitelist
from utils.config import get_config
from utils.logging_utils import get_logger, log_scan_start, log_scan_complete, log_detection
from threat_intel.intel import get_threat_intel

logger = get_logger('scanners.file_scanner')


@dataclass
class FileInfo:
    """Information about a file."""
    path: Path
    name: str
    size: int
    extension: str
    mime_type: str
    entropy: float
    sha256: str
    md5: str
    is_pe: bool = False
    is_office: bool = False
    is_image: bool = False
    is_archive: bool = False
    is_whitelisted: bool = False
    has_macros: bool = False
    pe_info: Dict[str, Any] = field(default_factory=dict)


class EntropyCalculator:
    """Calculate entropy for data analysis."""
    
    @staticmethod
    def calculate(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_file(filepath: Path, chunk_size: int = 65536) -> float:
        """Calculate entropy of a file."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(chunk_size)
            return EntropyCalculator.calculate(data)
        except Exception:
            return 0.0
    
    @staticmethod
    def calculate_sections(filepath: Path, section_size: int = 1024) -> List[float]:
        """Calculate entropy for file sections."""
        entropies = []
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(section_size)
                    if not data:
                        break
                    entropies.append(EntropyCalculator.calculate(data))
        except Exception:
            pass
        return entropies


class PEAnalyzer:
    """Analyze PE (Portable Executable) files."""
    
    # Suspicious imports
    SUSPICIOUS_IMPORTS = {
        'VirtualAlloc': 'Memory allocation (common in malware)',
        'VirtualAllocEx': 'Remote memory allocation (process injection)',
        'WriteProcessMemory': 'Write to remote process (process injection)',
        'CreateRemoteThread': 'Create thread in remote process (injection)',
        'NtUnmapViewOfSection': 'Process hollowing',
        'QueueUserAPC': 'APC injection',
        'SetWindowsHookEx': 'Hook installation (keylogging)',
        'GetAsyncKeyState': 'Key state detection (keylogging)',
        'GetKeyState': 'Key state detection (keylogging)',
        'UrlDownloadToFile': 'File download',
        'InternetOpen': 'Internet access',
        'InternetOpenUrl': 'URL access',
        'InternetReadFile': 'Internet file reading',
        'WinHttpOpen': 'HTTP access',
        'ShellExecute': 'Command execution',
        'WinExec': 'Command execution',
        'CreateProcess': 'Process creation',
    }
    
    # Suspicious section names
    SUSPICIOUS_SECTIONS = {
        '.UPX': 'UPX packed',
        '.ASPack': 'ASPack packed',
        '.PCMP': 'PECompact packed',
        '.Themida': 'Themida protected',
        '.VMProt': 'VMProtect protected',
        '.vmp0': 'VMProtect protected',
        '.MPRESS': 'MPRESS packed',
        '.-packed': 'Packed executable',
    }
    
    @staticmethod
    def is_pe_file(filepath: Path) -> bool:
        """Check if file is a PE executable."""
        try:
            with open(filepath, 'rb') as f:
                dos_header = f.read(2)
                if dos_header != b'MZ':
                    return False
                
                # Check PE header
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                pe_header = f.read(4)
                return pe_header == b'PE\x00\x00'
        except Exception:
            return False
    
    @staticmethod
    def analyze(filepath: Path) -> Dict[str, Any]:
        """Analyze PE file structure."""
        result = {
            'is_pe': False,
            'is_dll': False,
            'is_64bit': False,
            'sections': [],
            'imports': [],
            'suspicious_imports': [],
            'suspicious_sections': [],
            'entry_point': 0,
            'compile_time': None,
            'has_resources': False,
            'has_tls': False,
            'is_packed': False,
            'warnings': [],
        }
        
        try:
            import pefile
            pe = pefile.PE(str(filepath))
            
            result['is_pe'] = True
            result['is_dll'] = pe.is_dll()
            result['is_64bit'] = pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            result['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            
            # Compile timestamp
            if hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
                timestamp = pe.FILE_HEADER.TimeDateStamp
                result['compile_time'] = datetime.utcfromtimestamp(timestamp).isoformat()
            
            # Analyze sections
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                
                section_info = {
                    'name': name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                }
                result['sections'].append(section_info)
                
                # Check for suspicious sections
                for sus_name, desc in PEAnalyzer.SUSPICIOUS_SECTIONS.items():
                    if sus_name.lower() in name.lower():
                        result['suspicious_sections'].append({
                            'section': name,
                            'reason': desc
                        })
                        result['is_packed'] = True
                
                # High entropy section (packed/encrypted)
                if entropy > 7.0:
                    result['warnings'].append(f"High entropy section: {name} ({entropy:.2f})")
                    result['is_packed'] = True
            
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            result['imports'].append(f"{dll}!{name}")
                            
                            # Check suspicious imports
                            for sus_imp, desc in PEAnalyzer.SUSPICIOUS_IMPORTS.items():
                                if sus_imp.lower() == name.lower():
                                    result['suspicious_imports'].append({
                                        'import': name,
                                        'dll': dll,
                                        'reason': desc
                                    })
            
            # Check for resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                result['has_resources'] = True
            
            # Check for TLS
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                result['has_tls'] = True
                result['warnings'].append("TLS callbacks present (anti-debug)")
            
            pe.close()
            
        except ImportError:
            result['warnings'].append("pefile not available for detailed analysis")
        except Exception as e:
            result['warnings'].append(f"PE analysis error: {str(e)}")
        
        return result


class OfficeAnalyzer:
    """Analyze Office documents for malicious content."""
    
    @staticmethod
    def is_office_file(filepath: Path) -> bool:
        """Check if file is an Office document."""
        office_extensions = {
            '.doc', '.docx', '.docm', '.dot', '.dotm',
            '.xls', '.xlsx', '.xlsm', '.xlt', '.xltm',
            '.ppt', '.pptx', '.pptm', '.pot', '.potm',
            '.odt', '.ods', '.odp',
        }
        return filepath.suffix.lower() in office_extensions
    
    @staticmethod
    def analyze(filepath: Path) -> Dict[str, Any]:
        """Analyze Office document for malicious indicators."""
        result = {
            'is_office': True,
            'has_macros': False,
            'macro_suspicious': False,
            'embedded_objects': [],
            'external_links': [],
            'suspicious_strings': [],
            'warnings': [],
        }
        
        # Check for macro-enabled extension
        if filepath.suffix.lower() in ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm']:
            result['has_macros'] = True
            result['warnings'].append("Macro-enabled document")
        
        try:
            import olefile
            
            # Check if it's an OLE file (older formats)
            if olefile.isOleFile(str(filepath)):
                ole = olefile.OleFileIO(str(filepath))
                
                # Check for VBA macros
                if ole.exists('Macros') or ole.exists('VBA'):
                    result['has_macros'] = True
                    result['warnings'].append("VBA macros detected in OLE file")
                
                # List streams
                for stream in ole.listdir():
                    stream_name = '/'.join(stream)
                    if any(s in stream_name.lower() for s in ['macro', 'vba', 'code']):
                        result['suspicious_strings'].append(f"Stream: {stream_name}")
                
                ole.close()
        
        except ImportError:
            result['warnings'].append("olefile not available for OLE analysis")
        except Exception as e:
            result['warnings'].append(f"OLE analysis error: {str(e)}")
        
        # Try oletools for deeper analysis
        try:
            import oletools.olevba
            import oletools.msodde
            
            vba = oletools.olevba.VBA_Parser(str(filepath))
            
            if vba.detect_vba_macros():
                result['has_macros'] = True
                
                # Extract and analyze macros
                for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                    if vba_code:
                        result['suspicious_strings'].append(f"Macro in {vba_filename}")
                        
                        # Check for suspicious VBA patterns
                        suspicious_patterns = [
                            ('CreateObject', 'COM object creation'),
                            ('Shell', 'Shell command execution'),
                            ('WScript', 'Windows Script Host'),
                            ('PowerShell', 'PowerShell execution'),
                            ('DownloadFile', 'File download'),
                            ('URLDownload', 'URL download'),
                            ('AutoOpen', 'Auto-execution'),
                            ('Document_Open', 'Auto-execution'),
                            ('Workbook_Open', 'Auto-execution'),
                        ]
                        
                        for pattern, desc in suspicious_patterns:
                            if pattern.lower() in vba_code.lower():
                                result['macro_suspicious'] = True
                                result['suspicious_strings'].append(
                                    f"Suspicious: {desc} in {vba_filename}"
                                )
            
            vba.close()
            
        except ImportError:
            result['warnings'].append("oletools not available for macro analysis")
        except Exception as e:
            result['warnings'].append(f"Macro analysis error: {str(e)}")
        
        return result


class SteganographyDetector:
    """Detect steganography in images and media files."""
    
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
    
    @staticmethod
    def is_image_file(filepath: Path) -> bool:
        """Check if file is an image."""
        return filepath.suffix.lower() in SteganographyDetector.IMAGE_EXTENSIONS
    
    @staticmethod
    def analyze(filepath: Path) -> Dict[str, Any]:
        """Analyze image for steganography indicators."""
        result = {
            'is_image': True,
            'has_steganography': False,
            'lsb_analysis': {},
            'entropy_analysis': {},
            'warnings': [],
        }
        
        try:
            # Calculate entropy
            entropy = EntropyCalculator.calculate_file(filepath)
            result['entropy_analysis']['overall'] = round(entropy, 2)
            
            # High entropy in images could indicate hidden data
            if entropy > 7.5:
                result['entropy_analysis']['high_entropy'] = True
                result['warnings'].append(f"High entropy ({entropy:.2f}) - possible hidden data")
            
            # Simple LSB analysis
            with open(filepath, 'rb') as f:
                data = f.read(1024)  # Sample first KB
                
                # Check for LSB patterns (simplified)
                lsb_zero_count = 0
                lsb_one_count = 0
                
                for byte in data:
                    if byte & 0x01:
                        lsb_one_count += 1
                    else:
                        lsb_zero_count += 1
                
                # Balanced LSB could indicate hidden data
                ratio = lsb_one_count / (lsb_zero_count + 1)
                result['lsb_analysis'] = {
                    'zeros': lsb_zero_count,
                    'ones': lsb_one_count,
                    'ratio': round(ratio, 2),
                    'balanced': 0.9 < ratio < 1.1
                }
                
                if 0.9 < ratio < 1.1:
                    result['warnings'].append("Balanced LSB pattern - possible steganography")
                    result['has_steganography'] = True
        
        except Exception as e:
            result['warnings'].append(f"Steganography analysis error: {str(e)}")
        
        return result


class FileScanner(BaseScanner):
    """
    Scanner for analyzing files and directories.
    
    Detection Methods:
    - Yara static scanning
    - Entropy analysis
    - PE file analysis
    - Office document analysis
    - Steganography detection
    - Hash lookup
    """
    
    # Maximum file size to scan (100 MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024
    
    # High entropy threshold
    HIGH_ENTROPY_THRESHOLD = 7.0
    
    # Archive extensions
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'}
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.yara_manager = get_yara_manager()
        self.threat_intel = get_threat_intel()
    
    @property
    def scanner_name(self) -> str:
        return "File Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "file"
    
    def scan(self, target: Optional[str] = None) -> ScanResult:
        """
        Scan files or directories.
        
        Args:
            target: File path or directory path to scan
        
        Returns:
            ScanResult with file analysis findings
        """
        target_path = Path(target) if target else Path.cwd()
        
        log_scan_start('file', str(target_path))
        
        result = ScanResult(
            scan_type='file',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=str(target_path)
        )
        
        self.reset_cancel()
        
        try:
            # Collect files to scan
            files = self._collect_files(target_path)
            result.total_items = len(files)
            
            self.logger.info(f"Scanning {len(files)} files")
            
            # Scan each file
            for i, filepath in enumerate(files):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                self._report_progress(i + 1, len(files), f"Analyzing {filepath.name}")
                
                # Get file info
                file_info = self._get_file_info(filepath)
                
                if not file_info:
                    continue
                
                # Skip whitelisted
                if file_info.is_whitelisted:
                    result.clean_items += 1
                    continue
                
                # Run detections
                detections = self._analyze_file(file_info)
                
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
            self.logger.error(f"File scan error: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('file', result.scan_target, len(result.detections))
        
        return result
    
    def _collect_files(self, target: Path) -> List[Path]:
        """Collect all files to scan from target path."""
        files = []
        
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            for root, _, filenames in os.walk(target):
                for filename in filenames:
                    try:
                        filepath = Path(root) / filename
                        files.append(filepath)
                    except Exception:
                        continue
        
        # Filter by size
        files = [f for f in files if f.exists() and f.stat().st_size <= self.MAX_FILE_SIZE]
        
        return files
    
    def _get_file_info(self, filepath: Path) -> Optional[FileInfo]:
        """Get comprehensive file information."""
        try:
            stat = filepath.stat()
            
            # Calculate hashes
            sha256 = self.threat_intel.calculate_file_hash(filepath, 'sha256')
            md5 = self.threat_intel.calculate_file_hash(filepath, 'md5')
            
            # Calculate entropy
            entropy = EntropyCalculator.calculate_file(filepath)
            
            # Check whitelist
            is_whitelisted = (
                self.whitelist.is_whitelisted(str(filepath), 'path') or
                self.whitelist.is_whitelisted(sha256, 'hash') if sha256 else False
            )
            
            return FileInfo(
                path=filepath,
                name=filepath.name,
                size=stat.st_size,
                extension=filepath.suffix.lower(),
                mime_type=self._get_mime_type(filepath),
                entropy=entropy,
                sha256=sha256 or '',
                md5=md5 or '',
                is_pe=PEAnalyzer.is_pe_file(filepath),
                is_office=OfficeAnalyzer.is_office_file(filepath),
                is_image=SteganographyDetector.is_image_file(filepath),
                is_archive=filepath.suffix.lower() in self.ARCHIVE_EXTENSIONS,
                is_whitelisted=is_whitelisted,
            )
        
        except Exception as e:
            self.logger.debug(f"Error getting file info for {filepath}: {e}")
            return None
    
    def _get_mime_type(self, filepath: Path) -> str:
        """Get MIME type of file."""
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(str(filepath))
            return mime_type or 'application/octet-stream'
        except Exception:
            return 'application/octet-stream'
    
    def _analyze_file(self, file_info: FileInfo) -> List[Detection]:
        """Run all detection checks on a file."""
        detections = []
        
        detection_methods = [
            self._check_yara_rules,
            self._check_entropy,
            self._check_hash_reputation,
            self._check_pe_file,
            self._check_office_document,
            self._check_steganography,
        ]
        
        for method in detection_methods:
            if self.is_cancelled():
                break
            
            try:
                method_detections = method(file_info)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        return detections
    
    def _check_yara_rules(self, file_info: FileInfo) -> List[Detection]:
        """Check file against Yara rules."""
        detections = []
        
        yara_matches = self.yara_manager.scan_file(file_info.path)
        
        if yara_matches:
            critical_matches = [m for m in yara_matches if m.severity == 'critical']
            high_matches = [m for m in yara_matches if m.severity == 'high']
            medium_matches = [m for m in yara_matches if m.severity == 'medium']
            
            if critical_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_critical',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    description=f"Critical malware signature: {', '.join(m.rule for m in critical_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in critical_matches)}",
                    remediation=[
                        f"Quarantine file: {file_info.path}",
                        "Delete file after verification",
                        "Run full system scan",
                        "Check for related malware components"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in critical_matches],
                        'sha256': file_info.sha256,
                        'entropy': file_info.entropy
                    }
                )
                detections.append(detection)
            
            elif high_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_high',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description=f"Malicious patterns: {', '.join(m.rule for m in high_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in high_matches)}",
                    remediation=[
                        f"Quarantine file: {file_info.path}",
                        "Analyze file in sandbox",
                        "Verify file source"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in high_matches],
                        'sha256': file_info.sha256
                    }
                )
                detections.append(detection)
            
            elif medium_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_medium',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.7,
                    description=f"Suspicious patterns: {', '.join(m.rule for m in medium_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in medium_matches)}",
                    remediation=[
                        "Investigate file purpose",
                        "Verify file legitimacy"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in medium_matches]
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_entropy(self, file_info: FileInfo) -> List[Detection]:
        """Check for high entropy (packed/encrypted content)."""
        detections = []
        
        if file_info.entropy > self.HIGH_ENTROPY_THRESHOLD:
            # Only flag non-image files for high entropy
            if not file_info.is_image and not file_info.is_archive:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='high_entropy',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.LOW,
                    confidence=0.5,
                    description=f"High entropy file ({file_info.entropy:.2f}) - possible packed/encrypted content",
                    detection_reason="High Shannon entropy indicates packed or encrypted data",
                    remediation=[
                        "Analyze file with appropriate tools",
                        "Check if file is legitimate encrypted archive",
                        "Scan with anti-malware"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'entropy': file_info.entropy,
                        'threshold': self.HIGH_ENTROPY_THRESHOLD
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_hash_reputation(self, file_info: FileInfo) -> List[Detection]:
        """Check file hash against threat intelligence."""
        detections = []
        
        if not file_info.sha256:
            return detections
        
        hash_result = self.threat_intel.lookup_hash(file_info.sha256, use_online=True)
        
        if hash_result.is_malicious and hash_result.confidence in ['high', 'medium']:
            risk_level = RiskLevel.CRITICAL if hash_result.confidence == 'high' else RiskLevel.HIGH
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='hash_malicious',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=risk_level,
                confidence=0.9 if hash_result.confidence == 'high' else 0.7,
                description=f"Malicious file hash: {hash_result.detection_ratio}",
                detection_reason=f"Threat intelligence match: {', '.join(hash_result.threat_names[:3])}",
                remediation=[
                    f"Delete file: {file_info.path}",
                    "Quarantine and investigate",
                    "Run full system scan",
                    "Check for related infections"
                ],
                file_path=str(file_info.path),
                evidence={
                    'sha256': file_info.sha256,
                    'md5': file_info.md5,
                    'detection_ratio': hash_result.detection_ratio,
                    'threat_names': hash_result.threat_names,
                    'source': hash_result.source
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_pe_file(self, file_info: FileInfo) -> List[Detection]:
        """Analyze PE executable files."""
        detections = []
        
        if not file_info.is_pe:
            return detections
        
        pe_result = PEAnalyzer.analyze(file_info.path)
        file_info.pe_info = pe_result
        
        # Check for packed executable
        if pe_result.get('is_packed'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='pe_packed',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description="Packed or obfuscated executable detected",
                detection_reason=f"Packing indicators: {', '.join(str(s) for s in pe_result.get('suspicious_sections', []))}",
                remediation=[
                    "Unpack executable for analysis",
                    "Scan with anti-malware",
                    f"Quarantine file: {file_info.path}"
                ],
                file_path=str(file_info.path),
                evidence={
                    'packed': True,
                    'suspicious_sections': pe_result.get('suspicious_sections', []),
                    'warnings': pe_result.get('warnings', [])
                }
            )
            detections.append(detection)
        
        # Check for suspicious imports
        suspicious_imports = pe_result.get('suspicious_imports', [])
        if len(suspicious_imports) >= 3:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='pe_suspicious_imports',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                description=f"Multiple suspicious imports: {len(suspicious_imports)}",
                detection_reason=f"Suspicious API calls: {', '.join(i['import'] for i in suspicious_imports[:5])}",
                remediation=[
                    "Analyze file behavior",
                    f"Quarantine file: {file_info.path}",
                    "Check file source and legitimacy"
                ],
                file_path=str(file_info.path),
                evidence={
                    'suspicious_imports': suspicious_imports,
                    'is_64bit': pe_result.get('is_64bit'),
                    'compile_time': pe_result.get('compile_time')
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_office_document(self, file_info: FileInfo) -> List[Detection]:
        """Analyze Office documents for malicious content."""
        detections = []
        
        if not file_info.is_office:
            return detections
        
        office_result = OfficeAnalyzer.analyze(file_info.path)
        file_info.has_macros = office_result.get('has_macros', False)
        
        # Suspicious macros
        if office_result.get('macro_suspicious'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='office_macro_suspicious',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                description="Suspicious macros detected in Office document",
                detection_reason=f"Malicious macro patterns: {', '.join(office_result.get('suspicious_strings', [])[:3])}",
                remediation=[
                    "Remove macros from document",
                    f"Delete file if untrusted: {file_info.path}",
                    "Do not enable macros",
                    "Scan with anti-malware"
                ],
                file_path=str(file_info.path),
                evidence={
                    'has_macros': True,
                    'suspicious_strings': office_result.get('suspicious_strings', []),
                    'warnings': office_result.get('warnings', [])
                }
            )
            detections.append(detection)
        
        # Has macros but not flagged as suspicious
        elif office_result.get('has_macros'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='office_macro',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description="Office document contains macros",
                detection_reason="Macro content detected - requires verification",
                remediation=[
                    "Verify document source",
                    "Remove macros if not needed",
                    "Do not enable macros unless trusted"
                ],
                file_path=str(file_info.path),
                evidence={
                    'has_macros': True
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_steganography(self, file_info: FileInfo) -> List[Detection]:
        """Check images for steganography."""
        detections = []
        
        if not file_info.is_image:
            return detections
        
        stego_result = SteganographyDetector.analyze(file_info.path)
        
        if stego_result.get('has_steganography'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='steganography',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.5,
                description="Possible steganography detected in image",
                detection_reason=f"LSB analysis indicates hidden data",
                remediation=[
                    "Verify image source",
                    "Extract and analyze hidden data",
                    f"Quarantine if suspicious: {file_info.path}"
                ],
                file_path=str(file_info.path),
                evidence={
                    'lsb_analysis': stego_result.get('lsb_analysis', {}),
                    'entropy_analysis': stego_result.get('entropy_analysis', {}),
                    'warnings': stego_result.get('warnings', [])
                }
            )
            detections.append(detection)
        
        return detections
