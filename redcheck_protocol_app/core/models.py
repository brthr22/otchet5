"""
Data models for RedCheck protocol generator.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    ip: str = ""
    mask: str = ""
    gateway: str = ""
    dns: str = ""
    mac: str = ""
    name: str = ""


@dataclass
class Software:
    """Represents installed software."""
    name: str = ""
    version: str = ""
    install_date: str = ""


@dataclass
class UserGroup:
    """Represents a user or group."""
    name: str = ""
    type: str = ""  # 'user' or 'group'
    description: str = ""


@dataclass
class Service:
    """Represents a service or process."""
    name: str = ""
    status: str = ""  # 'running', 'stopped', etc.
    startup: str = ""  # 'auto', 'manual', 'disabled'
    path: str = ""


@dataclass
class Host:
    """
    Represents a host from inventory report.
    Contains all inventory data for a single host.
    """
    hostname: str = ""
    ip: str = ""
    os_name: str = ""
    os_version: str = ""
    os_architecture: str = ""
    domain_role: str = ""  # e.g., 'Domain Controller', 'Member Server'
    
    # Hardware
    cpu: str = ""
    ram: str = ""
    disk: str = ""
    
    # Network
    interfaces: List[NetworkInterface] = field(default_factory=list)
    
    # Software & Updates
    installed_software: List[Software] = field(default_factory=list)
    updates_kb: List[str] = field(default_factory=list)
    
    # Users & Groups
    users_groups: List[UserGroup] = field(default_factory=list)
    
    # Services & Processes
    services: List[Service] = field(default_factory=list)
    
    # Security Settings
    security_settings: Dict[str, str] = field(default_factory=dict)
    
    # Additional raw data for flexibility
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def get_primary_ip(self) -> str:
        """Get primary IP address (first non-localhost)."""
        if self.ip:
            return self.ip
        for iface in self.interfaces:
            if iface.ip and iface.ip != "127.0.0.1":
                return iface.ip
        return "unknown"


@dataclass
class PortScan:
    """Represents a port scan result for a host."""
    host_ip: str = ""
    hostname: str = ""
    scan_time: str = ""
    
    # Open ports: {port: {protocol, state, service, banner}}
    open_ports: List[Dict[str, str]] = field(default_factory=list)
    
    # SMB-specific findings
    smb_signing: str = ""  # e.g., 'required', 'not required', 'unknown'
    smb_findings: List[str] = field(default_factory=list)
    
    # Raw output for additional parsing
    raw_output: str = ""


@dataclass
class ScanMetadata:
    """Metadata about a vulnerability scan job."""
    scan_type: str = ""
    profile: str = ""
    target_ip: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: str = ""
    scanner_version: str = ""
    policy: str = ""


@dataclass
class Vulnerability:
    """Represents a single vulnerability finding."""
    vuln_id: str = ""  # Internal ID or CVE
    cve: str = ""
    title: str = ""
    description: str = ""
    
    # Severity
    severity: str = ""  # 'Critical', 'High', 'Medium', 'Low', 'Info'
    cvss_score: float = 0.0
    cvss_vector: str = ""
    
    # Exploitation status
    exploit_available: bool = False
    exploit_status: str = ""  # e.g., 'active', 'poc', 'none'
    
    # Affected host info
    affected_host: str = ""
    affected_port: int = 0
    affected_service: str = ""
    
    # Remediation
    solution: str = ""
    references: List[str] = field(default_factory=list)
    
    # Additional metadata
    plugin_id: str = ""
    first_detected: str = ""
    last_detected: str = ""
    
    # Raw data for flexibility
    raw_data: Dict[str, Any] = field(default_factory=dict)
