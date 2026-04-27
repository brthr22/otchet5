"""
Base parser module for RedCheck reports.

This module defines the abstract base class for all report parsers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class Host:
    """Represents a host from inventory report."""
    ip: str = ""
    hostname: str = ""
    os: str = ""
    architecture: str = ""
    domain_role: str = ""
    mac_address: str = ""
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    users: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    processes: List[Dict[str, Any]] = field(default_factory=list)
    installed_software: List[Dict[str, Any]] = field(default_factory=list)
    updates: List[Dict[str, Any]] = field(default_factory=list)
    security_policies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PortScan:
    """Represents port scan results from pentest report."""
    ip: str = ""
    hostname: str = ""
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    banners: List[str] = field(default_factory=list)
    smb_info: Optional[Dict[str, Any]] = None


@dataclass
class Vulnerability:
    """Represents a vulnerability from scan report."""
    id: str = ""
    name: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    exploit_available: bool = False
    exploitation_status: str = ""
    target_ip: str = ""
    target_port: int = 0
    description: str = ""
    remediation: str = ""
    cve_id: str = ""
    scan_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedData:
    """Container for all parsed data from reports."""
    hosts: List[Host] = field(default_factory=list)
    port_scans: List[PortScan] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class BaseParser(ABC):
    """Abstract base class for all RedCheck report parsers."""

    def __init__(self, file_path: str):
        """
        Initialize parser with file path.

        Args:
            file_path: Path to the XML report file
        """
        self.file_path = file_path
        self.errors: List[str] = []
        self.warnings: List[str] = []

    @abstractmethod
    def parse(self) -> ParsedData:
        """
        Parse the report file and extract data.

        Returns:
            ParsedData object containing extracted information
        """
        pass

    def _log_error(self, message: str):
        """Log an error message."""
        logger.error(f"[{self.file_path}] {message}")
        self.errors.append(message)

    def _log_warning(self, message: str):
        """Log a warning message."""
        logger.warning(f"[{self.file_path}] {message}")
        self.warnings.append(message)

    def _safe_get(self, element, tag: str, default: str = "") -> str:
        """
        Safely get text content from XML element.

        Args:
            element: XML element
            tag: Tag name to search for
            default: Default value if not found

        Returns:
            Text content or default value
        """
        try:
            if element is None:
                return default
            child = element.find(tag)
            if child is not None and child.text:
                return child.text.strip()
            return default
        except Exception as e:
            self._log_warning(f"Error getting tag '{tag}': {e}")
            return default

    def _safe_get_attr(self, element, attr: str, default: str = "") -> str:
        """
        Safely get attribute value from XML element.

        Args:
            element: XML element
            attr: Attribute name
            default: Default value if not found

        Returns:
            Attribute value or default value
        """
        try:
            if element is not None:
                return element.get(attr, default)
            return default
        except Exception as e:
            self._log_warning(f"Error getting attribute '{attr}': {e}")
            return default
