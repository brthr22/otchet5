"""
RedCheck Protocol Generator - Core Package
"""

from .models import Host, PortScan, Vulnerability, ScanMetadata
from .parser_interface import ParserInterface

__all__ = [
    'Host',
    'PortScan', 
    'Vulnerability',
    'ScanMetadata',
    'ParserInterface'
]
