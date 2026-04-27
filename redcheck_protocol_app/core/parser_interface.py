"""
Parser interface definition.
"""

from abc import ABC, abstractmethod
from typing import List, Any
from pathlib import Path


class ParserInterface(ABC):
    """Abstract base class for all RedCheck parsers."""
    
    @abstractmethod
    def parse(self, file_path: Path) -> Any:
        """
        Parse the input file and return structured data.
        
        Args:
            file_path: Path to the report file
            
        Returns:
            Parsed data structure (type depends on parser implementation)
            
        Raises:
            ParserError: If parsing fails
        """
        pass
    
    @abstractmethod
    def validate(self, file_path: Path) -> bool:
        """
        Validate that the file can be parsed by this parser.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            True if file appears valid for this parser type
        """
        pass


class ParserError(Exception):
    """Exception raised when parsing fails."""
    
    def __init__(self, message: str, file_path: Path = None, details: str = None):
        self.message = message
        self.file_path = file_path
        self.details = details
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        msg = self.message
        if self.file_path:
            msg = f"{msg} (file: {self.file_path})"
        if self.details:
            msg = f"{msg}: {self.details}"
        return msg
