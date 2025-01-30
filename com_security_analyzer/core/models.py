# core/models.py
"""
Data models for COM Security Analyzer
"""
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum, auto

class VulnerabilityLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class COMObjectInfo:
    """Basic information about a COM object"""
    clsid: str
    name: str
    server_type: Optional[str] = None
    server_path: Optional[str] = None
    threading_model: Optional[str] = None

@dataclass
class SecurityDescriptor:
    """Security descriptor information"""
    owner: str
    group: str
    dacl: List[Dict[str, Any]]

@dataclass
class MethodParameter:
    """Information about a COM method parameter"""
    name: str
    type_info: str
    flags: int

@dataclass
class MethodInfo:
    """Information about a COM method"""
    name: str
    parameters: List[MethodParameter]
    return_type: str
    flags: int
    dispid: Optional[int] = None