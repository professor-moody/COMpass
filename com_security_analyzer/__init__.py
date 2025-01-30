# com_security_analyzer/__init__.py
"""
COM Security Analyzer - A security testing tool for COM objects
"""
from .core.base import BaseAnalyzer, AnalysisResult
from .core.models import VulnerabilityLevel, COMObjectInfo
from .modules.registry import RegistryAnalyzer
from .modules.security import SecurityAnalyzer
from .modules.vulnerability import VulnerabilityAnalyzer

__version__ = '0.1.0'