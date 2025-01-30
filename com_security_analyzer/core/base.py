# core/base.py
"""
Base classes and types for COM Security Analyzer
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class AnalysisResult:
    """Base class for analysis results"""
    pass

class BaseAnalyzer(ABC):
    """Base class for all analyzer modules"""
    
    @abstractmethod
    def analyze(self, previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform the analysis
        
        Args:
            previous_results: Results from previously run analyzers
            
        Returns:
            Dict mapping CLSIDs to analysis results
        """
        pass