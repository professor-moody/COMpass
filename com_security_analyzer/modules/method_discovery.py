# com_security_analyzer/modules/method_discovery.py
"""
Method Discovery Module - Discovers and analyzes COM object methods
"""
import logging
import sys
from typing import Dict, List, Optional
import win32com.client
from dataclasses import dataclass

from com_security_analyzer.core.base import BaseAnalyzer, AnalysisResult
from com_security_analyzer.core.models import MethodInfo, MethodParameter

logger = logging.getLogger(__name__)

@dataclass
class MethodDiscoveryResult(AnalysisResult):
    """Results from method discovery analysis"""
    accessible: bool
    methods: List[MethodInfo]
    error: Optional[str] = None

class MethodDiscoveryAnalyzer(BaseAnalyzer):
    """Analyzes COM object methods and their properties"""

    def analyze(self, previous_results: Dict[str, AnalysisResult]) -> Dict[str, MethodDiscoveryResult]:
        results = {}
        registry_results = previous_results.get('RegistryAnalyzer', {})
        total = len(registry_results)
        success = 0
        errors = 0
        timeouts = 0
        
        sys.stdout.write("\nMethod Discovery Analysis:\n")
        sys.stdout.write("[%s%s] 0/%d objects analyzed    \r" % ('=' * 0, ' ' * 50, total))
        sys.stdout.flush()
        
        for idx, (clsid, com_info) in enumerate(registry_results.items(), 1):
            try:
                import concurrent.futures
                import threading
                
                # Create a thread pool for timeout management
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self._discover_methods, clsid)
                    try:
                        methods = future.result(timeout=10)  # 10 second timeout per object
                        results[clsid] = MethodDiscoveryResult(
                            accessible=True,
                            methods=methods,
                            error=None
                        )
                        success += 1
                    except concurrent.futures.TimeoutError:
                        results[clsid] = MethodDiscoveryResult(
                            accessible=False,
                            methods=[],
                            error="Timeout during analysis"
                        )
                        timeouts += 1
                    except Exception as e:
                        results[clsid] = MethodDiscoveryResult(
                            accessible=False,
                            methods=[],
                            error=str(e)
                        )
                        errors += 1
            except Exception as e:
                results[clsid] = MethodDiscoveryResult(
                    accessible=False,
                    methods=[],
                    error=f"Critical error: {str(e)}"
                )
                errors += 1
            
            # Update progress bar
            progress = int(50 * idx / total)
            sys.stdout.write("[%s%s] %d/%d objects analyzed (✓:%d ✗:%d ⏱:%d)\r" % 
                ('=' * progress, ' ' * (50 - progress), idx, total, success, errors, timeouts))
            sys.stdout.flush()
        
        sys.stdout.write("\nAnalysis complete.                                         \n")
        sys.stdout.flush()
        return results

        return results

    def _discover_methods(self, clsid: str) -> List[MethodInfo]:
        """Attempt to discover methods for a COM object"""
        methods = []
        
        try:
            # Create COM object instance
            obj = win32com.client.Dispatch(clsid)
            type_info = obj._oleobj_.GetTypeInfo()
            
            # Get method count
            attr = type_info.GetTypeAttr()
            func_count = attr[6]
            
            # Enumerate methods
            for i in range(func_count):
                try:
                    # Get function description
                    func_desc = type_info.GetFuncDesc(i)
                    method_name = type_info.GetNames(func_desc[0])[0]
                    
                    # Get parameter information
                    params = []
                    for j in range(func_desc[8]):  # Number of parameters
                        param_names = type_info.GetNames(func_desc[0])
                        if len(param_names) > j + 1:  # Skip first name (method name)
                            param_name = param_names[j + 1]
                            params.append(MethodParameter(
                                name=param_name,
                                type_info=self._get_type_info(func_desc[2][j]),  # Parameter type
                                flags=func_desc[9][j]  # Parameter flags
                            ))
                    
                    methods.append(MethodInfo(
                        name=method_name,
                        parameters=params,
                        return_type=self._get_type_info(func_desc[7]),
                        flags=func_desc[3],
                        dispid=func_desc[0]
                    ))
                    
                except Exception as e:
                    logger.debug(f"Error getting method info: {e}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Error creating COM object: {e}")
            raise
            
        return methods

    def _get_type_info(self, type_id: int) -> str:
        """Convert type ID to readable string"""
        # Map of type IDs to readable names
        type_map = {
            24: "VT_VOID",
            3: "VT_I4",
            8: "VT_BSTR",
            9: "VT_DISPATCH",
            13: "VT_UNKNOWN",
            # Add more type mappings as needed
        }
        return type_map.get(type_id, f"TYPE_{type_id}")

    def analyze_method_security(self, method: MethodInfo) -> List[str]:
        """Analyze method for potential security issues"""
        warnings = []
        
        # Check for dangerous parameter types
        for param in method.parameters:
            if "DISPATCH" in param.type_info or "UNKNOWN" in param.type_info:
                warnings.append(f"Method accepts potentially dangerous type: {param.type_info}")
                
        return warnings