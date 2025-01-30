# modules/registry.py
"""
Registry Analysis Module - Discovers and analyzes COM object registry entries
"""
import logging
import winreg
from typing import Dict, Optional
from dataclasses import dataclass

# Change to relative imports
from ..core.base import BaseAnalyzer, AnalysisResult
from ..core.models import COMObjectInfo

logger = logging.getLogger(__name__)

@dataclass
class RegistryResult(AnalysisResult):
    clsid: str
    name: str
    server_type: Optional[str]
    server_path: Optional[str]
    default_value: Optional[str]
    threading_model: Optional[str]

class RegistryAnalyzer(BaseAnalyzer):
    """Analyzes COM object registry entries"""

    def analyze(self, previous_results: Dict[str, AnalysisResult]) -> Dict[str, RegistryResult]:
        results = {}
        
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID", 0, winreg.KEY_READ) as clsid_key:
                idx = 0
                while True:
                    try:
                        clsid = winreg.EnumKey(clsid_key, idx)
                        result = self._analyze_com_object(clsid)
                        if result:
                            results[clsid] = result
                        idx += 1
                    except WindowsError:
                        break
        except Exception as e:
            logger.error(f"Error enumerating COM objects: {e}")
        
        return results

    def _analyze_com_object(self, clsid: str) -> Optional[RegistryResult]:
        """Analyze a single COM object's registry entries"""
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"CLSID\\{clsid}", 0, winreg.KEY_READ) as key:
                default_value = winreg.QueryValue(key, "")
                server_type = None
                server_path = None
                threading_model = None

                # Check for server types
                for srv_type in ['LocalServer32', 'InprocServer32']:
                    try:
                        with winreg.OpenKey(key, srv_type) as server_key:
                            server_type = srv_type
                            server_path = winreg.QueryValue(server_key, "")
                            
                            # Get threading model
                            try:
                                threading_model = winreg.QueryValueEx(server_key, "ThreadingModel")[0]
                            except WindowsError:
                                pass
                            break
                    except WindowsError:
                        continue

                return RegistryResult(
                    clsid=clsid,
                    name=default_value,
                    server_type=server_type,
                    server_path=server_path,
                    default_value=default_value,
                    threading_model=threading_model
                )

        except Exception as e:
            logger.debug(f"Error analyzing COM object {clsid}: {e}")
            return None

    def get_interesting_keys(self, clsid: str) -> Dict[str, str]:
        """Get interesting registry keys for a COM object"""
        interesting_keys = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"CLSID\\{clsid}", 0, winreg.KEY_READ) as key:
                # Check for interesting subkeys
                for subkey in ['ProgID', 'TypeLib', 'Elevation']:
                    try:
                        with winreg.OpenKey(key, subkey) as sub:
                            interesting_keys[subkey] = winreg.QueryValue(sub, "")
                    except WindowsError:
                        continue
        except Exception as e:
            logger.debug(f"Error getting interesting keys for {clsid}: {e}")
        
        return interesting_keys