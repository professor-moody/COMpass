# modules/security.py
"""
Security Analysis Module - Analyzes COM object security descriptors and permissions
"""
import logging
from typing import Dict, List, Optional
import win32security
import win32api
import win32con
import winreg
from dataclasses import dataclass

from ..core.base import BaseAnalyzer, AnalysisResult
from ..core.models import COMObjectInfo

logger = logging.getLogger(__name__)

@dataclass
class SecurityResult(AnalysisResult):
    permissions: List[Dict]
    owner: Optional[str] = None
    group: Optional[str] = None

class SecurityAnalyzer(BaseAnalyzer):
    """Analyzes COM object security settings"""

    def analyze(self, previous_results: Dict[str, AnalysisResult]) -> Dict[str, SecurityResult]:
        results = {}
        registry_results = previous_results.get('RegistryAnalyzer', {})
        
        # Iterate over CLSIDs directly from the dictionary
        for clsid in registry_results.keys():
            try:
                security_info = self._analyze_security(clsid)
                if security_info:
                    results[clsid] = security_info
            except Exception as e:
                logger.debug(f"Failed to analyze security for {clsid}: {e}")
                
        return results

    def _analyze_security(self, clsid: str) -> Optional[SecurityResult]:
        """Analyze security settings for a single COM object"""
        try:
            # Open the registry key
            key_path = f"CLSID\\{clsid}"
            hkey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path, 0, winreg.KEY_READ)
            
            # Get security descriptor
            sd = win32security.GetSecurityInfo(
                hkey.handle,
                win32security.SE_REGISTRY_KEY,
                win32security.OWNER_SECURITY_INFORMATION | 
                win32security.GROUP_SECURITY_INFORMATION | 
                win32security.DACL_SECURITY_INFORMATION
            )

            # Get owner and group
            owner_sid = sd.GetSecurityDescriptorOwner()
            group_sid = sd.GetSecurityDescriptorGroup()
            
            owner = self._sid_to_account(owner_sid)
            group = self._sid_to_account(group_sid)

            # Get DACL permissions
            dacl = sd.GetSecurityDescriptorDacl()
            permissions = []
            
            if dacl:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid = ace[2]
                    access_mask = ace[1]
                    
                    account = self._sid_to_account(sid)
                    access_rights = self._get_access_rights(access_mask)
                    
                    permissions.append({
                        'account': account,
                        'access_mask': access_mask,
                        'rights': access_rights
                    })

            return SecurityResult(
                permissions=permissions,
                owner=owner,
                group=group
            )

        except Exception as e:
            logger.debug(f"Error analyzing security for {clsid}: {e}")
            return None

    def _sid_to_account(self, sid) -> str:
        """Convert a SID to account name"""
        try:
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
        except win32security.error:
            return str(sid)

    def _get_access_rights(self, access_mask: int) -> List[str]:
        """Convert access mask to list of rights"""
        rights = []
        
        # Standard rights
        if access_mask & win32con.DELETE:
            rights.append("DELETE")
        if access_mask & win32con.READ_CONTROL:
            rights.append("READ_CONTROL")
        if access_mask & win32con.WRITE_DAC:
            rights.append("WRITE_DAC")
        if access_mask & win32con.WRITE_OWNER:
            rights.append("WRITE_OWNER")
        
        # Registry specific rights
        if access_mask & win32con.KEY_QUERY_VALUE:
            rights.append("QUERY_VALUE")
        if access_mask & win32con.KEY_SET_VALUE:
            rights.append("SET_VALUE")
        if access_mask & win32con.KEY_CREATE_SUB_KEY:
            rights.append("CREATE_SUB_KEY")
        if access_mask & win32con.KEY_ENUMERATE_SUB_KEYS:
            rights.append("ENUMERATE_SUB_KEYS")
        
        return rights