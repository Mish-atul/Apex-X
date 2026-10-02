"""
Fingerprint Engine
Computes structural fingerprints of an APK to detect repackaged malware variants
that evade simple SHA256 file hashes.
"""

from app.utils.file_utils import long_path
import os
import hashlib
from typing import Dict, Any

def compute_structural_fingerprint(androguard_data: Dict[str, Any], apktool_dir: str) -> Dict[str, Any]:
    """
    Hashes permission sets, class structures, core resources, and API calls.
    Returns a composite fingerprint_id along with its components.
    """
    fingerprint = {
        "permission_set_hash": "",
        "class_shape_hash": "",
        "resource_hashes": {},
        "api_call_signature": [],
        "fingerprint_id": ""
    }
    
    # 1. Permission Set Hash
    permissions = androguard_data.get("permissions", [])
    if isinstance(permissions, list):
        sorted_perms = sorted(permissions)
        fingerprint["permission_set_hash"] = hashlib.sha256(",".join(sorted_perms).encode()).hexdigest()
        
    # 2. API Call Signature
    api_calls = androguard_data.get("api_calls", {})
    high_risk_apis = api_calls.get("high_risk", [])
    if isinstance(high_risk_apis, list):
        # We only keep the class/method names, not exact line numbers
        api_names = []
        for call in high_risk_apis:
            name = call.get("api", "") if isinstance(call, dict) else str(call)
            api_names.append(name.split(" ")[0] if " " in name else name)
            
        sorted_apis = sorted(list(set(api_names)))
        fingerprint["api_call_signature"] = sorted_apis
        
    # 3. Class Shape (smali directory structure)
    # Just hashing the list of directories under smali/ to get a "shape"
    class_dirs = []
    if apktool_dir and os.path.isdir(apktool_dir):
        for root, dirs, files in os.walk(long_path(apktool_dir)):
            if "smali" in root:
                rel = os.path.relpath(root, long_path(apktool_dir))
                class_dirs.append(rel)
    
    if class_dirs:
        sorted_dirs = sorted(class_dirs)
        fingerprint["class_shape_hash"] = hashlib.sha256(",".join(sorted_dirs).encode()).hexdigest()
        
    # 4. Resource Hashes (specifically AndroidManifest.xml and classes.dex if available)
    # Wait, classes.dex is not in apktool_dir. Let's just hash AndroidManifest.xml
    if apktool_dir:
        manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            with open(manifest_path, "rb") as f:
                fingerprint["resource_hashes"]["AndroidManifest.xml"] = hashlib.sha256(f.read()).hexdigest()
                
    # Composite Fingerprint
    components = f"{fingerprint['permission_set_hash']}|{fingerprint['class_shape_hash']}|" + \
                 f"{fingerprint['resource_hashes'].get('AndroidManifest.xml', '')}"
    fingerprint["fingerprint_id"] = hashlib.sha256(components.encode()).hexdigest()
    
    return fingerprint

def similarity_score(fp_a: Dict[str, Any], fp_b: Dict[str, Any]) -> float:
    """
    Computes a similarity score (0.0 to 1.0) between two fingerprints using Jaccard coefficient methodology.
    """
    if fp_a.get("fingerprint_id") == fp_b.get("fingerprint_id") and fp_a.get("fingerprint_id"):
        return 1.0
        
    score = 0.0
    weight_total = 0.0
    
    # Permissions match (weight 30%)
    weight_total += 0.3
    if fp_a.get("permission_set_hash") == fp_b.get("permission_set_hash") and fp_a.get("permission_set_hash"):
        score += 0.3
        
    # Class shape match (weight 40%)
    weight_total += 0.4
    if fp_a.get("class_shape_hash") == fp_b.get("class_shape_hash") and fp_a.get("class_shape_hash"):
        score += 0.4
        
    # API calls Jaccard (weight 30%)
    weight_total += 0.3
    api_a = set(fp_a.get("api_call_signature", []))
    api_b = set(fp_b.get("api_call_signature", []))
    if api_a or api_b:
        intersection = len(api_a.intersection(api_b))
        union = len(api_a.union(api_b))
        jaccard = intersection / union
        score += 0.3 * jaccard
        
    return score / weight_total if weight_total > 0 else 0.0
