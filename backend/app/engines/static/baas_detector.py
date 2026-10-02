"""
BaaS-as-C2 Detector
Scans decompiled sources (especially strings.xml and smali) for hardcoded
Firebase and Supabase credentials, and optionally probes them to see if they
are completely open (read/write without auth).
"""

from app.utils.file_utils import long_path
import os
import re
import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Patterns for Firebase and Supabase
FIREBASE_URL_REGEX = re.compile(r'https://([a-zA-Z0-9-]+)\.firebaseio\.com')
SUPABASE_URL_REGEX = re.compile(r'https://([a-zA-Z0-9-]+)\.supabase\.co')
SUPABASE_KEY_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

def detect_baas_backends(scan_dirs: List[str]) -> Dict[str, Any]:
    """
    Scans a list of directories (like apktool_dir and jadx_dir) for BaaS URLs.
    """
    result = {
        "firebase_projects": [],
        "supabase_projects": []
    }
    
    firebase_urls = set()
    supabase_urls = set()
    supabase_keys = set()
    
    for scan_dir in scan_dirs:
        if not scan_dir or not os.path.isdir(scan_dir):
            continue
            
        for root, _, files in os.walk(long_path(scan_dir)):
            for file in files:
                if not file.endswith(('.xml', '.smali', '.java', '.json', '.txt', '.properties')):
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for match in FIREBASE_URL_REGEX.findall(content):
                            firebase_urls.add(match)
                            
                        for match in SUPABASE_URL_REGEX.findall(content):
                            supabase_urls.add(match)
                            
                        if "supabase" in content.lower():
                            for match in SUPABASE_KEY_REGEX.findall(content):
                                supabase_keys.add(match)
                except Exception:
                    continue
                    
    for proj in firebase_urls:
        result["firebase_projects"].append({
            "project_id": proj,
            "url": f"https://{proj}.firebaseio.com",
            "type": "firebase"
        })
        
    for proj in supabase_urls:
        # Just grab any first key found if it exists (very naive mapping)
        key = list(supabase_keys)[0] if supabase_keys else None
        result["supabase_projects"].append({
            "project_id": proj,
            "url": f"https://{proj}.supabase.co",
            "anon_key": key,
            "type": "supabase"
        })
        
    return result

def enrich_baas_exposure(baas_data: Dict[str, Any], allow_network: bool = False) -> Dict[str, Any]:
    """
    Optionally probes the found BaaS backends to see if they allow unauthenticated reads.
    """
    if not allow_network:
        return baas_data
        
    for fb in baas_data.get("firebase_projects", []):
        try:
            # Query the root with a shallow read
            url = f"{fb['url']}/.json?shallow=true"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                fb["publicly_readable"] = True
                fb["risk_level"] = "CRITICAL"
            elif response.status_code == 401:
                fb["publicly_readable"] = False
                fb["risk_level"] = "MEDIUM"
        except Exception as e:
            fb["probe_error"] = str(e)
            
    # For Supabase we would need to try a generic REST GET, which is harder without knowing tables.
    # We will just mark it.
    
    return baas_data
