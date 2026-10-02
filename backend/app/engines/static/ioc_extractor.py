"""
IOC (Indicator of Compromise) Extractor — Enhanced
Extracts URLs, IPs, domains, emails, crypto wallets, API keys,
Base64-encoded data, and other indicators from decompiled APK sources.
Includes whitelisting to reduce false positives from Android SDK domains.
"""

from app.utils.file_utils import long_path
import re
import os
import base64
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# --- Regex Patterns ---

URL_REGEX = re.compile(
    r'https?://[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}(?:/[^\s"\'<>\)\]]*)?',
    re.IGNORECASE,
)

IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

DOMAIN_REGEX = re.compile(
    r'\b[a-zA-Z0-9.\-]{1,255}\.(?:com|net|org|io|xyz|tk|ml|ga|cf|ru|cn|top|info|biz|cc|ws|pw|live|online|site|club)\b',
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# Bitcoin addresses (P2PKH, P2SH, Bech32)
BTC_REGEX = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
BTC_BECH32_REGEX = re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,87}\b')

# Ethereum addresses
ETH_REGEX = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

# Monero addresses
XMR_REGEX = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')

# API keys / secrets — generic patterns
API_KEY_REGEX = re.compile(
    r'(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|'
    r'private[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
    re.IGNORECASE,
)

# AWS access keys
AWS_KEY_REGEX = re.compile(r'\bAKIA[0-9A-Z]{16}\b')

# Google API keys
GOOGLE_API_REGEX = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')

# Base64-encoded strings that may contain URLs or secrets
BASE64_REGEX = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')

# --- Financial Indicators ---

# UPI Virtual Payment Address: username@bankhandle
UPI_REGEX = re.compile(
    r'\b[a-zA-Z0-9.\-_]{2,256}@(?:okhdfcbank|oksbi|okicici|okaxis|ybl|paytm|apl|ibl|axl|'
    r'upi|axisbank|icici|hdfcbank|sbi|kotak|yesbank|freecharge|jio)\b', re.IGNORECASE
)

# Indian bank account number (9-18 digits, contextual — pair with IFSC nearby)
IFSC_REGEX = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
BANK_ACCOUNT_REGEX = re.compile(r'\b\d{9,18}\b')

# --- Whitelist: known-safe domains/IPs ---

WHITELISTED_DOMAINS = {
    "schemas.android.com", "www.w3.org", "ns.adobe.com",
    "xmlpull.org", "xml.org", "www.xml.org",
    "google.com", "www.google.com", "googleapis.com",
    "android.com", "www.android.com", "developer.android.com",
    "play.google.com", "firebase.google.com", "crashlytics.com",
    "gstatic.com", "googleadservices.com", "googlesyndication.com",
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "facebook.com", "graph.facebook.com",
    "github.com", "raw.githubusercontent.com",
    "apache.org", "www.apache.org",
    "example.com", "www.example.com", "localhost",
    "127.0.0.1", "0.0.0.0", "10.0.0.1",
    # Android/Java SDK domains that are package names, not network indicators
    "android.net", "java.net", "java.io", "javax.net",
    "androidx.core.net", "android.os", "android.app",
    "android.content", "android.widget", "android.view",
    "android.graphics", "android.util", "android.text",
    "kotlin.io", "kotlinx.coroutines",
    # Common dev domains
    "stackoverflow.com", "maven.org", "mvnrepository.com",
    "jitpack.io", "bintray.com", "gradle.org",
    "jetbrains.com", "kotlinlang.org",
    "pexels.com", "images.pexels.com",
    # Developer references
    "issuetracker.google.com", "source.android.com",
    # Other internal namespaces
    "libcore.io", "dalvik.system",
}

# Patterns that look like domains but are actually Java/Kotlin identifiers
# e.g. rect.top, padding.top, logger.info, view.info, loglevel.info
JAVA_FALSE_POSITIVE_SUFFIXES = {
    ".top", ".bottom", ".left", ".right", ".start", ".end",
    ".width", ".height", ".size", ".length", ".count",
    ".info", ".warn", ".error", ".debug", ".trace", ".verbose",
    ".class", ".name", ".type", ".value", ".key", ".data",
    ".text", ".title", ".label", ".message",
    ".get", ".set", ".put", ".add", ".remove", ".clear",
    ".run", ".call", ".apply", ".bind", ".exec",
    ".init", ".create", ".build", ".make", ".parse",
    ".open", ".close", ".read", ".write", ".flush",
    ".show", ".hide", ".enable", ".disable",
}

# Java/Android package prefixes that should never be treated as domains
JAVA_PACKAGE_PREFIXES = [
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "com.google.android.", "com.android.", "org.apache.", "org.xml.",
    "dalvik.", "sun.", "org.json.", "junit.", "org.junit.",
    "libcore.", "bouncycastle.",
]

# --- Noise Reduction & SDK Filtering ---

# Directories from standard libraries and consent frameworks to skip
IGNORED_DIR_PATTERNS = [
    "androidx", "android/support", "android\\support",
    "com/google/android/gms", "com\\google\\android\\gms",
    "com/google/firebase", "com\\google\\firebase",
    "kotlin", "kotlinx", "okhttp3", "retrofit2",
    "io/reactivex", "org/apache", "org\\apache",
    "com/inmobi/cmp", "com\\inmobi\\cmp",
    "com/inmobi/ads", "com\\inmobi\\ads",
]

# Noise patterns: privacy policies, TCF compliance files, schemas, open-source licenses
TCF_AND_POLICY_NOISE = [
    "privacy-policy", "privacy_policy", "privacypolicy", "datenschutz",
    "politica-privacidad", "politique-confidentialite", "politica_privacidad",
    "devicestorage", "device_storage", "device-storage", "tcf", "gvl",
    "disclosure", "disclosures", "consent", "cookie-statement", "cookiepolicy",
    "iab.json", "iab_tcf", "iab-tcf", "sellers.json", "licenses",
    "legal/privacy", "privacy_notice", "privacy-notice", "privacystatement",
    "privacy-statement", "gdpr", "spdx.org", "apache.org/licenses",
    "w3.org", "schemas.android.com", "ns.adobe.com", "checkerframework.org",
    "errorprone.info", "findbugs.sourceforge.net", "jspecify.org",
    "play.google.com", "apple.com", "uptodown.com", "goo.gle", "goo.gl",
    "github.com", "gitlab.com", "bitbucket.org", "android.googlesource.com",
    "hubspotusercontent", "cloudfront.net/public/disclosures",
]

# File extensions to scan for IOCs
SCANNABLE_EXTENSIONS = {
    ".smali", ".java", ".xml", ".txt", ".json", ".js",
    ".html", ".properties", ".cfg", ".yml", ".yaml",
}


def extract_iocs_from_file(file_path: str) -> Dict[str, Any]:
    """
    Extract all IOC types from a single file.
    Tracks code_references mapping each IOC to file:line locations.
    """
    result = {
        "urls": set(),
        "ips": set(),
        "domains": set(),
        "emails": set(),
        "crypto_wallets": set(),
        "api_keys": set(),
        "base64_urls": set(),
        "upi_ids": set(),
        "ifsc_bank_pairs": list(),
        "code_references": {},  # ioc_value -> [{file, line, context}]
    }

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        logger.warning(f"Failed to read {file_path}: {e}")
        return _sets_to_lists(result)

    content = "".join(lines)
    rel_path = file_path  # Will be made relative in the directory scanner

    def _add_ref(ioc_value: str, line_num: int, line_text: str):
        """Add a code reference for an IOC."""
        if ioc_value not in result["code_references"]:
            result["code_references"][ioc_value] = []
        # Only keep first 3 references per IOC per file
        if len(result["code_references"][ioc_value]) < 3:
            result["code_references"][ioc_value].append({
                "file": rel_path,
                "line": line_num,
                "context": line_text.strip()[:200],
            })

    # Scan line-by-line for IOCs with line number tracking
    for line_num, line in enumerate(lines, 1):
        # URLs
        for url in URL_REGEX.findall(line):
            if not _is_whitelisted_url(url):
                normalized = url.rstrip(".,;:)]}/ ")
                result["urls"].add(normalized)
                _add_ref(normalized, line_num, line)

        # IP addresses
        for ip in IP_REGEX.findall(line):
            if not _is_whitelisted_ip(ip):
                result["ips"].add(ip)
                _add_ref(ip, line_num, line)

        # Domains
        for domain in DOMAIN_REGEX.findall(line):
            d = domain.lower()
            if d in WHITELISTED_DOMAINS:
                continue
            # Filter Java/Kotlin identifiers (rect.top, logger.info, etc.)
            if any(d.endswith(suffix) for suffix in JAVA_FALSE_POSITIVE_SUFFIXES):
                continue
            # Filter Java/Android package names
            if any(d.startswith(prefix) for prefix in JAVA_PACKAGE_PREFIXES):
                continue
            # Must have at least 2 parts and the first part should be > 1 char
            parts = d.split(".")
            if len(parts) < 2 or len(parts[0]) <= 1:
                continue
            # Filter single-word identifiers that look like code (camelCase, underscore)
            if "_" in parts[0] or (parts[0] != parts[0].lower() and not parts[0].startswith("www")):
                continue
            result["domains"].add(d)
            _add_ref(d, line_num, line)

        # Emails
        for email in EMAIL_REGEX.findall(line):
            domain = email.split('@')[-1].lower()
            if not any(domain.endswith(d) for d in ["android.com", "google.com", "example.com"]):
                result["emails"].add(email)
                _add_ref(email, line_num, line)

        # Crypto wallets
        for addr in BTC_REGEX.findall(line):
            result["crypto_wallets"].add(f"btc:{addr}")
            _add_ref(f"btc:{addr}", line_num, line)
        for addr in BTC_BECH32_REGEX.findall(line):
            result["crypto_wallets"].add(f"btc:{addr}")
            _add_ref(f"btc:{addr}", line_num, line)
        for addr in ETH_REGEX.findall(line):
            result["crypto_wallets"].add(f"eth:{addr}")
            _add_ref(f"eth:{addr}", line_num, line)

        # API keys and secrets
        for key in API_KEY_REGEX.findall(line):
            result["api_keys"].add(key)
            _add_ref(key, line_num, line)
        for key in AWS_KEY_REGEX.findall(line):
            result["api_keys"].add(f"aws:{key}")
            _add_ref(f"aws:{key}", line_num, line)
        for key in GOOGLE_API_REGEX.findall(line):
            result["api_keys"].add(f"google:{key}")
            _add_ref(f"google:{key}", line_num, line)

        # UPI IDs
        for upi in UPI_REGEX.findall(line):
            result["upi_ids"].add(upi)
            _add_ref(upi, line_num, line)

    # Base64-encoded URLs (whole content scan — not line-level)
    for b64 in BASE64_REGEX.findall(content):
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            urls_in_decoded = URL_REGEX.findall(decoded)
            for url in urls_in_decoded:
                if not _is_whitelisted_url(url):
                    result["base64_urls"].add(url)
        except Exception:
            pass

    # Contextual Bank Accounts (whole content scan)
    for ifsc_match in IFSC_REGEX.finditer(content):
        ifsc_code = ifsc_match.group(0)
        start_pos = max(0, ifsc_match.start() - 100)
        end_pos = min(len(content), ifsc_match.end() + 100)
        
        # Look for bank accounts in a 100 char window around the IFSC code
        window = content[start_pos:end_pos]
        for acc_match in BANK_ACCOUNT_REGEX.findall(window):
            result["ifsc_bank_pairs"].append({
                "ifsc": ifsc_code,
                "account_near": acc_match,
                "source_file": os.path.basename(file_path)
            })

    return _sets_to_lists(result)


def extract_iocs_from_directory(directory: str) -> Dict[str, Any]:
    """
    Recursively scan a directory (e.g., decompiled APK output) for IOCs.

    Returns aggregated IOC dict with deduplicated indicators.
    """
    aggregated: Dict[str, Any] = {
        "urls": set(),
        "ips": set(),
        "domains": set(),
        "emails": set(),
        "crypto_wallets": set(),
        "api_keys": set(),
        "base64_urls": set(),
        "upi_ids": set(),
        "ifsc_bank_pairs": list(),
        "code_references": {},  # ioc_value -> [{file, line, context}]
    }
    files_scanned = 0

    if not os.path.isdir(directory):
        logger.error(f"Directory not found: {directory}")
        return {**_sets_to_lists(aggregated), "files_scanned": 0, "code_references": {}}

    for root, _dirs, files in os.walk(long_path(directory)):
        # Skip scanning inside known third-party support/advertising libraries
        norm_root = root.replace("\\", "/")
        if any(ign in norm_root for ign in [
            "/androidx/", "/android/support/", "/kotlin/", "/kotlinx/",
            "/com/google/android/gms/", "/com/google/firebase/",
            "/okhttp3/", "/retrofit2/", "/org/apache/",
            "/com/inmobi/cmp/", "/com/inmobi/ads/", "/com/facebook/ads/",
        ]):
            continue

        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCANNABLE_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)

            # Skip very large files
            try:
                if os.path.getsize(file_path) > 5 * 1024 * 1024:  # 5 MB
                    continue
            except OSError:
                continue

            files_scanned += 1
            file_iocs = extract_iocs_from_file(file_path)

            for key in aggregated:
                if key == "code_references":
                    continue  # Handle separately
                if key in file_iocs:
                    if isinstance(aggregated[key], set):
                        aggregated[key].update(file_iocs[key])
                    elif isinstance(aggregated[key], list):
                        aggregated[key].extend(file_iocs[key])

            # Merge code_references with relative paths
            for ioc_val, refs in file_iocs.get("code_references", {}).items():
                if ioc_val not in aggregated["code_references"]:
                    aggregated["code_references"][ioc_val] = []
                for ref in refs:
                    # Make path relative to the scan directory
                    rel = os.path.relpath(ref["file"], long_path(directory))
                    aggregated["code_references"][ioc_val].append({
                        "file": rel.replace("\\", "/"),
                        "line": ref["line"],
                        "context": ref["context"],
                    })
                # Cap at 5 references per IOC across all files
                aggregated["code_references"][ioc_val] = aggregated["code_references"][ioc_val][:5]

    # Prioritize and cap URLs to avoid overwhelming UI/DB with 40,000+ items
    def _url_priority(u: str) -> int:
        u_low = u.lower()
        # High priority: raw IP, suspicious ports, financial/C2 terms
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', u_low): return 10
        if any(p in u_low for p in [':8080', ':8443', ':8888', ':9001', ':4444', ':5555']): return 9
        if any(k in u_low for k in ['telegram', 'bot', 'api/v1', 'collect', 'gate', 'c2', 'payload', 'upload', 'push']): return 8
        if any(k in u_low for k in ['upi', 'pay', 'bank', 'auth', 'login', 'token', 'admin']): return 7
        return 1

    sorted_urls = sorted(aggregated["urls"], key=lambda u: (-_url_priority(u), u))
    aggregated["urls"] = set(sorted_urls[:200])

    sorted_domains = sorted(aggregated["domains"])
    aggregated["domains"] = set(sorted_domains[:150])

    result = _sets_to_lists(aggregated)
    result["files_scanned"] = files_scanned
    result["total_indicators"] = sum(
        len(result[k]) for k in ["urls", "ips", "domains", "emails", "crypto_wallets", "api_keys", "base64_urls", "upi_ids", "ifsc_bank_pairs"]
    )

    logger.info(
        f"IOC extraction complete: {files_scanned} files scanned, "
        f"{result['total_indicators']} indicators retained (capped for relevance)."
    )

    return result


def _is_whitelisted_url(url: str) -> bool:
    """Check if a URL belongs to a whitelisted domain or is noise (privacy policies, TCF)."""
    url_lower = url.lower()
    
    # 1. Filter out TCF / privacy policy noise
    if any(noise in url_lower for noise in TCF_AND_POLICY_NOISE):
        return True

    # 2. Filter out known standard domains
    for domain in WHITELISTED_DOMAINS:
        if f"://{domain}" in url_lower or f"://{domain}/" in url_lower:
            return True
        if f".{domain}" in url_lower:
            return True
    return False


def _is_whitelisted_ip(ip: str) -> bool:
    """Check if an IP is a private/reserved address."""
    parts = ip.split(".")
    try:
        first = int(parts[0])
        second = int(parts[1])
    except (ValueError, IndexError):
        return True

    # Private ranges
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    if first == 0 or first == 255:
        return True

    return ip in WHITELISTED_DOMAINS


def _sets_to_lists(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert all sets in a dict to sorted lists."""
    result = {}
    for key, value in data.items():
        if isinstance(value, set):
            result[key] = sorted(value)
        else:
            result[key] = value
    return result
