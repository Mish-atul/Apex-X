"""
YARA Scanner — Real Integration
Scans decompiled APK output against YARA rules for malware pattern detection.
Uses the yara-python library for rule compilation and matching.
"""

from app.utils.file_utils import long_path
import os
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python library not installed. Install it: pip install yara-python>=3.11.0")

# Default rules directory
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".smali", ".java", ".xml", ".json", ".txt", ".js", ".html",
    ".dex", ".so", ".properties", ".cfg", ".yml", ".yaml",
}

# Max file size to scan (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


def compile_rules(rules_dir: Optional[str] = None) -> Optional[Any]:
    """
    Compile all YARA rule files from the rules directory.

    Args:
        rules_dir: Path to directory containing .yar/.yara files.

    Returns:
        Compiled yara.Rules object, or None on failure.
    """
    if not YARA_AVAILABLE:
        logger.error("yara-python not available — cannot compile rules.")
        return None

    rules_dir = rules_dir or RULES_DIR

    if not os.path.isdir(rules_dir):
        logger.error(f"YARA rules directory not found: {rules_dir}")
        return None

    # Collect all .yar and .yara files
    rule_files = {}
    for f in os.listdir(rules_dir):
        if f.endswith((".yar", ".yara")):
            rule_name = os.path.splitext(f)[0]
            rule_files[rule_name] = os.path.join(rules_dir, f)

    if not rule_files:
        logger.warning(f"No YARA rule files found in: {rules_dir}")
        return None

    try:
        compiled = yara.compile(filepaths=rule_files)
        logger.info(f"Compiled {len(rule_files)} YARA rule file(s) successfully.")
        return compiled
    except yara.SyntaxError as e:
        logger.error(f"YARA rule syntax error: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to compile YARA rules: {e}")
        return None


def scan_file(file_path: str, rules) -> List[Dict[str, Any]]:
    """
    Scan a single file against compiled YARA rules.

    Args:
        file_path: Path to the file to scan.
        rules: Compiled yara.Rules object.

    Returns:
        List of match dicts.
    """
    matches = []

    try:
        io_path = long_path(file_path)
        file_size = os.path.getsize(io_path)
        if file_size > MAX_FILE_SIZE:
            return matches

        with open(io_path, "rb") as fh:
            yara_matches = rules.match(data=fh.read(), timeout=30)

        for match in yara_matches:
            matched_strings = []
            for string_match in match.strings:
                try:
                    if hasattr(string_match, 'identifier') and hasattr(string_match, 'instances'):
                        # Newer yara-python
                        identifier = string_match.identifier
                        for instance in string_match.instances:
                            offset = getattr(instance, 'offset', 0)
                            data = getattr(instance, 'matched_data', b'')
                            try:
                                decoded = data.decode("utf-8", errors="replace")[:100]
                            except Exception:
                                decoded = str(data)[:100]
                            matched_strings.append({
                                "offset": offset,
                                "identifier": identifier,
                                "data": decoded,
                            })
                    else:
                        # Older yara-python (tuple)
                        offset, identifier, data = string_match
                        try:
                            decoded = data.decode("utf-8", errors="replace")[:100]
                        except Exception:
                            decoded = str(data)[:100]
                        matched_strings.append({
                            "offset": offset,
                            "identifier": identifier,
                            "data": decoded,
                        })
                except Exception:
                    pass

            matches.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
                "matched_strings": matched_strings[:20],
                "file": file_path,
            })

    except yara.TimeoutError:
        logger.warning(f"YARA scan timed out for: {file_path}")
    except yara.Error as e:
        logger.warning(f"YARA scan error for {file_path}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error scanning {file_path}: {e}")

    return matches


def scan_directory(
    directory: str,
    rules=None,
    rules_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Recursively scan a directory (e.g., decompiled APK output) against YARA rules.

    Args:
        directory: Root directory to scan.
        rules: Pre-compiled yara.Rules object. If None, compiles from rules_dir.
        rules_dir: Path to rules directory. Uses default if None.

    Returns:
        Dict with all matches, summary statistics, and risk indicators.
    """
    result = {
        "matches": [],
        "total_files_scanned": 0,
        "total_matches": 0,
        "rules_matched": [],
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "scan_errors": 0,
    }

    if not YARA_AVAILABLE:
        result["error"] = "yara-python not available"
        return result

    if not os.path.isdir(directory):
        result["error"] = f"Directory not found: {directory}"
        return result

    # Compile rules if not provided
    if rules is None:
        rules = compile_rules(rules_dir)
        if rules is None:
            result["error"] = "Failed to compile YARA rules"
            return result

    logger.info(f"Starting YARA scan of directory: {directory}")

    matched_rules = set()

    for root, _dirs, files in os.walk(long_path(directory)):
        for filename in files:
            # Check file extension
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCANNABLE_EXTENSIONS and ext != "":
                continue

            file_path = os.path.join(root, filename)
            result["total_files_scanned"] += 1

            try:
                file_matches = scan_file(file_path, rules)
                for match in file_matches:
                    # Use relative path in output
                    match["file"] = os.path.relpath(file_path, long_path(directory))
                    result["matches"].append(match)
                    result["total_matches"] += 1
                    matched_rules.add(match["rule"])

                    # Count severity
                    severity = match.get("meta", {}).get("severity", "medium").lower()
                    if severity in result["severity_counts"]:
                        result["severity_counts"][severity] += 1
                    else:
                        result["severity_counts"]["medium"] += 1

            except Exception as e:
                result["scan_errors"] += 1
                logger.warning(f"Error scanning {file_path}: {e}")

    result["rules_matched"] = sorted(matched_rules)

    logger.info(
        f"YARA scan complete: {result['total_files_scanned']} files scanned, "
        f"{result['total_matches']} matches from {len(matched_rules)} rules."
    )

    return result


def scan_apk_bytes(apk_path: str, rules=None, rules_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan the raw APK file (ZIP/binary) directly against YARA rules.
    This catches patterns in the original binary before decompilation.
    """
    result = {
        "matches": [],
        "total_matches": 0,
        "rules_matched": [],
    }

    if not YARA_AVAILABLE:
        result["error"] = "yara-python not available"
        return result

    if not os.path.exists(apk_path):
        result["error"] = f"APK not found: {apk_path}"
        return result

    if rules is None:
        rules = compile_rules(rules_dir)
        if rules is None:
            result["error"] = "Failed to compile YARA rules"
            return result

    file_matches = scan_file(apk_path, rules)
    matched_rules = set()

    for match in file_matches:
        match["file"] = os.path.basename(apk_path)
        result["matches"].append(match)
        result["total_matches"] += 1
        matched_rules.add(match["rule"])

    result["rules_matched"] = sorted(matched_rules)
    return result
