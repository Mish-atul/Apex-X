"""
JADX Wrapper — Real Integration
Extracts Java source code from APK files using the JADX decompiler
via subprocess.
"""

from app.utils.file_utils import long_path
import os
import subprocess
import shutil
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Timeout for JADX decompilation (seconds) — Java source extraction is slower
JADX_TIMEOUT = 180


def _find_jadx() -> Optional[str]:
    """Check if jadx is available on the system PATH or in local tools dir."""
    result = shutil.which("jadx")
    if result:
        return result
    # Check local tools directory (project_root/tools/jadx/bin/)
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    tools_dir = os.path.join(os.path.dirname(backend_dir), "tools")
    local_bat = os.path.join(tools_dir, "jadx", "bin", "jadx.bat")
    if os.path.isfile(local_bat):
        return local_bat
    local_bin = os.path.join(tools_dir, "jadx", "bin", "jadx")
    if os.path.isfile(local_bin):
        return local_bin
    # Common installation paths
    for path in [
        "/usr/local/bin/jadx",
        "/usr/bin/jadx",
        "/opt/homebrew/bin/jadx",
        os.path.expanduser("~/jadx/bin/jadx"),
    ]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def extract_java_source(
    apk_path: str,
    output_dir: str,
    no_res: bool = False,
    deobfuscate: bool = False,
    threads: int = 4,
) -> Optional[str]:
    """
    Extract Java source code from an APK using JADX.

    Args:
        apk_path: Absolute path to the APK file.
        output_dir: Directory where Java sources will be written.
        no_res: If True, skip resource decoding (faster).
        deobfuscate: If True, enable JADX deobfuscation.
        threads: Number of processing threads.

    Returns:
        Path to output directory containing Java sources, or None on failure.
    """
    if not os.path.exists(apk_path):
        logger.error(f"APK file not found: {apk_path}")
        return None

    jadx_bin = _find_jadx()
    if not jadx_bin:
        logger.warning(
            "jadx binary not found on system PATH. "
            "Install it: https://github.com/skylot/jadx/releases"
        )
        return None

    # Build command
    cmd = [jadx_bin, "-d", output_dir, apk_path, "--threads-count", str(threads)]
    if no_res:
        cmd.append("--no-res")
    if deobfuscate:
        cmd.append("--deobf")

    logger.info(f"Running JADX: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=JADX_TIMEOUT,
            cwd=os.path.dirname(apk_path),
        )

        if result.returncode != 0:
            # JADX often returns non-zero on partial decompilation — check if output exists
            if os.path.isdir(output_dir) and _has_java_files(output_dir):
                logger.warning(
                    f"JADX exited with code {result.returncode} but produced output. "
                    "Partial decompilation may have occurred."
                )
            else:
                logger.error(f"JADX failed (exit code {result.returncode})")
                logger.error(f"STDERR: {result.stderr[:500]}")
                return None

        logger.info(f"JADX decompilation successful: {output_dir}")
        return output_dir

    except subprocess.TimeoutExpired:
        logger.error(f"JADX timed out after {JADX_TIMEOUT}s for: {apk_path}")
        # Check if partial output was generated
        if os.path.isdir(output_dir) and _has_java_files(output_dir):
            logger.warning("JADX timed out but partial output exists — using partial results.")
            return output_dir
        return None
    except FileNotFoundError:
        logger.error("JADX binary disappeared or is not executable")
        return None
    except Exception as e:
        logger.error(f"JADX unexpected error: {e}")
        return None


def _has_java_files(directory: str) -> bool:
    """Check if a directory tree contains any .java files."""
    for root, _dirs, files in os.walk(long_path(directory)):
        for f in files:
            if f.endswith(".java"):
                return True
    return False


def get_java_source_stats(output_dir: str) -> Dict[str, Any]:
    """
    Gather statistics about the extracted Java source code.
    """
    stats = {
        "java_files": 0,
        "total_lines": 0,
        "packages": set(),
        "classes": [],
    }

    if not os.path.isdir(output_dir):
        return {**stats, "packages": []}

    sources_dir = os.path.join(output_dir, "sources")
    scan_dir = sources_dir if os.path.isdir(sources_dir) else output_dir

    for root, _dirs, files in os.walk(long_path(scan_dir)):
        for f in files:
            if f.endswith(".java"):
                stats["java_files"] += 1
                stats["classes"].append(f.replace(".java", ""))

                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        lines = fh.readlines()
                        stats["total_lines"] += len(lines)
                        # Extract package name
                        for line in lines[:5]:
                            if line.strip().startswith("package "):
                                pkg = line.strip().replace("package ", "").rstrip(";").strip()
                                stats["packages"].add(pkg)
                                break
                except Exception:
                    continue

    stats["packages"] = sorted(stats["packages"])
    stats["classes"] = stats["classes"][:100]  # Cap to avoid huge output
    return stats


def search_java_source(output_dir: str, patterns: List[str]) -> List[Dict[str, Any]]:
    """
    Search extracted Java source code for specific patterns (strings, method calls, etc.).

    Args:
        output_dir: Root of JADX output.
        patterns: List of string patterns to search for.

    Returns:
        List of match dicts with file, line_number, line_content, matched_pattern.
    """
    matches = []
    sources_dir = os.path.join(output_dir, "sources")
    scan_dir = sources_dir if os.path.isdir(sources_dir) else output_dir

    for root, _dirs, files in os.walk(long_path(scan_dir)):
        for f in files:
            if not f.endswith(".java"):
                continue
            file_path = os.path.join(root, f)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, 1):
                        for pattern in patterns:
                            if pattern.lower() in line.lower():
                                matches.append({
                                    "file": os.path.relpath(file_path, long_path(scan_dir)),
                                    "line_number": line_num,
                                    "line_content": line.strip()[:200],
                                    "matched_pattern": pattern,
                                })
            except Exception:
                continue

    return matches[:500]  # Cap results
