"""
Static Analysis Engine — Orchestrator
Chains all static analysis tools into a complete pipeline:
APKTool → JADX → Androguard → Manifest → YARA → IOC → Risk Score

Each step is independent and the pipeline continues even if individual steps fail.
All output artifacts are SHA256-hashed for forensic integrity.
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.engines.static import apktool_wrapper
from app.engines.static import jadx_wrapper
from app.engines.static import androguard_analyzer
from app.engines.static import manifest_parser
from app.engines.static import yara_scanner
from app.engines.static import ioc_extractor
from app.engines.static import risk_scorer
from app.engines.static import remote_access_detector
from app.engines.static import baas_detector
from app.engines.static import fingerprint_engine
from app.engines.static import mo_classifier
from app.config import settings

logger = logging.getLogger(__name__)


def run_full_static_analysis(apk_path: str, case_dir: str) -> Dict[str, Any]:
    """
    Execute the complete static analysis pipeline on an APK file.

    Args:
        apk_path: Absolute path to the APK file.
        case_dir: Directory to store all analysis output and artifacts.

    Returns:
        Comprehensive analysis result dict with all findings and metadata.
    """
    start_time = datetime.now(timezone.utc)

    result = {
        "phase": "static",
        "status": "running",
        "apk_path": apk_path,
        "case_dir": case_dir,
        "started_at": start_time.isoformat(),
        "completed_at": None,
        "duration_seconds": None,
        "steps": {},
        "errors": [],
        "risk_score": None,
        "risk_breakdown": None,
        "artifact_hashes": {},
    }

    # Create output directories
    static_dir = os.path.join(case_dir, "static_analysis")
    apktool_dir = os.path.join(static_dir, "apktool_output")
    jadx_dir = os.path.join(static_dir, "jadx_output")
    os.makedirs(static_dir, exist_ok=True)

    # ── Step 1: APKTool Decompilation ────────────────────────
    logger.info("Step 1/6: APKTool decompilation")
    try:
        apktool_output = apktool_wrapper.decompile_apk(apk_path, apktool_dir)
        if apktool_output:
            info = apktool_wrapper.get_decompiled_info(apktool_output)
            result["steps"]["apktool"] = {
                "status": "success",
                "output_dir": apktool_output,
                "info": info,
            }
        else:
            result["steps"]["apktool"] = {"status": "failed", "error": "APKTool returned None"}
            result["errors"].append("APKTool decompilation failed")
    except Exception as e:
        result["steps"]["apktool"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"APKTool error: {e}")

    # ── Step 2: JADX Java Source Extraction ──────────────────
    logger.info("Step 2/6: JADX Java source extraction")
    try:
        jadx_output = jadx_wrapper.extract_java_source(apk_path, jadx_dir, no_res=True)
        if jadx_output:
            stats = jadx_wrapper.get_java_source_stats(jadx_output)
            result["steps"]["jadx"] = {
                "status": "success",
                "output_dir": jadx_output,
                "stats": stats,
            }
        else:
            result["steps"]["jadx"] = {"status": "failed", "error": "JADX returned None"}
            result["errors"].append("JADX Java extraction failed")
    except Exception as e:
        result["steps"]["jadx"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"JADX error: {e}")

    # ── Step 3: Androguard Analysis ──────────────────────────
    logger.info("Step 3/6: Androguard APK analysis")
    try:
        ag_results = androguard_analyzer.analyze_apk(apk_path)
        if "error" not in ag_results:
            result["steps"]["androguard"] = {
                "status": "success",
                "data": ag_results,
            }
        else:
            result["steps"]["androguard"] = {
                "status": "failed",
                "error": ag_results["error"],
            }
            result["errors"].append(f"Androguard failed: {ag_results['error']}")
    except Exception as e:
        result["steps"]["androguard"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"Androguard error: {e}")

    # ── Step 4: Manifest Parsing ─────────────────────────────
    logger.info("Step 4/6: Manifest parsing")
    manifest_path = None
    if apktool_dir and os.path.isdir(apktool_dir):
        manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    manifest_results = {}
    try:
        if manifest_path and os.path.exists(manifest_path):
            manifest_results = manifest_parser.parse_manifest(manifest_path)
            
            # Feature 6: Check for remote access abuse
            remote_access_check = remote_access_detector.detect_remote_access_abuse(
                manifest_results, apktool_dir
            )
            manifest_results["remote_access_abuse"] = remote_access_check
            
            result["steps"]["manifest"] = {
                "status": "success",
                "data": manifest_results,
            }
        else:
            # FALLBACK: Use androguard data when APKTool is unavailable
            ag_step = result["steps"].get("androguard", {})
            ag_data = ag_step.get("data", {}) if ag_step.get("status") == "success" else {}
            if ag_data:
                ag_perms = ag_data.get("permissions", {})
                # Build manifest_results from androguard data
                perm_dict = {}
                for p in ag_perms.get("all", []):
                    is_dangerous = p in ag_perms.get("dangerous", [])
                    perm_dict[p] = {
                        "protection_level": "dangerous" if is_dangerous else "normal",
                        "description": p.split(".")[-1],
                    }
                manifest_results = {
                    "permissions": perm_dict,
                    "package_name": ag_data.get("package_name", "unknown"),
                    "activities": ag_data.get("activities", []),
                    "services": ag_data.get("services", []),
                    "receivers": ag_data.get("receivers", []),
                    "providers": ag_data.get("providers", []),
                    "misconfigurations": [],
                    "security_flags": {},
                }
                result["steps"]["manifest"] = {
                    "status": "success",
                    "data": manifest_results,
                    "source": "androguard_fallback",
                }
                logger.info("Using androguard fallback for manifest data")
            else:
                result["steps"]["manifest"] = {
                    "status": "skipped",
                    "reason": "No AndroidManifest.xml found and no androguard data available",
                }
    except Exception as e:
        result["steps"]["manifest"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"Manifest parser error: {e}")

    # ── Step 5: YARA Scanning ────────────────────────────────
    logger.info("Step 5/6: YARA rule scanning")
    yara_results = {}
    try:
        # Prefer jadx_dir (clean decompiled Java), fallback to apktool_dir if jadx produced no files
        has_jadx = jadx_dir and os.path.isdir(jadx_dir) and any(os.scandir(jadx_dir))
        primary_scan_dir = jadx_dir if has_jadx else (apktool_dir if (apktool_dir and os.path.isdir(apktool_dir)) else None)
        scan_targets = [primary_scan_dir] if primary_scan_dir else []

        compiled_rules = yara_scanner.compile_rules()
        all_yara_matches = []
        total_files = 0

        if compiled_rules:
            for target in scan_targets:
                dir_result = yara_scanner.scan_directory(target, rules=compiled_rules)
                all_yara_matches.extend(dir_result.get("matches", []))
                total_files += dir_result.get("total_files_scanned", 0)

            # Also scan raw APK binary
            logger.info(f"Scanning raw APK bytes for {apk_path}...")
            apk_result = yara_scanner.scan_apk_bytes(apk_path, rules=compiled_rules)
            logger.info("Finished scanning raw APK bytes.")
            all_yara_matches.extend(apk_result.get("matches", []))

            # Deduplicate by rule name + file
            seen_rules = set()
            unique_matches = []
            for m in all_yara_matches:
                rule_key = f"{m['rule']}:{m.get('file', '')}"
                if rule_key not in seen_rules:
                    seen_rules.add(rule_key)
                    unique_matches.append(m)

            yara_results = {
                "matches": unique_matches,
                "total_files_scanned": total_files,
                "total_matches": len(unique_matches),
                "rules_matched": sorted(set(m["rule"] for m in unique_matches)),
            }

            result["steps"]["yara"] = {
                "status": "success",
                "data": yara_results,
            }
        else:
            result["steps"]["yara"] = {
                "status": "skipped",
                "reason": "YARA rules could not be compiled",
            }
    except Exception as e:
        result["steps"]["yara"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"YARA scanner error: {e}")

    # ── Step 6: IOC Extraction ───────────────────────────────
    logger.info("Step 6/6: IOC extraction")
    ioc_results = {}
    try:
        # Use single primary scan directory to prevent 2x duplicate artifacts
        scan_dirs = scan_targets

        aggregated_iocs = {
            "urls": set(), "ips": set(), "domains": set(),
            "emails": set(), "crypto_wallets": set(),
            "api_keys": set(), "base64_urls": set(),
        }

        for scan_dir in scan_dirs:
            dir_iocs = ioc_extractor.extract_iocs_from_directory(scan_dir)
            for key in aggregated_iocs:
                if key in dir_iocs:
                    aggregated_iocs[key].update(dir_iocs[key])

        ioc_results = {
            k: sorted(v) if isinstance(v, set) else v
            for k, v in aggregated_iocs.items()
        }
        ioc_results["total_indicators"] = sum(
            len(v) for v in aggregated_iocs.values()
        )

        result["steps"]["iocs"] = {
            "status": "success",
            "data": ioc_results,
        }
    except Exception as e:
        result["steps"]["iocs"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"IOC extraction error: {e}")

    # ── Step 6.5: BaaS / C2 Detection ────────────────────────
    logger.info("Step 6.5/7: BaaS / C2 Detection")
    baas_results = {}
    try:
        scan_targets = []
        if apktool_dir and os.path.isdir(apktool_dir):
            scan_targets.append(apktool_dir)
        if jadx_dir and os.path.isdir(jadx_dir):
            scan_targets.append(jadx_dir)
            
        baas_data = baas_detector.detect_baas_backends(scan_targets)
        baas_results = baas_detector.enrich_baas_exposure(baas_data, allow_network=settings.ALLOW_BAAS_NETWORK_ENRICHMENT)
        result["steps"]["baas_detection"] = {
            "status": "success",
            "data": baas_results
        }
    except Exception as e:
        result["steps"]["baas_detection"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"BaaS detection error: {e}")

    # ── Step 6.6: APKiD — packers / obfuscators / anti-analysis ──
    logger.info("Step 6.6/7: APKiD packer & anti-analysis detection")
    try:
        from app.engines.static import apkid_scanner
        result["steps"]["apkid"] = {"status": "success", "data": apkid_scanner.scan_apk(apk_path)}
    except Exception as e:
        result["steps"]["apkid"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"APKiD error: {e}")

    # ── Step 6.7: Quark-Engine — rule-based behaviour scoring ──
    logger.info("Step 6.7/7: Quark-Engine behaviour rules")
    try:
        from app.engines.static import quark_scanner
        result["steps"]["quark"] = {"status": "success", "data": quark_scanner.scan_apk(apk_path)}
    except Exception as e:
        result["steps"]["quark"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"Quark-Engine error: {e}")

    # ── Step 6.8: Embedded payload / child APK detection ──
    logger.info("Step 6.8/7: Embedded payload (child APK) scan")
    embedded_results = {}
    try:
        from app.engines.static import embedded_payload_scanner
        embedded_results = embedded_payload_scanner.scan_apk(apk_path)
        result["steps"]["embedded_payloads"] = {"status": "success", "data": embedded_results}
    except Exception as e:
        result["steps"]["embedded_payloads"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"Embedded payload scan error: {e}")

    # ── Step 7: Risk Scoring ─────────────────────────────────
    logger.info("Step 7/7: Risk scoring")
    try:
        ag_step = result["steps"].get("androguard", {})
        ag_data = ag_step.get("data", {}) if ag_step.get("status") == "success" else {}
        
        scoring_input = {
            "permissions": manifest_results.get("permissions", {}),
            "manifest_misconfigurations": manifest_results.get("misconfigurations", []),
            "security_flags": manifest_results.get("security_flags", {}),
            "remote_access_abuse": manifest_results.get("remote_access_abuse", {}),
            "yara_results": yara_results,
            "iocs": ioc_results,
            "api_calls": ag_data.get("api_calls", {}),
            "baas_results": baas_results,
            "embedded_payloads": embedded_results,
        }

        risk_breakdown = risk_scorer.compute_static_risk(scoring_input)
        result["risk_score"] = risk_breakdown["total_score"]
        result["risk_breakdown"] = risk_breakdown

    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        result["errors"].append(f"Risk scoring error: {e}")
        result["risk_score"] = -1

    # ── Step 7.5: MO Classification ──────────────────────────
    logger.info("Step 7.5/8: MO Classification")
    try:
        mos = mo_classifier.classify_mo(manifest_results, ag_data)
        result["steps"]["mo_classification"] = {
            "status": "success",
            "data": {"mos": mos}
        }
        # Inject MOs into risk breakdown for frontend summary
        if "risk_breakdown" in result:
            result["risk_breakdown"]["mos"] = mos
    except Exception as e:
        logger.error(f"MO Classification failed: {e}")
        result["steps"]["mo_classification"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"MO Classification error: {e}")

    # ── Step 8: Fingerprinting ───────────────────────────────
    logger.info("Step 8/8: Structural Fingerprinting")
    try:
        fingerprint = fingerprint_engine.compute_structural_fingerprint(ag_data, apktool_dir)
        result["steps"]["fingerprint"] = {
            "status": "success",
            "data": fingerprint
        }
        # Save to DB later in task_service? The DB table is ApkFingerprint. 
        # We will save it to static_report for now.
    except Exception as e:
        logger.error(f"Fingerprinting failed: {e}")
        result["steps"]["fingerprint"] = {"status": "error", "error": str(e)}
        result["errors"].append(f"Fingerprint error: {e}")

    # ── Save Results & Hash Artifacts ────────────────────────
    end_time = datetime.now(timezone.utc)
    result["completed_at"] = end_time.isoformat()
    result["duration_seconds"] = (end_time - start_time).total_seconds()
    result["status"] = "completed" if not result["errors"] else "completed_with_errors"

    # Save the full report
    report_path = os.path.join(static_dir, "static_report.json")
    try:
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        result["artifact_hashes"]["static_report.json"] = _hash_file(report_path)
    except Exception as e:
        logger.error(f"Failed to save static report: {e}")

    # Save IOC list separately
    ioc_path = os.path.join(static_dir, "ioc_list.json")
    try:
        with open(ioc_path, "w") as f:
            json.dump(ioc_results, f, indent=2, default=str)
        result["artifact_hashes"]["ioc_list.json"] = _hash_file(ioc_path)
    except Exception as e:
        logger.error(f"Failed to save IOC list: {e}")

    # Save permissions profile
    perm_path = os.path.join(static_dir, "permissions_profile.json")
    try:
        perm_data = scoring_input.get("permissions", {})
        with open(perm_path, "w") as f:
            json.dump(perm_data, f, indent=2, default=str)
        result["artifact_hashes"]["permissions_profile.json"] = _hash_file(perm_path)
    except Exception as e:
        logger.error(f"Failed to save permissions profile: {e}")

    logger.info(
        f"Static analysis complete in {result['duration_seconds']:.1f}s — "
        f"Risk score: {result['risk_score']}/100 "
        f"({len(result['errors'])} errors)"
    )

    return result


def _hash_file(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "error"
