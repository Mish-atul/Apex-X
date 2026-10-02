#!/usr/bin/env python3
"""
Standalone Testing Script for TM2 Analysis Engines (Static & Dynamic)
Usage:
    python run_engines.py path/to/sample.apk [--dynamic-only | --static-only]
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime

# Setup paths so we can import 'app' module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.engines.static import run_full_static_analysis
from app.engines.dynamic import run_full_dynamic_analysis
from app.engines.vulnerability import run_vulnerability_scan

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("StandaloneTester")

def main():
    parser = argparse.ArgumentParser(description="Standalone Test Runner for APEX-X Analysis Engines")
    parser.add_argument("apk_path", help="Path to the APK file to analyze")
    parser.add_argument("--static-only", action="store_true", help="Run only static analysis")
    parser.add_argument("--dynamic-only", action="store_true", help="Run only dynamic analysis")
    parser.add_argument("--output-dir", default="test_results", help="Directory to save the analysis reports")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.apk_path):
        logger.error(f"Error: APK file not found at {args.apk_path}")
        sys.exit(1)
        
    apk_path = os.path.abspath(args.apk_path)
    base_apk_name = os.path.basename(apk_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create unique output directory for this run
    case_dir = os.path.abspath(os.path.join(args.output_dir, f"{base_apk_name}_{timestamp}"))
    os.makedirs(case_dir, exist_ok=True)
    
    logger.info(f"Starting analysis for: {base_apk_name}")
    logger.info(f"Output directory: {case_dir}")
    
    results = {}
    
    # Run Static Analysis
    if not args.dynamic_only:
        logger.info("\n" + "="*50)
        logger.info("PHASE 1: STATIC ANALYSIS")
        logger.info("="*50)
        try:
            static_result = run_full_static_analysis(apk_path, case_dir)
            results["static"] = static_result
            
            logger.info("\n[+] Static Analysis Summary:")
            logger.info(f"  - Status: {static_result.get('status')}")
            logger.info(f"  - Risk Score: {static_result.get('risk_score')}/100")
            logger.info(f"  - Duration: {static_result.get('duration_seconds', 0):.2f}s")
            
            # Print steps that ran
            steps = static_result.get("steps", {})
            for step_name, step_data in steps.items():
                logger.info(f"  * {step_name}: {step_data.get('status', 'unknown')}")
                
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
    
    # Run Dynamic Analysis
    if not args.static_only:
        logger.info("\n" + "="*50)
        logger.info("PHASE 2: DYNAMIC ANALYSIS")
        logger.info("="*50)
        try:
            # We use a 30 second duration for this quick standalone test
            dynamic_result = run_full_dynamic_analysis(apk_path, case_dir, duration=30)
            results["dynamic"] = dynamic_result
            
            logger.info("\n[+] Dynamic Analysis Summary:")
            logger.info(f"  - Status: {dynamic_result.get('status')}")
            logger.info(f"  - Risk Score: {dynamic_result.get('risk_score')}/100")
            logger.info(f"  - Duration: {dynamic_result.get('duration_seconds', 0):.2f}s")
            
            # Print behaviors detected
            behaviors = dynamic_result.get("behavior_profile", {}).get("behaviors", {})
            detected = [k for k, v in behaviors.items() if v]
            logger.info(f"  - Detected Behaviors: {', '.join(detected) if detected else 'None'}")
            
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            
    # Run Vulnerability Discovery
    if not args.static_only and not args.dynamic_only:
        logger.info("\n" + "="*50)
        logger.info("PHASE 3: VULNERABILITY DISCOVERY")
        logger.info("="*50)
        try:
            # CLI runs have no database case, so pass a random id (DB fallback is skipped)
            import uuid
            vuln_result = run_vulnerability_scan(case_dir, str(uuid.uuid4()))
            results["vulnerability"] = vuln_result

            findings = vuln_result.get("findings", [])
            by_sev = {s: sum(1 for f in findings if f.get("severity") == s) for s in ("critical", "high", "medium", "low")}
            logger.info("\n[+] Vulnerability Discovery Summary:")
            logger.info(f"  - Status: {vuln_result.get('status')}  Risk score: {vuln_result.get('risk_score')}")
            logger.info(f"  - Total Vulnerabilities: {len(findings)}")
            logger.info(f"  - Critical: {by_sev['critical']}, High: {by_sev['high']}, Medium: {by_sev['medium']}, Low: {by_sev['low']}")
            logger.info(f"  - Duration: {vuln_result.get('duration_seconds', 0):.2f}s")
            
        except Exception as e:
            logger.error(f"Vulnerability discovery failed: {e}")
            
    # Save combined report
    combined_report_path = os.path.join(case_dir, "combined_report.json")
    try:
        with open(combined_report_path, "w") as f:
            json.dump(results, f, indent=4, default=str)
        logger.info(f"\n[✓] Analysis complete! Full combined report saved to: {combined_report_path}")
    except Exception as e:
        logger.error(f"Failed to save combined report: {e}")

if __name__ == "__main__":
    main()
