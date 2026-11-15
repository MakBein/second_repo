#!/usr/bin/env python3
"""
AutoRecon Runner — простой запускатель для orchestrator.py
Использование: python run_autorecon.py https://target.com
"""

import sys
import os

# Добавляем родительскую директорию в путь для импортов
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Теперь можем импортировать модули
from xss_security_gui.auto_recon.orchestrator import run_full_autorecon, run_aggressive_scan
from xss_security_gui.auto_recon.reporting import get_report_generator
import argparse
import logging

def main():
    parser = argparse.ArgumentParser(description="AutoRecon Enterprise Runner")
    parser.add_argument("targets", nargs="+", help="Target URLs to scan")
    parser.add_argument("--aggressive", action="store_true", help="Run aggressive scan")
    parser.add_argument("--workers", type=int, default=5, help="Max workers (default: 5)")
    parser.add_argument("--payloads", type=int, default=50, help="Max payloads per type (default: 50)")
    parser.add_argument("--export-html", action="store_true", help="Export HTML report")
    parser.add_argument("--export-json", action="store_true", help="Export JSON report")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Build config
    config = {
        "aggressive": args.aggressive,
        "max_workers": args.workers,
        "max_payloads": args.payloads,
        "export_html": args.export_html,
        "export_json": args.export_json,
    }

    def progress_callback(msg):
        stage = msg.get("stage", "unknown")
        status = msg.get("status", "running")
        print(f"[{stage.upper()}] {status}")

    try:
        print(f"🚀 Starting AutoRecon Enterprise scan for: {', '.join(args.targets)}")
        print(f"⚙️  Config: {config}")

        if args.aggressive:
            result = run_aggressive_scan(args.targets, progress_callback)
        else:
            result = run_full_autorecon(args.targets, config, progress_callback)

        print("✅ Scan completed successfully!")

        # Export reports if requested
        if args.export_html or args.export_json:
            reporter = get_report_generator()

            if args.export_json:
                json_path = reporter.save_report(result)
                print(f"📄 JSON report saved: {json_path}")

            if args.export_html:
                html_path = reporter.generate_html_report(result)
                print(f"🌐 HTML report saved: {html_path}")

        # Print summary
        threat_report = result.get("threat_report", {})
        stats = threat_report.get("scan_report", {}).get("statistics", {})
        print("📊 Summary:")
        print(f"  • Total scanned: {stats.get('total_scanned', 0)}")
        print(f"  • Vulnerabilities found: {stats.get('vulnerable_found', 0)}")
        print(f"  • Success rate: {stats.get('success_rate_percent', 0):.1f}%")

        risk = threat_report.get("detailed_analysis", {}).get("risk_assessment", {})
        print(f"  • Risk level: {risk.get('risk_level', 'unknown')}")
        print(f"  • Overall score: {risk.get('overall_score', 0):.1f}/10")

    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during scan: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
