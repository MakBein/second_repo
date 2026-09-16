# xss_security_gui/auto_recon/orchestrator/__main__.py
"""
Entry point for running orchestrator as a module.
Usage: python -m xss_security_gui.auto_recon.orchestrator https://target.com
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from xss_security_gui.auto_recon.orchestrator import run_full_autorecon_enterprise
    from xss_security_gui.auto_recon import get_logger, get_user_context
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m xss_security_gui.auto_recon.orchestrator <target_url> [options]")
        print("Example: python -m xss_security_gui.auto_recon.orchestrator https://example.com --aggressive")
        sys.exit(1)

    target = sys.argv[1]
    aggressive = "--aggressive" in sys.argv

    logger = get_logger("OrchestratorMain")
    ctx = get_user_context()

    print(f"🔒 AutoRecon Enterprise V7")
    print(f"User: {ctx.user_id}, Session: {ctx.session_id}")
    print(f"Target: {target}")
    print(f"Mode: {'Aggressive' if aggressive else 'Standard'}")

    try:
        config = {"aggressive": aggressive}
        report = run_full_autorecon_enterprise(target, config=config)

        if "error" in report:
            print(f"❌ Error: {report['error']}")
            return 1

        total_vulns = report.get("vulnerability_report", {}).get("metadata", {}).get("total_vulnerabilities", 0)
        risk_score = report.get("detailed_analysis", {}).get("risk_assessment", {}).get("overall_score", 0)

        print("✅ Scan complete!")
        print(f"Vulnerabilities found: {total_vulns}")
        print(f"Risk Score: {risk_score}")

        return 0

    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Scan failed: {e}", user_id=ctx.user_id)
        return 1


if __name__ == "__main__":
    sys.exit(main())
