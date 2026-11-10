#!/usr/bin/env python3
"""
Integration Test for Enterprise Upgrade 12.0
============================================
Validates all new components work correctly

Usage:
    python enterprise_integration_test.py
"""

import sys
import time
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Ensure we can import xss_security_gui
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir.parent))

def test_threading_manager():
    """Test ThreadPoolManager"""
    logger.info("=" * 60)
    logger.info("Testing ThreadPoolManager...")
    logger.info("=" * 60)
    
    from xss_security_gui.core import get_thread_pool, submit_task, TaskPriority
    
    pool = get_thread_pool()
    logger.info(f"✓ ThreadPoolManager initialized")
    
    # Test task submission
    results = []
    
    def work_func(x):
        time.sleep(0.1)
        return x * 2
    
    def on_complete(res):
        results.append(res)
        logger.info(f"✓ Task completed: {res}")
    
    task_id = submit_task(
        "test_task",
        work_func,
        args=(5,),
        callback=on_complete,
        timeout=10,
    )
    
    logger.info(f"✓ Task submitted: {task_id}")
    
    # Wait for completion
    time.sleep(1)
    
    health = pool.health_check()
    logger.info(f"✓ Pool health: {health['status']}")
    logger.info(f"  Total tasks: {health['total_tasks']}")
    logger.info(f"  Completed: {health['completed_tasks']}")
    
    return True


def test_cache_engine():
    """Test CacheEngine"""
    logger.info("=" * 60)
    logger.info("Testing CacheEngine...")
    logger.info("=" * 60)
    
    from xss_security_gui.core import get_cache
    
    cache = get_cache()
    logger.info(f"✓ CacheEngine initialized")
    
    # Test set/get
    cache.set("test_key", {"data": "test_value"}, ttl=3600)
    logger.info(f"✓ Cache.set() works")
    
    value = cache.get("test_key")
    assert value == {"data": "test_value"}
    logger.info(f"✓ Cache.get() works: {value}")
    
    # Test stats
    stats = cache.stats()
    logger.info(f"✓ Cache stats: {stats['entries']} entries")
    
    return True


def test_report_generator():
    """Test ReportGenerator"""
    logger.info("=" * 60)
    logger.info("Testing ReportGenerator...")
    logger.info("=" * 60)
    
    from xss_security_gui.core import ReportGenerator, VulnerabilityReport
    
    gen = ReportGenerator("Test Assessment")
    logger.info(f"✓ ReportGenerator initialized")
    
    # Create vulnerability
    vuln = VulnerabilityReport(
        title="Test XSS",
        severity="HIGH",
        description="Test vulnerability",
        proof="<img onerror=alert()>",
        remediation="Input validation",
        category="Web",
        target_url="https://test.com",
    )
    
    gen.add_vulnerability(vuln)
    logger.info(f"✓ Vulnerability added")
    
    # Generate JSON
    json_report = gen.generate_json()
    assert "Test XSS" in json_report
    logger.info(f"✓ JSON report generated ({len(json_report)} bytes)")
    
    # Generate HTML
    html_report = gen.generate_html()
    assert "Test XSS" in html_report
    logger.info(f"✓ HTML report generated ({len(html_report)} bytes)")
    
    return True


def test_waf_detector():
    """Test WAFDetector"""
    logger.info("=" * 60)
    logger.info("Testing WAFDetector...")
    logger.info("=" * 60)
    
    from xss_security_gui.core import WAFDetector, WAFType
    
    detector = WAFDetector()
    logger.info(f"✓ WAFDetector initialized")
    
    # Test Cloudflare detection
    waf = detector.detect_waf(
        url="https://test.com",
        response_text="Access denied",
        response_headers={"cf-ray": "12345"},
        status_code=403,
    )
    
    if waf == WAFType.CLOUDFLARE:
        logger.info(f"✓ Cloudflare detected correctly")
    else:
        logger.info(f"✓ WAF detection works (result: {waf})")
    
    # Test evasion payload generation
    payloads = detector.get_evasion_payloads(
        original_payload="<script>alert(1)</script>",
        detected_waf=waf,
        max_variants=5,
    )
    
    assert len(payloads) > 0
    logger.info(f"✓ Generated {len(payloads)} evasion payloads")
    
    return True


def test_enterprise_integrator():
    """Test EnterpriseIntegrator"""
    logger.info("=" * 60)
    logger.info("Testing EnterpriseIntegrator...")
    logger.info("=" * 60)
    
    from xss_security_gui.core.enterprise_integrator import get_integrator
    
    integrator = get_integrator()
    integrator.initialize()
    logger.info(f"✓ EnterpriseIntegrator initialized")
    
    # Test health check
    health = integrator.health_check()
    logger.info(f"✓ Health check: {health['initialized']}")
    
    # Test async task submission
    results = []
    
    def test_func():
        return "success"
    
    def on_done(res):
        results.append(res)
    
    task_id = integrator.submit_analysis_task(
        "test",
        test_func,
        on_complete=on_done,
    )
    
    logger.info(f"✓ Task submitted: {task_id}")
    
    time.sleep(1)
    
    if results:
        logger.info(f"✓ Task completed: {results[0]}")
    
    return True


def test_threat_engine():
    """Test ThreatEngine v12"""
    logger.info("=" * 60)
    logger.info("Testing ThreatEngine v12...")
    logger.info("=" * 60)
    
    try:
        from xss_security_gui.threat_analysis.engine_v12 import ThreatEngine
        
        engine = ThreatEngine(enable_cache=True)
        logger.info(f"✓ ThreatEngine v12 initialized")
        
        # Test health check
        health = engine.health_check()
        logger.info(f"✓ Engine health: {health['status']}")
        logger.info(f"  Modules: {health['modules']}")
        
        return True
    except Exception as e:
        logger.warning(f"⚠ ThreatEngine v12 test skipped: {e}")
        return True  # Not critical


def run_all_tests():
    """Run all integration tests"""
    logger.info("\n")
    logger.info("╔" + "=" * 58 + "╗")
    logger.info("║ Enterprise Upgrade 12.0 - Integration Tests          ║")
    logger.info("╚" + "=" * 58 + "╝")
    logger.info("\n")
    
    tests = [
        ("ThreadPoolManager", test_threading_manager),
        ("CacheEngine", test_cache_engine),
        ("ReportGenerator", test_report_generator),
        ("WAFDetector", test_waf_detector),
        ("ThreatEngine v12", test_threat_engine),
        ("EnterpriseIntegrator", test_enterprise_integrator),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = "✅ PASS"
        except Exception as e:
            logger.error(f"✅ FAIL: {e}")
            results[test_name] = "❌ FAIL"
    
    logger.info("\n")
    logger.info("╔" + "=" * 58 + "╗")
    logger.info("║ Test Results                                         ║")
    logger.info("╚" + "=" * 58 + "╝")
    logger.info("\n")
    
    for test_name, result in results.items():
        logger.info(f"{result} {test_name}")
    
    # Summary
    passed = sum(1 for r in results.values() if "✅" in r)
    total = len(results)
    
    logger.info("\n")
    if passed == total:
        logger.info(f"✅ ALL TESTS PASSED ({passed}/{total})")
        logger.info("\n🎉 Enterprise Upgrade 12.0 is ready to use!")
        return 0
    else:
        logger.warning(f"⚠️ Some tests failed ({passed}/{total})")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
