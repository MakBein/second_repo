#!/usr/bin/env python
# xss_security_gui/examples_ai_training.py
"""
Examples of using AI training integration in various scenarios.
Run individual functions to test different components.
"""

import sys
from pathlib import Path

# Add project root to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def example_1_analyze_threats():
    """Example 1: Analyze threats with ML model."""
    from xss_security_gui.ai_adapter import get_ai_assistant
    
    print("\n" + "="*70)
    print("EXAMPLE 1: Analyze threats with ML model")
    print("="*70)
    
    assistant = get_ai_assistant()
    print(f"[✓] AI Assistant loaded (model: {type(assistant.core).__name__})")
    
    threats = [
        {
            "type": "email_leak",
            "emails": ["admin@example.com", "user@example.com"],
            "smtp_passwords": ["password123", "admin456"],
        },
        {
            "type": "credit_card",
            "numbers": ["4111111111111111", "5555555555554444"],
        },
        {
            "type": "xss_payload",
            "payload": '<script>alert("xss")</script>',
        },
    ]
    
    for i, threat in enumerate(threats, 1):
        result = assistant.analyze(threat)
        print(f"\n[Threat {i}]")
        print(f"  Type: {threat.get('type')}")
        print(f"  Analysis: {result}")


def example_2_learn_threats():
    """Example 2: Learn threats for future training."""
    from xss_security_gui.ai_adapter import get_ai_assistant
    
    print("\n" + "="*70)
    print("EXAMPLE 2: Learn threats for future training")
    print("="*70)
    
    assistant = get_ai_assistant()
    
    threats = [
        {"type": "safe", "content": "Hello world"},
        {"type": "xss", "content": "<img src=x onerror=alert(1)>"},
        {"type": "xss", "content": "eval(atob('...')"},
    ]
    
    for i, threat in enumerate(threats, 1):
        assistant.learn(threat)
        print(f"[{i}] Learned: {threat}")
    
    print("\n[✓] All threats queued for next training cycle")


def example_3_start_training():
    """Example 3: Start async training and monitor progress."""
    from xss_security_gui.ai_adapter import train_ai_async, get_training_status
    import time
    
    print("\n" + "="*70)
    print("EXAMPLE 3: Start async training and monitor progress")
    print("="*70)
    
    def on_training_done(report):
        print(f"\n[✓] Training completed!")
        print(f"  Status: {report.get('status')}")
        print(f"  Message: {report.get('message')}")
        print(f"  Samples: {report.get('num_samples_raw')}")
        print(f"  Model path: {report.get('model_path')}")
    
    def on_training_error(error):
        print(f"\n[✗] Training failed: {error}")
    
    print("[*] Starting training...")
    success = train_ai_async(on_done=on_training_done, on_error=on_training_error)
    
    if not success:
        print("[!] Training already in progress or no trainer available")
        return
    
    print("[*] Training started in background")
    print("[*] Polling status...")
    
    # Simple polling (in real GUI, this would be done via tkinter.after)
    for _ in range(60):
        time.sleep(0.5)
        status = get_training_status()
        if not status.get('in_progress'):
            print(f"\n[✓] Training finished")
            break
        print(".", end="", flush=True)


def example_4_cli_training():
    """Example 4: Direct training from CLI."""
    from xss_security_gui.ai_core.train_nn_model import train_from_logs
    
    print("\n" + "="*70)
    print("EXAMPLE 4: Direct training from CLI")
    print("="*70)
    
    print("[*] Running train_from_logs()...")
    report = train_from_logs()
    
    print(f"\n[✓] Training report:")
    for key, value in report.items():
        if key != "metrics":
            print(f"  {key}: {value}")


def example_5_threat_history():
    """Example 5: Check threat history."""
    from pathlib import Path
    import json
    
    print("\n" + "="*70)
    print("EXAMPLE 5: Check threat history")
    print("="*70)
    
    history_file = Path(__file__).parent / "logs" / "threat_history.json"
    
    if not history_file.exists():
        print(f"[!] No threat history found at: {history_file}")
        print("[*] History will be created after loading threats in Threat Tab")
        return
    
    with open(history_file, "r", encoding="utf-8") as f:
        history = json.load(f) or []
    
    print(f"[✓] Found {len(history)} threats in history")
    
    for i, record in enumerate(history[:5], 1):
        print(f"\n[{i}] {record.get('timestamp')}")
        entry = record.get('entry', {})
        if isinstance(entry, dict):
            print(f"    Keys: {list(entry.keys())}")


def example_6_training_report():
    """Example 6: View training report."""
    from pathlib import Path
    import json
    
    print("\n" + "="*70)
    print("EXAMPLE 6: View training report")
    print("="*70)
    
    report_file = Path(__file__).parent / "logs" / "ai_core" / "training_report.json"
    
    if not report_file.exists():
        print(f"[!] No training report found at: {report_file}")
        print("[*] Report will be created after running training")
        return
    
    with open(report_file, "r", encoding="utf-8") as f:
        report = json.load(f)
    
    print(f"[✓] Training Report:")
    print(f"  Status: {report.get('status')}")
    print(f"  Message: {report.get('message')}")
    print(f"  Samples: {report.get('num_samples_raw')}")
    print(f"  Classes: {report.get('num_classes')}")
    print(f"  Model path: {report.get('model_path')}")
    
    metrics = report.get('metrics', {})
    if metrics and 'classification_report' in metrics:
        print(f"  Metrics available: {list(metrics.keys())}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Training Examples")
    parser.add_argument(
        "example",
        nargs="?",
        choices=["1", "2", "3", "4", "5", "6", "all"],
        default="all",
        help="Example to run (default: all)"
    )
    
    args = parser.parse_args()
    
    examples = {
        "1": example_1_analyze_threats,
        "2": example_2_learn_threats,
        "3": example_3_start_training,
        "4": example_4_cli_training,
        "5": example_5_threat_history,
        "6": example_6_training_report,
    }
    
    if args.example == "all":
        for num in ["1", "2", "5", "6"]:
            try:
                examples[num]()
            except Exception as e:
                print(f"\n[✗] Example {num} failed: {e}")
    else:
        try:
            examples[args.example]()
        except Exception as e:
            print(f"\n[✗] Example failed: {e}")
            import traceback
            traceback.print_exc()

