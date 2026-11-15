import os
import subprocess
import sys
from pathlib import Path


def test_main_module_import_does_not_load_native_tls_client():
    project_parent = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["XSS_GUI_AUTO_INIT"] = "0"

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import xss_security_gui.main; "
            "assert 'tls_client' not in sys.modules",
        ],
        cwd=project_parent,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=45,
    )

    assert result.returncode == 0, (
        f"GUI startup import failed ({result.returncode}):\n"
        f"{result.stdout}\n{result.stderr}"
    )
