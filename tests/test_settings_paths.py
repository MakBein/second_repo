from xss_security_gui.settings import PAYLOADS_DIR, Settings


def test_settings_resolve_payload_directory_tokens():
    settings = Settings()

    assert settings.get("payloads.ssrf_file") == str(PAYLOADS_DIR / "ssrf.json")
    assert (PAYLOADS_DIR / "ssrf.json").is_file()
