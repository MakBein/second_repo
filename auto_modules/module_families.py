# xss_security_gui/auto_modules/module_families.py
MODULE_FAMILIES = {
    "API Endpoints": {
        "family": "recon",
        "risk": 3,
        "tags": ["api", "recon", "mapping"],
    },
    "Token Brute Force": {
        "family": "auth",
        "risk": 7,
        "tags": ["auth", "bruteforce", "tokens"],
    },
    "Parameters Discovery": {
        "family": "recon",
        "risk": 4,
        "tags": ["params", "recon"],
    },
    "User IDs Enumeration": {
        "family": "auth",
        "risk": 6,
        "tags": ["auth", "enumeration"],
    },
    "XSS Targets": {
        "family": "xss",
        "risk": 9,
        "tags": ["xss", "injection"],
    },
    "GraphQL Endpoints": {
        "family": "graphql",
        "risk": 5,
        "tags": ["graphql", "api"],
    },
    "JS Sensitive Analysis": {
        "family": "js",
        "risk": 6,
        "tags": ["js", "secrets", "analysis"],
    },
    "Security Headers Review": {
        "family": "headers",
        "risk": 4,
        "tags": ["headers", "security"],
    },
    "CSP Weakness Scan": {
        "family": "headers",
        "risk": 7,
        "tags": ["csp", "headers", "xss"],
    },
    "Secrets & Keys": {
        "family": "secrets",
        "risk": 10,
        "tags": ["secrets", "keys", "leaks"],
    },
    "JWT Tokens": {
        "family": "auth",
        "risk": 8,
        "tags": ["jwt", "auth"],
    },
    "Forms & Inputs": {
        "family": "forms",
        "risk": 5,
        "tags": ["forms", "inputs", "validation"],
    },
    "Error Pages & Stacktraces": {
        "family": "errors",
        "risk": 6,
        "tags": ["errors", "debug"],
    },
    "CORS Misconfiguration": {
        "family": "headers",
        "risk": 8,
        "tags": ["cors", "headers", "misconfiguration"],
    },
    "Security Headers Audit": {
        "family": "headers",
        "risk": 5,
        "tags": ["headers", "security", "audit"],
    },
    "Open Redirect": {
        "family": "redirect",
        "risk": 6,
        "tags": ["redirect", "phishing"],
    },
    "CRLF Injection": {
        "family": "injection",
        "risk": 7,
        "tags": ["crlf", "injection", "headers"],
    },
    "HTTP Method Tampering": {
        "family": "recon",
        "risk": 5,
        "tags": ["methods", "recon", "bypass"],
    },
    "Path Traversal": {
        "family": "injection",
        "risk": 8,
        "tags": ["lfi", "path_traversal", "injection"],
    },
    "Header Injection": {
        "family": "injection",
        "risk": 7,
        "tags": ["headers", "injection"],
    },
    "Technology Fingerprint": {
        "family": "recon",
        "risk": 2,
        "tags": ["fingerprint", "recon", "tech"],
    },
}