# xss_security_gui/result_transformer.py

"""
Crawler Results Transformer
Converts raw crawler output into a production-ready "боевой" format.
Enhances data, masks sensitive info, and provides actionable insights.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse


class CrawlerResultTransformer:
    """Transform raw crawler results into enhanced production format."""
    
    # Patterns to mask/obfuscate sensitive data
    SENSITIVE_PATTERNS = {
        'api_key': r'[\w\-]{20,}(?:[A-Za-z0-9_\-]{10,})?',
        'jwt': r'eyJ[\w\-\.]+',
        'recaptcha_key': r'6L[\w\-]{38,}',
        'auth_token': r'["\']token["\']:\s*["\'][\w\-\.]{20,}["\']',
    }
    
    SENSITIVE_KEYWORDS = {
        'password', 'secret', 'token', 'api_key', 'auth', 'credential',
        'privatekey', 'private_key', 'accesskey', 'access_key',
        'secret_key', 'client_secret', 'consumer_secret'
    }
    
    # JS libraries/frameworks to identify
    TECH_PATTERNS = {
        'react': r'react|_react|\b__REACT',
        'vue': r'vue|__VUE__',
        'angular': r'angular|ng-',
        'jquery': r'\bjQuery|\$\.ajax',
        'bootstrap': r'bootstrap\.min|bootstrap\.css',
        'lodash': r'_\.|\blodash\b',
        'axios': r'axios\.(?:get|post)',
        'fetch': r'fetch\(',
    }
    
    def __init__(self, raw_data: Dict[str, Any], verbose: bool = False):
        """Initialize transformer with raw crawler data."""
        self.raw = raw_data
        self.verbose = verbose
        self.target_url = raw_data.get('meta', {}).get('target_url', 'unknown')
        self.timestamp = raw_data.get('meta', {}).get('timestamp', datetime.now().isoformat())
    
    def mask_sensitive_value(self, value: str, hint: str = "") -> str:
        """Mask sensitive values while keeping structure visible."""
        if not isinstance(value, str) or len(value) < 8:
            return value
        
        # Check if value matches sensitive patterns
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, value):
                # Return masked version
                return f"***{pattern_name}***[{len(value)} chars]"
        
        # Check if it looks like an API key or secret
        if any(kw in value.lower() for kw in self.SENSITIVE_KEYWORDS):
            return f"***sensitive***[{len(value)} chars]"
        
        return value
    
    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except:
            return url
    
    def categorize_errors(self, errors: List[str]) -> Dict[str, List[str]]:
        """Categorize errors by type."""
        categories = {
            'timeout': [],
            'auth': [],
            'blocked': [],
            'network': [],
            'other': []
        }
        
        for error in errors:
            error_lower = error.lower()
            if 'timeout' in error_lower or 'timed out' in error_lower:
                categories['timeout'].append(error)
            elif 'auth' in error_lower or 'login' in error_lower or '401' in error or '403' in error:
                categories['auth'].append(error)
            elif 'block' in error_lower or '429' in error or 'cloudflare' in error_lower:
                categories['blocked'].append(error)
            elif 'connect' in error_lower or 'dns' in error_lower or 'network' in error_lower:
                categories['network'].append(error)
            else:
                categories['other'].append(error)
        
        return {k: v for k, v in categories.items() if v}
    
    def extract_top_scripts(self, scripts: List[str], limit: int = 10) -> List[Dict[str, str]]:
        """Extract and categorize top scripts."""
        script_data = []
        for script_url in scripts[:limit]:
            domain = self.extract_domain_from_url(script_url)
            category = self._categorize_script(script_url)
            script_data.append({
                'url': script_url,
                'domain': domain,
                'category': category
            })
        return script_data
    
    def _categorize_script(self, url: str) -> str:
        """Categorize script by its source/purpose."""
        url_lower = url.lower()
        
        if 'google' in url_lower:
            return 'analytics'
        elif 'cdn' in url_lower or 'jsdelivr' in url_lower or 'cloudflare' in url_lower:
            return 'cdn'
        elif 'recaptcha' in url_lower or 'captcha' in url_lower:
            return 'captcha'
        elif 'analytics' in url_lower or 'gtag' in url_lower or 'ga' in url_lower:
            return 'analytics'
        elif 'ads' in url_lower or 'ad.' in url_lower:
            return 'advertising'
        elif 'tracking' in url_lower or 'pixel' in url_lower:
            return 'tracking'
        else:
            return 'third-party'
    
    def extract_tokens_summary(self, tokens: List[str], limit: int = 20) -> Dict[str, Any]:
        """Extract meaningful tokens (filtering common noise)."""
        if not tokens:
            return {'count': 0, 'samples': [], 'categories': {}}
        
        # Filter out obvious noise and variable names
        meaningful = []
        categories = {
            'dom_id': [],
            'css_class': [],
            'js_var': [],
            'security': [],
            'other': []
        }
        
        for token in tokens:
            if not token or len(token) < 2:
                continue
            
            # Skip obvious noise
            if re.match(r'^[._\-]*$', token) or token.isdigit():
                continue
            
            # Categorize
            if any(x in token.lower() for x in ['id', 'wrapper', 'content', 'comment']):
                categories['dom_id'].append(token)
            elif token.startswith('jq-'):
                categories['css_class'].append(token)
            elif any(x in token.lower() for x in ['function', 'var', 'global', 'alt', 'key']):
                categories['js_var'].append(token)
            elif any(x in token.lower() for x in ['token', 'key', 'secret', 'auth', 'recaptcha']):
                categories['security'].append(token)
            else:
                categories['other'].append(token)
            
            meaningful.append(token)
        
        return {
            'total': len(meaningful),
            'samples': meaningful[:limit],
            'categories': {k: len(v) for k, v in categories.items() if v}
        }
    
    def detect_technologies(self, content: Dict[str, Any]) -> List[str]:
        """Detect technologies used on site."""
        techs = []
        
        # Scan scripts
        scripts = content.get('scripts', [])
        for script in scripts:
            for tech, pattern in self.TECH_PATTERNS.items():
                if re.search(pattern, script, re.I):
                    if tech not in techs:
                        techs.append(tech)
        
        # Scan tokens for common framework patterns
        tokens = content.get('tokens', [])
        token_str = ' '.join(str(t) for t in tokens[:100])
        for tech, pattern in self.TECH_PATTERNS.items():
            if re.search(pattern, token_str, re.I):
                if tech not in techs:
                    techs.append(tech)
        
        return techs
    
    def transform(self) -> Dict[str, Any]:
        """Transform raw data into enhanced production format."""
        
        result = {
            "metadata": {
                "target_url": self.target_url,
                "timestamp": self.timestamp,
                "transformer_version": "1.0",
                "status": self._determine_status(),
            },
            "summary": self._build_summary(),
            "errors_report": self._build_errors_report(),
            "content_analysis": self._build_content_analysis(),
            "security_insights": self._build_security_insights(),
            "technologies_detected": self.detect_technologies(self.raw),
            "recommendations": self._build_recommendations(),
            "raw_counts": {
                "visited_urls": len(self.raw.get('visited', [])),
                "scripts": len(self.raw.get('scripts', [])),
                "api_endpoints": len(self.raw.get('api_endpoints', [])),
                "tokens": len(self.raw.get('tokens', [])),
                "emails": len(self.raw.get('emails', [])),
                "errors": len(self.raw.get('errors', [])),
            }
        }
        
        return result
    
    def _determine_status(self) -> str:
        """Determine overall crawl status."""
        errors = self.raw.get('errors', [])
        visited = self.raw.get('visited', [])
        
        if not errors and visited:
            return "success"
        elif errors and visited:
            return "partial"
        elif errors and not visited:
            return "failed"
        else:
            return "unknown"
    
    def _build_summary(self) -> Dict[str, Any]:
        """Build high-level summary."""
        raw = self.raw
        return {
            "crawl_result": self._determine_status().upper(),
            "pages_visited": len(raw.get('visited', [])),
            "scripts_found": len(raw.get('scripts', [])),
            "api_endpoints": len(raw.get('api_endpoints', [])),
            "external_links": len([u for u in raw.get('visited', []) if not u.startswith('javascript:')]),
            "sensitive_data_found": len(raw.get('emails', [])) + len(raw.get('tokens', [])) > 0,
            "error_count": len(raw.get('errors', [])),
        }
    
    def _build_errors_report(self) -> Dict[str, Any]:
        """Build detailed error report."""
        errors = self.raw.get('errors', [])
        if not errors:
            return {"status": "no_errors", "categories": {}}
        
        return {
            "status": "errors_detected",
            "total_errors": len(errors),
            "categories": self.categorize_errors(errors),
            "recent": errors[-3:] if len(errors) > 3 else errors,
        }
    
    def _build_content_analysis(self) -> Dict[str, Any]:
        """Build content analysis."""
        return {
            "top_scripts": self.extract_top_scripts(self.raw.get('scripts', []), limit=10),
            "tokens_summary": self.extract_tokens_summary(self.raw.get('tokens', []), limit=20),
            "visited_urls_sample": (self.raw.get('visited', []))[:5],
            "emails_found": self.raw.get('emails', [])[:20],  # Limit to first 20
        }
    
    def _build_security_insights(self) -> Dict[str, Any]:
        """Build security-focused insights."""
        return {
            "found_potential_secrets": any(
                keyword in str(self.raw).lower() 
                for keyword in self.SENSITIVE_KEYWORDS
            ),
            "has_external_scripts": len(self.raw.get('scripts', [])) > 0,
            "has_api_endpoints": len(self.raw.get('api_endpoints', [])) > 0,
            "third_party_domains": self._extract_third_party_domains(),
            "risk_level": self._assess_risk_level(),
        }
    
    def _extract_third_party_domains(self) -> List[str]:
        """Extract third-party domains."""
        domains = set()
        target_domain = self.extract_domain_from_url(self.target_url)
        
        for url in self.raw.get('scripts', []):
            domain = self.extract_domain_from_url(url)
            if domain and domain != target_domain:
                domains.add(domain)
        
        return sorted(list(domains))[:10]
    
    def _assess_risk_level(self) -> str:
        """Assess overall risk level."""
        errors = self.raw.get('errors', [])
        scripts = self.raw.get('scripts', [])
        
        if any('block' in e.lower() or 'cloudflare' in e.lower() for e in errors):
            return "HIGH (WAF/protection detected)"
        elif any('timeout' in e.lower() for e in errors):
            return "MEDIUM (timeout issues)"
        elif len(scripts) > 20:
            return "MEDIUM (many external scripts)"
        elif errors:
            return "MEDIUM (errors encountered)"
        else:
            return "LOW (clean crawl)"
    
    def _build_recommendations(self) -> List[str]:
        """Build recommendations based on findings."""
        recommendations = []
        
        errors = self.raw.get('errors', [])
        if any('timeout' in e.lower() for e in errors):
            recommendations.append("⚠️ Consider increasing timeout for slow targets (use --timeout 30000)")
        
        if any('block' in e.lower() or 'cloudflare' in e.lower() for e in errors):
            recommendations.append("🛡️ Target protected by WAF; may require proxy rotation or headers adjustment")
        
        if len(self.raw.get('scripts', [])) > 30:
            recommendations.append("📊 Target loaded many external scripts; consider security review")
        
        if self.raw.get('tokens', []):
            recommendations.append("🔑 Sensitive tokens found; review and verify they're not credentials")
        
        if not errors and self.raw.get('visited', []):
            recommendations.append("✅ Clean crawl; target is standard web application")
        
        return recommendations


def transform_crawler_results(input_file: Path, output_file: Path, verbose: bool = False) -> bool:
    """Transform a crawler results file."""
    try:
        # Read input
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract raw data
        raw_data = data.get('raw', {})
        
        # Transform
        transformer = CrawlerResultTransformer(raw_data, verbose=verbose)
        transformed = transformer.transform()
        
        # Add original data for reference
        output = {
            "enhanced_results": transformed,
            "original_raw_data_retained": {
                "visited_count": len(raw_data.get('visited', [])),
                "scripts_count": len(raw_data.get('scripts', [])),
                "total_tokens": len(raw_data.get('tokens', [])),
            }
        }
        
        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        if verbose:
            print(f"✅ Transformed: {input_file} → {output_file}")
        
        return True
    except Exception as e:
        print(f"❌ Transform failed: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python result_transformer.py <input.json> [output.json]")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(str(input_path).replace('.json', '_enhanced.json'))
    
    success = transform_crawler_results(input_path, output_path, verbose=True)
    sys.exit(0 if success else 1)

