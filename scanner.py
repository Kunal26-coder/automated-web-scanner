#!/usr/bin/env python3
"""
=============================================================================
Automated Web Scanner
=============================================================================
A comprehensive cybersecurity CLI tool that audits web applications for:
  - Missing HTTP Security Headers (HSTS, CSP, X-Frame-Options, etc.)
  - Information Disclosure & Banner Leakage (Server, X-Powered-By, etc.)
  - Insecure Cookie Directives (Missing Secure and HttpOnly flags)
  - CORS Misconfigurations (Arbitrary origin reflection, wildcard with creds)
  - Transport Layer Security (Plaintext HTTP vs HTTPS enforcement)
  - Security Posture Scoring (100-point rubric with A-F grading)

OWASP Top 10 Mapping: A05:2021 - Security Misconfiguration

LEGAL DISCLAIMER:
This tool is intended strictly for educational, defensive, and authorized
security testing. Scanning targets without prior explicit written authorization
is illegal under international computer misuse regulations. Always ensure you
have permission before conducting security audits.

Author: Senior Cybersecurity Engineer
Tech Stack: Python 3 standard library + requests
=============================================================================
"""

import argparse
import ctypes
import html
import json
import os
import re
import socket
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

# Suppress SSL verification warnings when falling back to verify=False for cert audits
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure current script directory is in sys.path for direct module import
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from report_generator import generate_html_report


# =============================================================================
# ANSI Terminal Colors & Formatter
# =============================================================================
class Colors:
    """ANSI color codes for rich terminal visualization."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Foreground colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    
    # Background badges
    BG_RED = "\033[41m\033[97m\033[1m"
    BG_YELLOW = "\033[43m\033[30m\033[1m"
    BG_BLUE = "\033[44m\033[97m\033[1m"
    BG_GREEN = "\033[42m\033[30m\033[1m"
    BG_GRAY = "\033[100m\033[97m\033[1m"


def enable_windows_ansi() -> None:
    """Enable virtual terminal processing and UTF-8 encoding in Windows consoles."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


def colorize(text: str, color: str, use_color: bool = True) -> str:
    """Wrap text in ANSI color codes if coloring is active."""
    return f"{color}{text}{Colors.RESET}" if use_color else text


# =============================================================================
# Security Audit Specifications & Remediation Knowledgebase
# =============================================================================
OWASP_A05 = "A05:2021 - Security Misconfiguration"

SECURITY_HEADERS_DEF = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Protects against protocol downgrade attacks, SSL stripping, and cookie hijacking.",
        "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "owasp": OWASP_A05,
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "name": "Content-Security-Policy (CSP)",
        "description": "Mitigates Cross-Site Scripting (XSS), code injection, and data exfiltration.",
        "remediation": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
        "owasp": OWASP_A05,
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "name": "X-Frame-Options (Clickjacking Protection)",
        "description": "Prevents clickjacking by controlling if the site can be rendered inside a <frame> or <iframe>.",
        "remediation": "X-Frame-Options: DENY (or SAMEORIGIN, or CSP frame-ancestors)",
        "owasp": OWASP_A05,
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "name": "X-Content-Type-Options (MIME Sniffing)",
        "description": "Prevents MIME-type confusion attacks by forcing browsers to honor declared Content-Type.",
        "remediation": "X-Content-Type-Options: nosniff",
        "owasp": OWASP_A05,
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "name": "Referrer-Policy",
        "description": "Controls how much sensitive referrer information (e.g. tokens in URLs) is sent in requests.",
        "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
        "owasp": OWASP_A05,
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "name": "Permissions-Policy",
        "description": "Restricts browser features and APIs (camera, microphone, geolocation) accessible to the origin.",
        "remediation": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "owasp": OWASP_A05,
    },
}

INFORMATION_LEAK_HEADERS = {
    "Server": {
        "name": "Server Software Version Disclosure",
        "description": "Discloses server software and version numbers, aiding targeted vulnerability research.",
        "remediation": "Disable detailed banner in web server (e.g., Apache 'ServerTokens Prod', Nginx 'server_tokens off').",
    },
    "X-Powered-By": {
        "name": "Backend Technology Disclosure (X-Powered-By)",
        "description": "Reveals framework, language, or CMS runtime (e.g., PHP, Express, ASP.NET).",
        "remediation": "Remove header via runtime config (e.g., php.ini: expose_php = Off, app.disable('x-powered-by')).",
    },
    "X-AspNet-Version": {
        "name": "ASP.NET Version Disclosure",
        "description": "Exposes Microsoft ASP.NET framework version.",
        "remediation": "Add <httpRuntime enableVersionHeader=\"false\" /> to web.config.",
    },
    "X-AspNetMvc-Version": {
        "name": "ASP.NET MVC Version Disclosure",
        "description": "Exposes Microsoft ASP.NET MVC architecture version.",
        "remediation": "Set MvcHandler.DisableMvcResponseHeader = true in Application_Start.",
    },
}


# =============================================================================
# Core Security Audit Engine
# =============================================================================
class SecurityAuditEngine:
    """Encapsulates all passive and active security header / CORS tests."""

    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "AutomatedWebScanner/1.0 (+https://github.com/security/web-scanner; "
            "Educational Cybersecurity Audit Tool)"
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def audit_target(self, target_url: str) -> Dict[str, Any]:
        """
        Execute full security assessment on a target URL.
        
        Returns a structured dictionary containing all metadata, findings,
        scores, and raw technical evidence.
        """
        # Normalize URL scheme
        if not re.match(r"^https?://", target_url, re.IGNORECASE):
            target_url = "https://" + target_url

        start_time = time.time()
        findings: List[Dict[str, Any]] = []
        parsed_url = urllib.parse.urlparse(target_url)
        hostname = parsed_url.hostname or ""

        # Resolve IP address
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = "Unable to resolve"

        # ---------------------------------------------------------
        # 1. Fetch Primary HTTP/HTTPS Response
        # ---------------------------------------------------------
        ssl_failed = False
        ssl_error_msg = ""
        response = None
        used_verify = True

        try:
            response = self.session.get(
                target_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
        except requests.exceptions.SSLError as ssl_err:
            ssl_failed = True
            ssl_error_msg = str(ssl_err)
            # Fallback to verify=False so we can still audit headers and cookies
            try:
                response = self.session.get(
                    target_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                used_verify = False
            except Exception as e:
                return self._create_error_result(target_url, f"SSL Error & Connection Failure: {e}", start_time)
        except requests.exceptions.ConnectTimeout:
            return self._create_error_result(
                target_url,
                f"Connection timed out after {self.timeout}s while connecting to {target_url}",
                start_time,
            )
        except requests.exceptions.ConnectionError as conn_err:
            return self._create_error_result(
                target_url,
                f"Failed to establish a network connection: {conn_err}",
                start_time,
            )
        except requests.exceptions.RequestException as req_err:
            return self._create_error_result(
                target_url,
                f"HTTP Request failed: {req_err}",
                start_time,
            )

        elapsed_ms = (time.time() - start_time) * 1000
        final_url = response.url
        headers = response.headers

        # ---------------------------------------------------------
        # 2. HTTPS & Transport Security Audit
        # ---------------------------------------------------------
        https_findings = self._check_https_security(target_url, final_url, ssl_failed, ssl_error_msg)
        findings.extend(https_findings)

        # ---------------------------------------------------------
        # 3. Security Headers Audit
        # ---------------------------------------------------------
        header_findings = self._check_security_headers(headers, final_url)
        findings.extend(header_findings)

        # ---------------------------------------------------------
        # 4. Information Leakage Audit
        # ---------------------------------------------------------
        leak_findings = self._check_information_leakage(headers)
        findings.extend(leak_findings)

        # ---------------------------------------------------------
        # 5. Cookie Security Audit
        # ---------------------------------------------------------
        cookie_findings = self._check_cookies(response)
        findings.extend(cookie_findings)

        # ---------------------------------------------------------
        # 6. Active CORS Misconfiguration Testing
        # ---------------------------------------------------------
        cors_findings, cors_tests = self._check_cors(final_url)
        findings.extend(cors_findings)

        # ---------------------------------------------------------
        # 7. Scoring & Grade Calculation
        # ---------------------------------------------------------
        score, grade = self._calculate_score(findings)

        # Sort findings by severity order: HIGH -> MEDIUM -> LOW -> INFO
        severity_weight = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        findings.sort(key=lambda x: severity_weight.get(x.get("severity", "LOW"), 99))

        return {
            "target_url": target_url,
            "final_url": final_url,
            "status_code": response.status_code,
            "response_time_ms": elapsed_ms,
            "ip_address": ip_address,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "score": score,
            "grade": grade,
            "findings": findings,
            "headers": dict(headers),
            "cors_tests": cors_tests,
            "error": None,
        }

    # -------------------------------------------------------------------------
    # Check 1: HTTPS & Transport Enforcement
    # -------------------------------------------------------------------------
    def _check_https_security(
        self,
        initial_url: str,
        final_url: str,
        ssl_failed: bool,
        ssl_error_msg: str,
    ) -> List[Dict[str, Any]]:
        """Verify HTTPS usage, redirection, and valid SSL/TLS certificates."""
        findings = []

        # Check SSL certificate validity
        if ssl_failed:
            findings.append({
                "severity": "HIGH",
                "category": "Transport Security",
                "title": "Invalid or Untrusted TLS/SSL Certificate",
                "description": "The target's TLS certificate failed verification (e.g., self-signed, expired, or hostname mismatch).",
                "evidence": f"Certificate Validation Error: {ssl_error_msg}",
                "remediation": "Install a valid, non-expired TLS certificate from a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert).",
                "owasp_ref": OWASP_A05,
            })

        # Check if the site serves traffic unencrypted or fails to enforce HTTPS
        if final_url.lower().startswith("http://"):
            findings.append({
                "severity": "HIGH",
                "category": "Transport Security",
                "title": "Insecure Transport Protocol (Plaintext HTTP)",
                "description": "The site serves unencrypted HTTP traffic without redirecting to HTTPS, exposing data to MITM interception.",
                "evidence": f"Final destination reached via plaintext HTTP: {final_url}",
                "remediation": "Enforce HTTPS by issuing a 301 Permanent Redirect from HTTP (port 80) to HTTPS (port 443).",
                "owasp_ref": OWASP_A05,
            })
        elif initial_url.lower().startswith("http://") and final_url.lower().startswith("https://"):
            # Redirected properly to HTTPS (positive condition)
            pass

        return findings

    # -------------------------------------------------------------------------
    # Check 2: Missing HTTP Security Headers
    # -------------------------------------------------------------------------
    def _check_security_headers(self, headers: Dict[str, str], final_url: str) -> List[Dict[str, Any]]:
        """Audit for presence and configuration of modern security headers."""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, spec in SECURITY_HEADERS_DEF.items():
            h_key = header_name.lower()
            if h_key not in headers_lower:
                # Note: HSTS only applies when served over HTTPS
                if header_name == "Strict-Transport-Security" and not final_url.startswith("https://"):
                    continue

                findings.append({
                    "severity": spec["severity"],
                    "category": "Security Headers",
                    "title": f"Missing {spec['name']}",
                    "description": spec["description"],
                    "evidence": "Header not present in HTTP response",
                    "remediation": spec["remediation"],
                    "owasp_ref": spec["owasp"],
                })
            else:
                value = headers_lower[h_key]
                # Additional deep inspections for existing headers
                if header_name == "X-Content-Type-Options" and "nosniff" not in value.lower():
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Security Headers",
                        "title": "Invalid X-Content-Type-Options Header Value",
                        "description": "The header must be explicitly set to 'nosniff' to disable MIME sniffing.",
                        "evidence": f"Observed value: '{value}'",
                        "remediation": "X-Content-Type-Options: nosniff",
                        "owasp_ref": OWASP_A05,
                    })
                elif header_name == "Strict-Transport-Security":
                    # Check for short max-age (< 120 days = 10368000s)
                    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
                    if match:
                        max_age = int(match.group(1))
                        if max_age < 10368000:
                            findings.append({
                                "severity": "LOW",
                                "category": "Security Headers",
                                "title": "Suboptimal HSTS max-age Duration",
                                "description": f"HSTS max-age is set to {max_age}s, which is below the recommended 1 year (31536000s).",
                                "evidence": f"Observed HSTS: '{value}'",
                                "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                                "owasp_ref": OWASP_A05,
                            })
                elif header_name == "Referrer-Policy":
                    insecure_policies = ["unsafe-url", "no-referrer-when-downgrade"]
                    if any(pol in value.lower() for pol in insecure_policies):
                        findings.append({
                            "severity": "LOW",
                            "category": "Security Headers",
                            "title": "Insecure Referrer-Policy Configuration",
                            "description": f"The policy '{value}' may leak full URL parameters and path data to third-party domains.",
                            "evidence": f"Observed Referrer-Policy: '{value}'",
                            "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
                            "owasp_ref": OWASP_A05,
                        })

        return findings

    # -------------------------------------------------------------------------
    # Check 3: Information Leakage Headers
    # -------------------------------------------------------------------------
    def _check_information_leakage(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Identify headers that disclose server, OS, or technology versions."""
        findings = []
        headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

        for leak_header, spec in INFORMATION_LEAK_HEADERS.items():
            l_key = leak_header.lower()
            if l_key in headers_lower:
                orig_key, value = headers_lower[l_key]
                findings.append({
                    "severity": "LOW",
                    "category": "Information Leakage",
                    "title": spec["name"],
                    "description": spec["description"],
                    "evidence": f"{orig_key}: {value}",
                    "remediation": spec["remediation"],
                    "owasp_ref": OWASP_A05,
                })

        return findings

    # -------------------------------------------------------------------------
    # Check 4: Cookie Security Audit
    # -------------------------------------------------------------------------
    def _check_cookies(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Verify whether cookies implement Secure and HttpOnly defense flags."""
        findings = []
        cookies_audited = set()

        # Method A: Inspect via RequestsCookieJar
        for cookie in response.cookies:
            cookie_name = cookie.name
            cookies_audited.add(cookie_name)
            
            is_secure = cookie.secure
            is_httponly = (
                cookie.has_nonstandard_attr("httponly")
                or "httponly" in [k.lower() for k in getattr(cookie, "_rest", {}).keys()]
            )

            if not is_secure:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Cookie Security",
                    "title": f"Cookie Missing 'Secure' Flag ({cookie_name})",
                    "description": "Cookies without the 'Secure' attribute can be transmitted over unencrypted HTTP channels.",
                    "evidence": f"Cookie '{cookie_name}' lacks Secure flag",
                    "remediation": f"Set-Cookie: {cookie_name}=<value>; Secure; HttpOnly; SameSite=Lax",
                    "owasp_ref": OWASP_A05,
                })

            if not is_httponly:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Cookie Security",
                    "title": f"Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                    "description": "Cookies without 'HttpOnly' can be accessed by client-side JavaScript, increasing XSS session theft risk.",
                    "evidence": f"Cookie '{cookie_name}' lacks HttpOnly flag",
                    "remediation": f"Set-Cookie: {cookie_name}=<value>; Secure; HttpOnly; SameSite=Lax",
                    "owasp_ref": OWASP_A05,
                })

        # Method B: Parse raw Set-Cookie headers for unparsed attributes
        raw_set_cookies = []
        if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
            raw_set_cookies = response.raw.headers.getlist("Set-Cookie")
        elif "Set-Cookie" in response.headers:
            raw_set_cookies = [response.headers["Set-Cookie"]]

        for raw_cookie in raw_set_cookies:
            # Extract name
            match = re.match(r"^\s*([^=;]+)=", raw_cookie)
            if not match:
                continue
            c_name = match.group(1).strip()
            if c_name in cookies_audited:
                continue  # Already audited via CookieJar
            
            cookies_audited.add(c_name)
            cookie_lower = raw_cookie.lower()

            if "; secure" not in cookie_lower and not cookie_lower.endswith("secure"):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Cookie Security",
                    "title": f"Cookie Missing 'Secure' Flag ({c_name})",
                    "description": "Cookies without the 'Secure' attribute can be intercepted in transit over unencrypted connections.",
                    "evidence": f"Raw header: {raw_cookie}",
                    "remediation": f"Set-Cookie: {c_name}=<value>; Secure; HttpOnly; SameSite=Lax",
                    "owasp_ref": OWASP_A05,
                })

            if "; httponly" not in cookie_lower and not cookie_lower.endswith("httponly"):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Cookie Security",
                    "title": f"Cookie Missing 'HttpOnly' Flag ({c_name})",
                    "description": "Cookies without 'HttpOnly' can be stolen via XSS document.cookie manipulation.",
                    "evidence": f"Raw header: {raw_cookie}",
                    "remediation": f"Set-Cookie: {c_name}=<value>; Secure; HttpOnly; SameSite=Lax",
                    "owasp_ref": OWASP_A05,
                })

        return findings

    # -------------------------------------------------------------------------
    # Check 5: CORS Misconfiguration Testing
    # -------------------------------------------------------------------------
    def _check_cors(self, url: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Probe CORS configuration with arbitrary origins:
          1. Origin: https://evil.example.com
          2. Origin: null
        """
        findings = []
        cors_tests = []
        test_origins = [
            ("https://evil.example.com", "Arbitrary Untrusted Domain"),
            ("null", "Null Origin (Sandboxed iframe / local origin)"),
        ]

        for test_origin, label in test_origins:
            req_headers = {
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET",
            }
            try:
                # Perform probe request with test Origin
                res = self.session.get(
                    url,
                    headers=req_headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                
                acao = res.headers.get("Access-Control-Allow-Origin")
                acac = res.headers.get("Access-Control-Allow-Credentials", "false").lower()

                cors_tests.append({
                    "test_origin": test_origin,
                    "label": label,
                    "acao": acao,
                    "acac": acac,
                    "status_code": res.status_code,
                })

                if not acao:
                    continue

                # Scenario (a): Wildcard * with Credentials enabled
                if acao == "*" and acac == "true":
                    findings.append({
                        "severity": "HIGH",
                        "category": "CORS Misconfiguration",
                        "title": "CORS Wildcard with Credentials Enabled",
                        "description": "The server specifies Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true, exposing authenticated user sessions to cross-origin abuse.",
                        "evidence": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: {acac}",
                        "remediation": "Do not specify wildcard '*' when credentials are required. Explicitly whitelist trusted origins.",
                        "owasp_ref": OWASP_A05,
                    })

                # Scenario (b): Arbitrary Origin Reflected
                elif acao == test_origin:
                    if acac == "true":
                        findings.append({
                            "severity": "HIGH",
                            "category": "CORS Misconfiguration",
                            "title": f"CORS Reflected Origin with Credentials Allowed ({test_origin})",
                            "description": f"The application reflects arbitrary origin '{test_origin}' and permits credentials, allowing malicious domains to exfiltrate private user sessions.",
                            "evidence": f"Injected Origin: {test_origin} -> Reflected ACAO: {acao} (Credentials: true)",
                            "remediation": "Avoid reflecting the incoming Origin header. Implement a strict server-side origin whitelist.",
                            "owasp_ref": OWASP_A05,
                        })
                    else:
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "CORS Misconfiguration",
                            "title": f"CORS Reflected Origin without Credentials ({test_origin})",
                            "description": f"The application dynamically reflects arbitrary origin '{test_origin}' into Access-Control-Allow-Origin.",
                            "evidence": f"Injected Origin: {test_origin} -> Reflected ACAO: {acao}",
                            "remediation": "Implement an explicit whitelist of authorized domains rather than reflecting arbitrary origins.",
                            "owasp_ref": OWASP_A05,
                        })

                # Scenario (c): Plain Wildcard
                elif acao == "*":
                    # Only add once to avoid duplicate findings across multiple test origins
                    if not any(f["title"] == "CORS Overly Permissive Wildcard Origin" for f in findings):
                        findings.append({
                            "severity": "LOW",
                            "category": "CORS Misconfiguration",
                            "title": "CORS Overly Permissive Wildcard Origin",
                            "description": "The resource permits public cross-origin reads from any origin. If this endpoint handles private or sensitive data, this is insecure.",
                            "evidence": "Access-Control-Allow-Origin: *",
                            "remediation": "If the resource is public/static, wildcard is acceptable. For sensitive resources, replace with explicit origin checks.",
                            "owasp_ref": OWASP_A05,
                        })

            except Exception as e:
                cors_tests.append({
                    "test_origin": test_origin,
                    "label": label,
                    "error": str(e),
                })

        return findings, cors_tests

    # -------------------------------------------------------------------------
    # Scoring Algorithm
    # -------------------------------------------------------------------------
    def _calculate_score(self, findings: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Deduction Rubric:
          - Base: 100
          - Subtract 20 per HIGH
          - Subtract 10 per MEDIUM
          - Subtract 5 per LOW
          - Minimum: 0
        
        Grade mapping:
          90-100: A
          80-89:  B
          70-79:  C
          60-69:  D
          0-59:   F
        """
        score = 100
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev == "HIGH":
                score -= 20
            elif sev == "MEDIUM":
                score -= 10
            elif sev == "LOW":
                score -= 5

        score = max(0, score)

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _create_error_result(self, url: str, error_msg: str, start_time: float) -> Dict[str, Any]:
        """Construct an error record when target host is unreachable."""
        return {
            "target_url": url,
            "final_url": url,
            "status_code": None,
            "response_time_ms": (time.time() - start_time) * 1000,
            "ip_address": None,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "score": 0,
            "grade": "F",
            "findings": [],
            "headers": {},
            "cors_tests": [],
            "error": error_msg,
        }


# =============================================================================
# Terminal UI & Formatting
# =============================================================================
def print_banner(use_color: bool = True) -> None:
    """Print cybersecurity tool header and legal disclaimer banner."""
    banner = r"""
    ___         __                        __           _       __      __       _____                                 
   /   | __  __/ /_____  ____ ___  ____ _/ /____  ____| |     / /___  / /_     / ___/_________ _____  ____  ___  _____
  / /| |/ / / / __/ __ \/ __ `__ \/ __ `/ __/ _ \/ __  / | /| / / _ \/ __ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ / /_/ / /_/ /_/ / / / / / / /_/ / /_/  __/ /_/ /| |/ |/ /  __/ /_/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/  |_\__,_/\__/\____/_/ /_/ /_/\__,_/\__/\___/\__,_/ |__/|__/\___/_.___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
    """
    print(colorize(banner, Colors.CYAN, use_color))
    print(colorize(" Automated Web Scanner - Security Headers, CORS & Transport Audit Tool", Colors.BOLD, use_color))
    print(colorize(" OWASP Benchmark: A05:2021 (Security Misconfiguration)", Colors.GRAY, use_color))
    print(colorize("-" * 88, Colors.GRAY, use_color))
    print(colorize(" [!] LEGAL DISCLAIMER: Scan only systems you own or have explicit authorization to test.", Colors.YELLOW, use_color))
    print(colorize("-" * 88, Colors.GRAY, use_color))
    print()


def format_cell(text: str, width: int, color: str = "", use_color: bool = True) -> str:
    """Pad text to target width based on visible characters, then apply color."""
    padded = text.ljust(width)
    if color and use_color:
        return f"{color}{padded}{Colors.RESET}"
    return padded


def print_target_report(result: Dict[str, Any], use_color: bool = True) -> None:
    """Format and print target findings to terminal with ANSI colors."""
    url = result["target_url"]
    error = result.get("error")

    if error:
        print(colorize(f"Target: {url}", Colors.BOLD, use_color))
        print(colorize(f"  [ERROR] Connection failed: {error}", Colors.RED, use_color))
        print(colorize("-" * 88, Colors.GRAY, use_color))
        print()
        return

    score = result["score"]
    grade = result["grade"]
    status_code = result["status_code"]
    latency = f"{result['response_time_ms']:.0f}ms"
    findings = result.get("findings", [])

    # Grade coloring
    grade_color = Colors.GREEN if grade == "A" else (
        Colors.CYAN if grade == "B" else (
            Colors.YELLOW if grade == "C" else Colors.RED
        )
    )

    print(colorize(f"[*] Target Audit: {url}", Colors.BOLD, use_color))
    print(
        f"    Final URL: {colorize(result['final_url'], Colors.CYAN, use_color)} | "
        f"Status: {colorize(str(status_code), Colors.GREEN, use_color)} | "
        f"Latency: {latency} | "
        f"IP: {result.get('ip_address', 'N/A')}"
    )
    print(
        f"    Score: {colorize(f'{score}/100', Colors.BOLD, use_color)} | "
        f"Grade: {colorize(f'[{grade}]', grade_color + Colors.BOLD, use_color)} | "
        f"Total Findings: {len(findings)}"
    )
    print()

    if not findings:
        print(colorize("    [+] No security misconfigurations identified! Excellent posture.", Colors.GREEN, use_color))
        print(colorize("-" * 88, Colors.GRAY, use_color))
        print()
        return

    # Print Findings Table Header
    print(f"    {'SEVERITY':<11} {'CATEGORY':<22} {'ISSUE / EVIDENCE':<50}")
    print(colorize("    " + "-" * 84, Colors.GRAY, use_color))

    for f in findings:
        sev = f["severity"]
        cat = f["category"]
        title = f["title"]
        evidence = f["evidence"]

        if sev == "HIGH":
            sev_badge = format_cell(f"[{sev}]", 11, Colors.RED + Colors.BOLD, use_color)
        elif sev == "MEDIUM":
            sev_badge = format_cell(f"[{sev}]", 11, Colors.YELLOW + Colors.BOLD, use_color)
        elif sev == "LOW":
            sev_badge = format_cell(f"[{sev}]", 11, Colors.BLUE, use_color)
        else:
            sev_badge = format_cell(f"[{sev}]", 11, Colors.GRAY, use_color)

        cat_cell = format_cell(cat, 22, Colors.WHITE, use_color)
        print(f"    {sev_badge} {cat_cell} {title}")
        print(colorize(f"      Evidence:   {evidence}", Colors.DIM, use_color))
        print(colorize(f"      How to Fix: {f['remediation']}", Colors.GREEN, use_color))
        print()

    print(colorize("-" * 88, Colors.GRAY, use_color))
    print()


def print_overall_summary(results: List[Dict[str, Any]], use_color: bool = True) -> None:
    """Print executive terminal summary table across all audited targets."""
    print(colorize("=" * 88, Colors.CYAN, use_color))
    print(colorize(" MULTI-TARGET EXECUTIVE AUDIT SUMMARY", Colors.BOLD, use_color))
    print(colorize("=" * 88, Colors.CYAN, use_color))
    print(f" {'#':<3} {'TARGET URL':<36} {'STATUS':<8} {'SCORE':<10} {'GRADE':<8} {'HIGH':<6} {'MED':<6} {'LOW':<6}")
    print(colorize("-" * 88, Colors.GRAY, use_color))

    for idx, r in enumerate(results, start=1):
        url = r["target_url"]
        if len(url) > 34:
            url = url[:31] + "..."

        if r.get("error"):
            status_cell = format_cell("ERROR", 8, Colors.RED, use_color)
            print(f" {idx:<3} {url:<36} {status_cell} {'—':<10} {'ERR':<8} {'—':<6} {'—':<6} {'—':<6}")
        else:
            status = str(r["status_code"])
            score_str = f"{r['score']}/100"
            grade = r["grade"]
            grade_color = Colors.GREEN if grade == "A" else (
                Colors.CYAN if grade == "B" else (
                    Colors.YELLOW if grade == "C" else Colors.RED
                )
            )
            findings = r.get("findings", [])
            high = sum(1 for f in findings if f["severity"] == "HIGH")
            med = sum(1 for f in findings if f["severity"] == "MEDIUM")
            low = sum(1 for f in findings if f["severity"] == "LOW")

            grade_cell = format_cell(f"[{grade}]", 8, grade_color + Colors.BOLD, use_color)
            print(f" {idx:<3} {url:<36} {status:<8} {score_str:<10} {grade_cell} {high:<6} {med:<6} {low:<6}")

    print(colorize("-" * 88, Colors.GRAY, use_color))
    print()


# =============================================================================
# CLI Main Guard & Argument Parser
# =============================================================================
def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="Automated Web Scanner - Security Headers & CORS Misconfiguration Auditor",
        epilog="Example: python scanner.py https://example.com http://testphp.vulnweb.com --html report.html --json report.json",
    )
    parser.add_argument(
        "urls",
        nargs="*",
        default=[],
        help="One or more target URLs to scan (e.g., https://example.com http://testphp.vulnweb.com)",
    )
    parser.add_argument(
        "--serve",
        "--web",
        action="store_true",
        help="Launch interactive web browser application with URL input box",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind interactive web GUI (default: 5000)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        dest="json_file",
        help="Save complete audit results as structured JSON to specified file path",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        dest="html_file",
        help="Generate clean, executive HTML vulnerability report with remediation table",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP connection and read timeout in seconds (default: 10s)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in terminal",
    )

    return parser.parse_args()


def main() -> None:
    """Main execution entrypoint for Automated Web Scanner."""
    enable_windows_ansi()
    args = parse_arguments()
    use_color = not args.no_color

    print_banner(use_color)

    # Launch interactive Web GUI if --serve is requested or no URLs provided
    if args.serve or not args.urls:
        print(colorize("[*] Starting interactive Web GUI console with live input box...", Colors.CYAN, use_color))
        from app import start_server
        start_server(port=args.port, auto_open=True)
        return

    engine = SecurityAuditEngine(timeout=args.timeout)
    scan_results: List[Dict[str, Any]] = []

    print(colorize(f"[*] Commencing automated security audit against {len(args.urls)} target(s)...", Colors.BOLD, use_color))
    print(colorize(f"[*] Connection Timeout: {args.timeout}s\n", Colors.GRAY, use_color))

    for target in args.urls:
        print(colorize(f"[>] Auditing target: {target} ...", Colors.CYAN, use_color))
        result = engine.audit_target(target)
        scan_results.append(result)
        print_target_report(result, use_color)

    # Print Multi-target Summary if multiple URLs audited
    if len(scan_results) > 1:
        print_overall_summary(scan_results, use_color)

    # Handle JSON Export
    if args.json_file:
        try:
            with open(args.json_file, "w", encoding="utf-8") as jf:
                json.dump(scan_results, jf, indent=2)
            print(colorize(f"[+] JSON report successfully exported to: {args.json_file}", Colors.GREEN + Colors.BOLD, use_color))
        except Exception as e:
            print(colorize(f"[!] Failed to write JSON report: {e}", Colors.RED, use_color))

    # Handle HTML Export
    if args.html_file:
        try:
            generate_html_report(scan_results, args.html_file)
            print(colorize(f"[+] Executive HTML report successfully generated: {args.html_file}", Colors.GREEN + Colors.BOLD, use_color))
        except Exception as e:
            print(colorize(f"[!] Failed to write HTML report: {e}", Colors.RED, use_color))

    print(colorize("\n[+] Security audit completed.", Colors.BOLD, use_color))


if __name__ == "__main__":
    main()
