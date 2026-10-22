# 🛡️ Automated Web Scanner: Security Headers & CORS Misconfiguration Auditor

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP Benchmark](https://img.shields.io/badge/OWASP-A05%3A2021--Security%20Misconfiguration-red.svg)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
[![Dependencies](https://img.shields.io/badge/Dependencies-requests-orange.svg)](requirements.txt)

A lightweight, enterprise-grade command-line security auditing tool developed in Python. **Automated Web Scanner** performs rapid, non-invasive vulnerability assessments of web endpoints to uncover missing HTTP security headers, CORS flaws, cookie weaknesses, transport layer flaws, and server information disclosures.

---

## 📑 Table of Contents

- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [Architecture & Project Structure](#-architecture--project-structure)
- [Mapping to OWASP Top 10](#-mapping-to-owasp-top-10)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [How Each Check Works](#-how-each-check-works)
  - [1. Transport Security (HTTPS)](#1-transport-security-https)
  - [2. Modern Security Headers](#2-modern-security-headers)
  - [3. Information Leakage](#3-information-leakage)
  - [4. Cookie Flag Audit](#4-cookie-flag-audit)
  - [5. Cross-Origin Resource Sharing (CORS) Probing](#5-cross-origin-resource-sharing-cors-probing)
  - [6. Security Posture Scoring Engine](#6-security-posture-scoring-engine)
- [Sample Terminal Output](#-sample-terminal-output)
- [HTML Report Demonstration](#-html-report-demonstration)
- [Legal & Ethical Disclaimer](#-legal--ethical-disclaimer)
- [Future Improvements & Roadmap](#-future-improvements--roadmap)

---

## 🔍 Project Overview

According to Verizon's Data Breach Investigations Report (DBIR) and OWASP findings, **misconfigured web servers and missing defense-in-depth headers** remain one of the most widespread attack vectors on the modern Internet. Modern browsers come equipped with powerful security mechanisms (such as Content Security Policy, strict origin isolation, HSTS, and frame protections), but they rely entirely on the web server transmitting explicit HTTP instructions.

**Automated Web Scanner** bridges the gap between manual header inspection and heavy commercial DAST tools. It evaluates endpoints against defensive benchmarks, computes an objective letter grade (`A` through `F`) based on a standardized deduction rubric, and exports both machine-readable JSON and publication-ready executive HTML reports with actionable remediation instructions for system administrators.

---

## ⚡ Key Features

- **Zero-Bloat Dependency Model:** Built strictly with Python standard library and `requests`. No bulky browser engines or Node.js runtime needed.
- **Robust Transport Layer Auditing:** Identifies plaintext HTTP exposure, missing 301/308 HTTPS redirects, and untrusted TLS certificates.
- **Defensive Header Inspection:** Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Active CORS Probing:** Injects untrusted origins (`https://evil.example.com`, `null`) to detect credential leaks and arbitrary origin reflection.
- **Cookie Security Verification:** Identifies session cookies missing `Secure` and `HttpOnly` attributes.
- **Server Information Disclosure:** Flags server banner grabbing (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Scoring Engine:** 100-point rubric with tiered deductions (High: -20, Medium: -10, Low: -5) producing a standardized letter grade.
- **Multi-Format Reporting:** High-contrast ANSI terminal visualization, machine-parsable JSON, and an executive dark-themed HTML report.

---

## 📂 Architecture & Project Structure

```
web-scanner/
├── scanner.py          # Main CLI application, audit engine & argument parser
├── report_generator.py # Executive HTML vulnerability report generator (embedded CSS/JS)
├── requirements.txt    # Project runtime dependencies (requests >= 2.31.0)
└── README.md           # Comprehensive technical documentation & project guide
```

---

## 🛡️ Mapping to OWASP Top 10

### **A05:2021 – Security Misconfiguration**
This scanner is directly mapped to **OWASP Top 10 Category A05:2021 (Security Misconfiguration)**. Specifically:
- **Lack of Security Hardening:** Failing to implement modern defensive headers (`CSP`, `HSTS`, `X-Content-Type-Options`) leaves applications vulnerable to Cross-Site Scripting (XSS), Clickjacking, and MIME-sniffing exploits.
- **Overly Permissive Cross-Domain Policies:** Wildcard or dynamic CORS reflections with `Access-Control-Allow-Credentials: true` permit unauthorized third-party sites to steal sensitive data via authenticated browser sessions.
- **Default & Verbose Server Banners:** Exposing server software versions (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`) accelerates attacker reconnaissance and zero-day exploitation.
- **Insecure Cookie Directives:** Cookies sent without `Secure` can be intercepted across unencrypted links; cookies without `HttpOnly` can be stolen via DOM access in an XSS payload.

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher installed on your system.
- `pip` package manager.

### 1. Clone or Navigate to Project
```bash
cd "c:\Users\Lenovo\OneDrive\Desktop\cyber security ibm project\web-scanner"
```

### 2. Install Required Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Usage Examples

### 🌐 Option A: Interactive Web Application (Live URL Input)
Launch the interactive web console in your browser where you can enter any website URL, view live scan progress, and inspect interactive findings:
```bash
python app.py
```
*(or run `python scanner.py --serve`)*

Then open your browser at **`http://127.0.0.1:5000`**. You can enter any website URL into the input field, hit **"Audit Website"**, and immediately inspect findings, filter by severity, and export results!

---

### 🖥️ Option B: Command-Line Interface (CLI Mode)

#### 1. Basic Single-Target Scan
```bash
python scanner.py https://example.com
```

#### 2. Multi-Target Assessment
Scan multiple targets sequentially with an executive terminal summary:
```bash
python scanner.py https://example.com http://testphp.vulnweb.com
```

#### 3. Full Audit with HTML and JSON Export
Generate both structured JSON output for automated CI/CD pipelines and a styled HTML report for stakeholders:
```bash
python scanner.py https://example.com http://testphp.vulnweb.com --html report.html --json report.json
```

#### 4. Custom Timeout & Disabling Terminal Colors
```bash
python scanner.py https://example.com --timeout 5 --no-color
```

### CLI Flag Reference
| Flag | Type | Default | Description |
|---|---|---|---|
| `urls` | Positional | Optional | One or more space-separated target URLs |
| `--serve`, `--web` | Flag | False | Launches interactive web browser console with URL input field |
| `--port <int>` | Optional | `5000` | Port for local interactive web app |
| `--html <file>` | Optional | None | Exports executive HTML audit report to `<file>` |
| `--json <file>` | Optional | None | Exports detailed JSON scan results to `<file>` |
| `--timeout <sec>` | Optional | `10` | Maximum network connection and read timeout |
| `--no-color` | Optional | False | Disables ANSI color escapes (useful for raw logging) |

---

## 🔬 How Each Check Works

### 1. Transport Security (HTTPS)
- **Check Mechanism:** Inspects both the requested URL and the final destination URL following HTTP redirects (`allow_redirects=True`).
- **Severity:** `[HIGH]`
- **Threat Vector:** Plaintext HTTP communicates over unencrypted TCP sockets. Eavesdroppers on the same network (e.g. public Wi-Fi) can sniff credentials and session tokens or alter webpage content in-flight.
- **Remediation:** Enforce 301 Permanent Redirects on port 80 to port 443 with TLS 1.2/1.3.

### 2. Modern Security Headers
The scanner checks for presence, valid syntax, and secure directive configurations:

| Header Name | Severity | Risk Mitigated | Optimal Header Value |
|---|---|---|---|
| **Strict-Transport-Security** | `HIGH` | Man-in-the-Middle, SSL Stripping | `max-age=31536000; includeSubDomains; preload` |
| **Content-Security-Policy** | `HIGH` | XSS, Data Injection, Clickjacking | `default-src 'self'; script-src 'self'; object-src 'none';` |
| **X-Frame-Options** | `MEDIUM` | Clickjacking / UI Redressing | `DENY` or `SAMEORIGIN` |
| **X-Content-Type-Options** | `MEDIUM` | MIME-confusion / Drive-by downloads | `nosniff` |
| **Referrer-Policy** | `LOW` | Credential/token leakage in URLs | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | `LOW` | Unauthorized hardware API access | `camera=(), microphone=(), geolocation=()` |

### 3. Information Leakage
- **Check Mechanism:** Inspects response headers for software identifiers: `Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-AspNetMvc-Version`.
- **Severity:** `[LOW]`
- **Threat Vector:** Disclosing precise framework and web server versions assists malicious actors in identifying applicable CVEs.
- **Remediation:** In Apache, set `ServerTokens Prod`; in Nginx, configure `server_tokens off;`; in PHP, configure `expose_php = Off`.

### 4. Cookie Flag Audit
- **Check Mechanism:** Inspects all cookies received in the response (via `RequestsCookieJar` and raw `Set-Cookie` headers) for `Secure` and `HttpOnly` attributes.
- **Severity:** `[MEDIUM]` per missing attribute.
- **Threat Vector:** Cookies without `Secure` are transmitted in plaintext over HTTP. Cookies without `HttpOnly` can be stolen by malicious JavaScript via `document.cookie` during an XSS attack.
- **Remediation:** Always append `; Secure; HttpOnly; SameSite=Lax` to sensitive session cookies.

### 5. Cross-Origin Resource Sharing (CORS) Probing
- **Check Mechanism:** Issues active HTTP probe requests containing untrusted `Origin` headers:
  1. `Origin: https://evil.example.com` (untrusted third party)
  2. `Origin: null` (sandboxed or local file contexts)
- **Vulnerabilities Evaluated:**
  - **Wildcard with Credentials `[HIGH]`:** `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
  - **Reflected Arbitrary Origin with Credentials `[HIGH]`:** Dynamically reflecting the attacker origin and permitting credentials allows arbitrary websites to exfiltrate private user records.
  - **Reflected Arbitrary Origin without Credentials `[MEDIUM]`:** Origin is mirrored blindly.
  - **Overly Permissive Wildcard `[LOW]`:** Endpoint allows public cross-origin reading.

### 6. Security Posture Scoring Engine
- **Base Score:** 100 points
- **Deductions:**
  - `-20 points` for each `HIGH` severity finding
  - `-10 points` for each `MEDIUM` severity finding
  - `-5 points` for each `LOW` severity finding
- **Floor:** Scores are clamped to a minimum of 0 points.
- **Academic Grading Scale:**
  - `90 – 100`: **Grade A** (Superior defensive configuration)
  - `80 – 89`:  **Grade B** (Good posture, minor improvements required)
  - `70 – 79`:  **Grade C** (Moderate posture, missing basic defense-in-depth)
  - `60 – 69`:  **Grade D** (Poor posture, critical vulnerabilities present)
  - `0 – 59`:   **Grade F** (Failing posture, severe security misconfigurations)

---

## 🖥️ Sample Terminal Output

```text
 █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

 Automated Web Scanner - Security Headers, CORS & Transport Audit Tool
 OWASP Benchmark: A05:2021 (Security Misconfiguration)
----------------------------------------------------------------------------------------
 [!] LEGAL DISCLAIMER: Scan only systems you own or have explicit authorization to test.
----------------------------------------------------------------------------------------

[*] Commencing automated security audit against 2 target(s)...
[*] Connection Timeout: 10s

[>] Auditing target: https://example.com ...
[*] Target Audit: https://example.com
    Final URL: https://example.com/ | Status: 200 | Latency: 215ms | IP: 93.184.215.14
    Score: 65/100 | Grade: [D] | Total Findings: 5

    SEVERITY   CATEGORY             ISSUE / EVIDENCE                                  
    ------------------------------------------------------------------------------------
    [HIGH]     Security Headers     Missing Strict-Transport-Security (HSTS)
      Evidence:   Header not present in HTTP response
      How to Fix: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

    [HIGH]     Security Headers     Missing Content-Security-Policy (CSP)
      Evidence:   Header not present in HTTP response
      How to Fix: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

    [MEDIUM]   Security Headers     Missing X-Frame-Options (Clickjacking Protection)
      Evidence:   Header not present in HTTP response
      How to Fix: X-Frame-Options: DENY (or SAMEORIGIN, or CSP frame-ancestors)

    [MEDIUM]   Security Headers     Missing X-Content-Type-Options (MIME Sniffing)
      Evidence:   Header not present in HTTP response
      How to Fix: X-Content-Type-Options: nosniff

    [LOW]      Security Headers     Missing Permissions-Policy
      Evidence:   Header not present in HTTP response
      How to Fix: Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## 📊 HTML Report Demonstration

The generated HTML report features:
- **Executive KPI Cards:** Quick summary of scanned hosts, average score, and counts of High/Medium/Low findings.
- **Executive Summary Table:** Color-coded badges for HTTP status, score, grade, and findings breakdown.
- **Interactive Severity Filters:** Easily filter vulnerabilities between High, Medium, and Low risks.
- **Detailed Finding Cards:** Clear vulnerability titles, OWASP references, observed HTTP response evidence, and copy-paste remediation directives.
- **Print & PDF Support:** Custom CSS `@media print` rules ensure clean export to PDF for audit submissions.

---

## ⚖️ Legal & Ethical Disclaimer

> **IMPORTANT:** This software is designed exclusively for educational purposes, defensive auditing, and authorized security research. 
> 
> Testing websites without prior written permission from the asset owner is illegal and violates computer fraud regulations (such as the **US Computer Fraud and Abuse Act (CFAA)**, the **UK Computer Misuse Act**, and equivalent international cybersecurity statutes). 
> 
> The author assumes no liability and is not responsible for any misuse or damage caused by this utility.

---

## 🔮 Future Improvements & Roadmap

- [ ] **TLS Cipher Suite Enumeration:** Integrate `ssl` handshake inspections to flag weak ciphers (RC4, 3DES) and obsolete TLS versions (1.0, 1.1).
- [ ] **Subdomain Brute-Forcing & Enumeration:** Automatically uncover subdomains to audit attack surface holistically.
- [ ] **API Endpoint Authentication Testing:** Check for missing `Authorization` or weak JWT signing headers on REST/GraphQL endpoints.
- [ ] **Automated CI/CD GitHub Action:** Create a turnkey GitHub Action to fail builds if security score drops below a configurable threshold (e.g., Grade `B`).
- [ ] **Dynamic CSP Validator:** Deeply parse complex CSP syntax to flag `unsafe-inline`, `unsafe-eval`, or overly broad CDN wildcards.
