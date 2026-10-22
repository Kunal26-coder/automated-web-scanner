# 🎓 ACADEMIC PROJECT REPORT

---

# **AUTOMATED WEB SCANNER**
### *An Automated Security Auditing Tool for HTTP Security Headers, CORS Policies, and Transport Layer Vulnerabilities*

**Course:** Cyber Security & Information Assurance  
**Project Category:** Defensive Application Security & Vulnerability Assessment  
**OWASP Benchmark:** Category A05:2021 – Security Misconfiguration  
**Repository:** [github.com/Kunal26-coder/automated-web-scanner](https://github.com/Kunal26-coder/automated-web-scanner)  
**Date of Submission:** October 2026  

---

## 📑 TABLE OF CONTENTS

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
   - 2.1 Background & Motivation
   - 2.2 Problem Statement
   - 2.3 Project Objectives
   - 2.4 Scope and Boundaries
3. [Theoretical Framework & Vulnerability Analysis](#3-theoretical-framework--vulnerability-analysis)
   - 3.1 HTTP Security Headers Overview
   - 3.2 Cross-Origin Resource Sharing (CORS) Security
   - 3.3 Cookie Security Directives
   - 3.4 Information Disclosure & Server Fingerprinting
   - 3.5 Mapping to OWASP Top 10 (A05:2021)
4. [System Architecture & Design](#4-system-architecture--design)
   - 4.1 Architectural Overview
   - 4.2 System Flowchart & Lifecycle
   - 4.3 Data Structures and Model Design
   - 4.4 Scoring Engine & Academic Grading Formula
5. [Implementation Details](#5-implementation-details)
   - 5.1 Technology Stack Rationale
   - 5.2 Core Scanner Engine (`scanner.py`)
   - 5.3 Executive HTML Report Generator (`report_generator.py`)
   - 5.4 Interactive Web Application (`app.py`)
   - 5.5 Resilient Network & Error Handling
6. [Experimental Results & Case Studies](#6-experimental-results--case-studies)
   - 6.1 Test Methodology
   - 6.2 Case Study 1: `https://example.com` (Production Hardening Baseline)
   - 6.3 Case Study 2: `http://testphp.vulnweb.com` (Legacy & Timeout Handling)
   - 6.4 Case Study 3: `https://httpbin.org/get` (Active CORS & Credential Testing)
7. [Ethical, Legal & Compliance Considerations](#7-ethical-legal--compliance-considerations)
8. [Conclusion & Future Roadmap](#8-conclusion--future-roadmap)
9. [References](#9-references)

---

## 1. ABSTRACT

Modern web applications are increasingly exposed to client-side and transport-layer cyber threats, including Cross-Site Scripting (XSS), Clickjacking, Man-in-the-Middle (MITM) session interception, and Cross-Origin Resource Sharing (CORS) data exfiltration. While modern web browsers possess defense-in-depth protection mechanisms, these defenses rely entirely on explicit configuration instructions provided by the web server via HTTP response headers. A significant majority of production web applications fail to configure these headers properly, introducing high-impact security misconfigurations.

This project presents **Automated Web Scanner**, a lightweight, non-invasive, dual-interface (CLI and Web GUI) vulnerability assessment tool built in Python. The system audits arbitrary web targets against rigorous security benchmarks: presence and correctness of key HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`), active CORS misconfiguration probing (wildcards with credentials, reflected origins), session cookie flags (`Secure`, `HttpOnly`), and server banner leakage. Findings are processed through an objective 100-point tiered deduction scoring engine that maps compliance to an academic grade (`A` through `F`). The application generates terminal visualizations, machine-readable JSON artifacts, and an interactive HTML report featuring remediation directives.

---

## 2. INTRODUCTION

### 2.1 Background & Motivation
The HTTP protocol was originally conceived for static document sharing across academic institutions. As web platforms evolved into sophisticated distributed software powering banking, commerce, and identity systems, security mechanisms were retrofitted into HTTP through custom and standardized header specifications.

Modern web browsers operate under the **Same-Origin Policy (SOP)**, which isolates scripts executed in one origin from accessing resources in another origin. However, developers frequently relax this boundary using Cross-Origin Resource Sharing (CORS) or neglect to instruct browsers to enforce strict HTTPS transport, frame isolation, or script execution boundaries. Consequently, attackers exploit these omissions through Clickjacking, XSS injection, and unauthorized cross-origin API invocation.

Commercial Dynamic Application Security Testing (DAST) tools (such as Burp Suite Professional, OWASP ZAP, or Acunetix) can detect these flaws, but they are resource-heavy, require complex configuration, and often depend on heavy Java or browser execution engines. There is a strong educational and operational need for a lightweight, dependency-minimal tool capable of executing rapid header and CORS audits in automated pipelines and interactive web environments.

### 2.2 Problem Statement
System administrators and developers frequently deploy applications without verifying defensive header baselines or understanding the risks of default server banners and permissive CORS rules. Specifically:
- Missing `Strict-Transport-Security` exposes users to SSL stripping attacks.
- Missing `Content-Security-Policy` leaves endpoints vulnerable to XSS and content injection.
- Missing `X-Frame-Options` enables UI redressing and Clickjacking attacks.
- Misconfigured CORS policies (e.g., reflecting `Origin: null` or untrusted domains with `Access-Control-Allow-Credentials: true`) allow third-party attackers to exfiltrate private user records.
- Cookies omitted from `Secure` and `HttpOnly` flags lead to session hijacking via network sniffing or JavaScript DOM access.

### 2.3 Project Objectives
The primary objectives of the **Automated Web Scanner** project are:
1. **Develop an Autonomous Auditing Engine:** Build a modular Python application utilizing only `requests` and the standard library to passively and actively assess web targets.
2. **Implement Multi-Vector Security Checks:** Cover transport security, six essential defensive headers, information leakage banners, cookie flags, and active CORS injection probes.
3. **Formulate an Objective Scoring Rubric:** Create a standardized 100-point deduction algorithm that grades targets from `A` to `F` according to finding severity.
4. **Provide Dual User Interfaces:** Deliver both an ANSI-colored CLI tool for terminal automation and an interactive Web Application (Web GUI) with a live URL input box.
5. **Generate Actionable Remediation Guidance:** Produce publication-ready HTML reports containing copy-paste server configuration snippets (Apache, Nginx, application code) for every discovered flaw.

### 2.4 Scope and Boundaries
- **In Scope:** Passive inspection of HTTP response headers, cookie flags, active CORS preflight/GET requests with custom `Origin` headers, transport layer scheme validation, and reporting.
- **Out of Scope:** Destructive testing, SQL injection payloads, denial-of-service, authenticated session crawling, or exploiting vulnerabilities. The tool is non-invasive and safe for production reconnaissance.

---

## 3. THEORETICAL FRAMEWORK & VULNERABILITY ANALYSIS

### 3.1 HTTP Security Headers Overview

| Header Name | Severity | Default / Missing Threat | Defense Mechanism |
|---|---|---|---|
| **Strict-Transport-Security (HSTS)** | **HIGH** | SSL stripping, downgrade attacks, MITM interception on initial request. | Forces the browser to communicate exclusively over HTTPS for a specified duration (`max-age`). |
| **Content-Security-Policy (CSP)** | **HIGH** | Cross-Site Scripting (XSS), malicious script execution, unauthorized iframe framing. | Restricts origins from which scripts, styles, images, and objects can be loaded or executed. |
| **X-Frame-Options (XFO)** | **MEDIUM** | Clickjacking / UI Redressing attacks where the site is framed invisibly. | Instructs the browser whether the site can be embedded inside `<frame>`, `<iframe>`, or `<embed>`. |
| **X-Content-Type-Options** | **MEDIUM** | MIME-type confusion / sniffing attacks where non-executable files are parsed as scripts. | Enforces strict MIME typing via `nosniff`, preventing drive-by payload execution. |
| **Referrer-Policy** | **LOW** | Leakage of sensitive tokens, user IDs, or reset keys embedded in URL query parameters. | Governs what referrer information is sent along with cross-origin requests. |
| **Permissions-Policy** | **LOW** | Unauthorized access to client hardware APIs (camera, microphone, geolocation). | Explicitly restricts or disables sensitive browser feature access. |

### 3.2 Cross-Origin Resource Sharing (CORS) Security
CORS relaxes the Same-Origin Policy by allowing servers to indicate which origins are permitted to read response data in the browser. However, common configuration shortcuts create severe vulnerabilities:

```
[Attacker Website] ----(1) GET /api/user [Origin: https://evil.example.com]----> [Vulnerable Server]
[Attacker Website] <---(2) ACAO: https://evil.example.com | ACAC: true -------- [Vulnerable Server]
[Attacker Browser] ---> Reads sensitive JSON payload on behalf of authenticated user!
```

The scanner dynamically tests three critical CORS misconfigurations:
1. **Wildcard Origin with Credentials Enabled (`[HIGH]`):**  
   `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`.  
   *Note:* While modern browsers prohibit reading responses under this combination, server configuration reflects gross negligence and enables abuse in legacy environments or custom clients.
2. **Arbitrary Origin Reflection with Credentials (`[HIGH]`):**  
   The server echoes the incoming `Origin` header (e.g. `https://evil.example.com` or `null`) directly into `Access-Control-Allow-Origin` and enables credentials. This completely bypasses the SOP, allowing malicious sites to read private user data.
3. **Overly Permissive Wildcard Origin (`[LOW]`):**  
   `Access-Control-Allow-Origin: *` without credentials. Acceptable for public content, but dangerous if applied to private or internal APIs.

### 3.3 Cookie Security Directives
Cookies remain the primary storage mechanism for session identifiers:
- **`Secure` Attribute (`[MEDIUM]`):** Directs the browser to only transmit the cookie over encrypted TLS connections. If missing, a user visiting `http://` can leak their session token over cleartext.
- **`HttpOnly` Attribute (`[MEDIUM]`):** Prohibits client-side JavaScript (`document.cookie`) from accessing the cookie. If an application suffers from an XSS flaw, `HttpOnly` prevents the attacker from immediately stealing session tokens.

### 3.4 Information Disclosure & Server Fingerprinting
Exposing internal server versions aids attackers in targeted CVE lookup:
- `Server`: e.g., `Apache/2.4.41 (Ubuntu)`, `nginx/1.18.0`
- `X-Powered-By`: e.g., `PHP/7.4.3`, `Express`, `ASP.NET`
- `X-AspNet-Version` / `X-AspNetMvc-Version`: e.g., `4.0.30319`

### 3.5 Mapping to OWASP Top 10 (A05:2021)
This project is directly situated within **OWASP Top 10 Category A05:2021 – Security Misconfiguration**:
> *"As attacks against web applications have evolved, security misconfiguration has grown to encompass missing appropriate security hardening across any part of the application stack, including missing defensive headers, default accounts, overly permissive CORS policies, and unprotected files."*

---

## 4. SYSTEM ARCHITECTURE & DESIGN

### 4.1 Architectural Overview
The system is constructed with a decoupled, modular architecture adhering to separation of concerns:
1. **Input Interface Layer:** Command-Line Interface (`argparse`) or Interactive Web GUI (`app.py`).
2. **Audit Core Engine (`SecurityAuditEngine`):** Handles network sessions, transport validation, passive header auditing, cookie parsing, and active CORS injection probes.
3. **Scoring & Grading Engine:** Evaluates collected findings against the weighted deduction rubric.
4. **Presentation & Reporting Layer:** Outputs terminal ANSI tables, generates HTML reports, or streams JSON responses.

### 4.2 System Flowchart & Lifecycle

```mermaid
flowchart TD
    Start([User Initiates Scan]) --> Input{Input Source}
    Input -->|CLI| CLIArgs[scanner.py CLI Argument Parser]
    Input -->|Web GUI| WebForm[app.py Browser Input Field]
    
    CLIArgs --> Engine[SecurityAuditEngine.audit_target]
    WebForm --> APIScan[/api/scan POST Endpoint]
    APIScan --> Engine

    subgraph "Core Security Auditing Engine"
        Engine --> Step1[1. Transport Layer Check: Scheme & TLS Validity]
        Step1 --> Step2[2. Passive Header Audit: HSTS, CSP, XFO, etc.]
        Step2 --> Step3[3. Information Disclosure: Server, X-Powered-By]
        Step3 --> Step4[4. Cookie Audit: Secure & HttpOnly Flags]
        Step4 --> Step5[5. Active CORS Probing: evil.example.com & null]
    end

    Step5 --> Scoring[6. Calculate Score & Letter Grade A-F]
    Scoring --> Results[Structured Result Dictionary]

    Results --> OutputType{Output Mode}
    OutputType -->|Terminal| TermOutput[Color-Coded ANSI Output Table]
    OutputType -->|JSON| JSONFile[Export scan_report.json]
    OutputType -->|HTML Report| HTMLGen[report_generator.py -> scan_report.html]
    OutputType -->|Web GUI| BrowserRender[Interactive DOM Render in Browser]
```

### 4.3 Data Structures and Model Design
Findings are encapsulated in standardized dictionaries:
```python
Finding = {
    "severity": "HIGH" | "MEDIUM" | "LOW" | "INFO",
    "category": str,      # e.g., "Security Headers", "CORS", "Cookie Security"
    "title": str,         # e.g., "Missing Strict-Transport-Security (HSTS)"
    "description": str,   # Threat impact explanation
    "evidence": str,      # Observed header value or absent status
    "remediation": str,   # Exact configuration instruction
    "owasp_ref": str      # "A05:2021 - Security Misconfiguration"
}
```

### 4.4 Scoring Engine & Academic Grading Formula
The system employs a mathematical deduction model:

$$\text{Final Score} = \max\left(0, 100 - (20 \times N_{\text{HIGH}} + 10 \times N_{\text{MEDIUM}} + 5 \times N_{\text{LOW}})\right)$$

Where $N_{\text{HIGH}}$, $N_{\text{MEDIUM}}$, and $N_{\text{LOW}}$ denote the counts of findings for each severity tier.

#### Grading Conversion Table:
| Score Interval | Letter Grade | Evaluation & Health Posture |
|---|:---:|---|
| **90 – 100** | **A** | Excellent; comprehensive defense-in-depth implemented. |
| **80 – 89** | **B** | Good posture; minor recommendations (e.g. Referrer-Policy). |
| **70 – 79** | **C** | Fair posture; notable defensive headers missing. |
| **60 – 69** | **D** | Poor; critical defense mechanisms omitted. |
| **0 – 59** | **F** | Failing; high-risk security misconfigurations present. |

---

## 5. IMPLEMENTATION DETAILS

### 5.1 Technology Stack Rationale
- **Language:** Python 3.8+ (cross-platform compatibility, clean standard library).
- **HTTP Client:** `requests` (robust connection pooling, SSL context handling).
- **Web Server:** Standard library `http.server.HTTPServer` (guarantees zero external web framework bloat; runs anywhere without installing Flask or Django).
- **Styling & UI:** Vanilla HTML5, modern CSS3 (custom properties, glassmorphism, flexbox/grid), and lightweight Vanilla JavaScript.

### 5.2 Core Scanner Engine (`scanner.py`)
- **Transport Security:** Normalizes bare URLs (adding `https://` by default), tests HTTP-to-HTTPS 301 redirection, and catches `requests.exceptions.SSLError`. If an SSL certificate fails, the scanner logs a `HIGH` finding and re-executes with `verify=False` to safely complete the remaining audits.
- **Header Parsing:** Case-insensitive dictionary evaluation comparing response headers against `SECURITY_HEADERS_DEF` and `INFORMATION_LEAK_HEADERS`.
- **Cookie Extraction:** Dual-mode auditing that inspects both `response.cookies` (`RequestsCookieJar`) and raw `Set-Cookie` lines to catch all directives.
- **Active CORS Probing:** Injects `Origin: https://evil.example.com` and `Origin: null` with `Access-Control-Request-Method: GET`, analyzing `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.

### 5.3 Executive HTML Report Generator (`report_generator.py`)
- Compiles scan results into a responsive, executive HTML dashboard.
- Includes KPI metric cards, target summary tables, grade badges with glowing borders, and an interactive JavaScript filter for instant vulnerability triage.
- Embedded CSS `@media print` rules ensure clean PDF export for audit submissions.

### 5.4 Interactive Web Application (`app.py`)
- Integrates a lightweight HTTP server (`HTTPServer`, `BaseHTTPRequestHandler`) bound to `127.0.0.1:5000`.
- Provides an interactive dashboard with a glowing URL input field, preset test chips, real-time scan animation, and instant rendering of findings with JSON export capabilities.

### 5.5 Resilient Network & Error Handling
- **10-Second Strict Timeout:** Prevents hanging execution on unresponsive servers.
- **Exception Quarantine:** Catches `ConnectTimeout`, `ConnectionError`, and `RequestException` at the target level, ensuring that an unreachable host does not abort scanning of subsequent targets.
- **Windows Console VT100 & UTF-8 Reconfiguration:** Configures `sys.stdout` and `sys.stderr` to UTF-8 and enables virtual terminal processing in the Windows kernel, completely preventing `UnicodeEncodeError` exceptions.

---

## 6. EXPERIMENTAL RESULTS & CASE STUDIES

### 6.1 Test Methodology
The scanner was validated against multiple web environments:
1. A reference production domain (`https://example.com`).
2. An intentionally vulnerable web testbed (`http://testphp.vulnweb.com`).
3. An active HTTP testing service (`https://httpbin.org/get`).

---

### 6.2 Case Study 1: `https://example.com`
- **Final URL:** `https://example.com/`
- **HTTP Status Code:** `200 OK`
- **Latency:** ~213 ms
- **Findings Summary:** 2 High, 2 Medium, 3 Low.
- **Calculated Score:** $100 - (20 \times 2 + 10 \times 2 + 5 \times 3) = 25/100$
- **Assigned Grade:** **F**

#### Findings Breakdown:
| Severity | Category | Discovered Issue | Observed Evidence | Recommended Fix |
|---|---|---|---|---|
| **HIGH** | Security Headers | Missing Strict-Transport-Security | Absent | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` |
| **HIGH** | Security Headers | Missing Content-Security-Policy | Absent | `Content-Security-Policy: default-src 'self'; script-src 'self';` |
| **MEDIUM** | Security Headers | Missing X-Frame-Options | Absent | `X-Frame-Options: DENY` |
| **MEDIUM** | Security Headers | Missing X-Content-Type-Options | Absent | `X-Content-Type-Options: nosniff` |
| **LOW** | Security Headers | Missing Referrer-Policy | Absent | `Referrer-Policy: strict-origin-when-cross-origin` |
| **LOW** | Security Headers | Missing Permissions-Policy | Absent | `Permissions-Policy: camera=(), microphone=(), geolocation=()` |
| **LOW** | Information Leakage | Server Version Disclosure | `Server: cloudflare` | Configure web server to omit server identity banner. |

*Analysis:* Despite being hosted on modern CDN infrastructure (Cloudflare), `example.com` intentionally omits defensive headers because it serves as an RFC documentation placeholder, demonstrating why automated audits are critical even on high-profile domains.

---

### 6.3 Case Study 2: `http://testphp.vulnweb.com`
- **Target URL:** `http://testphp.vulnweb.com`
- **Observed Behavior:** Target timed out after 10 seconds due to outbound port 80 restrictions / host unavailability.
- **Engine Handling:** Handled gracefully via `requests.exceptions.ConnectTimeout`. Marked as `[ERROR] Connection failed: Connection timed out after 10s while connecting to http://testphp.vulnweb.com`.
- **Outcome:** The engine quarantined the failure, displayed an informative alert box in the reports, and continued to audit subsequent targets without crashing.

---

### 6.4 Case Study 3: `https://httpbin.org/get`
- **CORS Test Results:**
  - `Access-Control-Allow-Origin: *`
  - `Access-Control-Allow-Credentials: true`
- **Finding:** **CORS Wildcard with Credentials Enabled `[HIGH]`**
- **Analysis:** Demonstrates active detection of overly permissive cross-origin policies that could allow third-party scripts to manipulate authenticated user contexts.

---

## 7. ETHICAL, LEGAL & COMPLIANCE CONSIDERATIONS

1. **Authorization & Legal Boundaries:**  
   Security testing without authorization violates computer misuse regulations, including the **US Computer Fraud and Abuse Act (CFAA)**, the **UK Computer Misuse Act 1990**, and **Section 66 of the Indian Information Technology Act 2000**. The scanner includes a mandatory legal disclaimer on CLI execution, web interfaces, and reports.
2. **Non-Invasive Architecture:**  
   The scanner performs only benign `GET` and `OPTIONS` requests without fuzzing parameters, attempting authentication bypass, or injecting exploit payloads. It adheres to passive reconnaissance principles.
3. **Defensive Utility:**  
   Every identified vulnerability is paired with actionable remediation directives, transforming raw audit data into an educational tool for secure software engineering.

---

## 8. CONCLUSION & FUTURE ROADMAP

### 8.1 Summary of Contributions
The **Automated Web Scanner** project successfully fulfills all stated objectives:
- Created a robust, production-ready security auditor using only Python standard library and `requests`.
- Implemented deep auditing across 6 essential security headers, active CORS probe injection, cookie flags, and information disclosure banners.
- Engineered an objective 100-point scoring algorithm with academic letter grading (`A`–`F`).
- Built dual user interfaces: a colored CLI tool and an interactive, real-time Web GUI on `http://127.0.0.1:5000`.
- Delivered publication-quality executive HTML and JSON reports with remediation guides.

### 8.2 Future Roadmap
- [ ] **TLS Cipher Suite Enumeration:** Integrate the Python `ssl` library to detect deprecated protocols (TLS 1.0, 1.1) and insecure ciphers (RC4, 3DES).
- [ ] **Deep CSP Syntax Validation:** Parse CSP policy strings to flag risky directives such as `'unsafe-inline'`, `'unsafe-eval'`, and broad CDN wildcards.
- [ ] **CI/CD Pipeline Integration:** Provide a GitHub Action / GitLab CI container that automatically breaks builds if an application's security grade falls below `B`.
- [ ] **Subdomain Reconnaissance:** Add passive DNS enumeration to assess an organization's entire digital perimeter simultaneously.

---

## 9. REFERENCES

1. **OWASP Foundation (2021).** *OWASP Top 10:2021 – A05: Security Misconfiguration*. Available at: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
2. **Mozilla Developer Network (MDN) Web Docs.** *HTTP Headers Reference: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options*. Available at: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
3. **Barth, A. (2011).** *HTTP State Management Mechanism (RFC 6265)*. Internet Engineering Task Force (IETF).
4. **Hodges, J., Jackson, C., & Barth, A. (2012).** *HTTP Strict Transport Security (HSTS) (RFC 6797)*. IETF.
5. **W3C (2020).** *Cross-Origin Resource Sharing (CORS) Living Standard*. WHATWG.
6. **Kunal26-coder (2026).** *Automated Web Scanner Source Code Repository*. Available at: https://github.com/Kunal26-coder/automated-web-scanner

---
*End of Project Report*
