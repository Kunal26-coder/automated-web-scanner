"""
=============================================================================
Automated Web Scanner - HTML Report Generator
=============================================================================
Generates professional, responsive, executive-grade cybersecurity audit reports
in HTML format. Visualizes target grades, severity breakdown, technical
evidence, and actionable remediation guidelines.

Author: Senior Cybersecurity Engineer
Tech Stack: Python Standard Library (HTML/CSS/JS generation)
Zero external runtime dependencies.
=============================================================================
"""

import html
import json
from datetime import datetime
from typing import List, Dict, Any


def get_grade_color(grade: str) -> Dict[str, str]:
    """Return styling tokens based on the letter grade."""
    palettes = {
        "A": {"bg": "rgba(16, 185, 129, 0.15)", "border": "#10b981", "text": "#34d399", "glow": "rgba(16, 185, 129, 0.4)"},
        "B": {"bg": "rgba(14, 165, 233, 0.15)", "border": "#0ea5e9", "text": "#38bdf8", "glow": "rgba(14, 165, 233, 0.4)"},
        "C": {"bg": "rgba(245, 158, 11, 0.15)", "border": "#f59e0b", "text": "#fbbf24", "glow": "rgba(245, 158, 11, 0.4)"},
        "D": {"bg": "rgba(249, 115, 22, 0.15)", "border": "#f97316", "text": "#fb923c", "glow": "rgba(249, 115, 22, 0.4)"},
        "F": {"bg": "rgba(239, 68, 68, 0.15)", "border": "#ef4444", "text": "#f87171", "glow": "rgba(239, 68, 68, 0.4)"},
    }
    return palettes.get(grade.upper(), palettes["F"])


def get_severity_badge_class(severity: str) -> str:
    """Return CSS class name for severity."""
    s = severity.upper()
    if s == "HIGH":
        return "badge-high"
    elif s == "MEDIUM":
        return "badge-medium"
    elif s == "LOW":
        return "badge-low"
    return "badge-info"


def generate_html_report(scan_results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Build and write an executive HTML report from a list of scan results.
    
    :param scan_results: List of scan result dictionaries from scanner.py
    :param output_path: Destination file path for the .html report
    """
    total_targets = len(scan_results)
    successful_scans = [r for r in scan_results if not r.get("error")]
    failed_scans = [r for r in scan_results if r.get("error")]
    
    avg_score = (
        round(sum(r["score"] for r in successful_scans) / len(successful_scans), 1)
        if successful_scans else 0
    )
    
    total_high = sum(
        sum(1 for f in r.get("findings", []) if f.get("severity") == "HIGH")
        for r in successful_scans
    )
    total_medium = sum(
        sum(1 for f in r.get("findings", []) if f.get("severity") == "MEDIUM")
        for r in successful_scans
    )
    total_low = sum(
        sum(1 for f in r.get("findings", []) if f.get("severity") == "LOW")
        for r in successful_scans
    )
    total_findings = total_high + total_medium + total_low

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build target cards & findings tables HTML
    target_sections_html = []
    summary_rows_html = []

    for idx, target in enumerate(scan_results, start=1):
        url = html.escape(target.get("target_url", "Unknown"))
        final_url = html.escape(target.get("final_url", url))
        score = target.get("score", 0)
        grade = target.get("grade", "F")
        error = target.get("error")
        status_code = target.get("status_code", "N/A")
        response_time = f"{target.get('response_time_ms', 0):.0f}ms"
        findings = target.get("findings", [])
        
        high_cnt = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_cnt = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_cnt = sum(1 for f in findings if f.get("severity") == "LOW")

        grade_style = get_grade_color(grade)

        # Summary Table Row
        if error:
            summary_rows_html.append(f"""
                <tr>
                    <td><strong>#{idx}</strong></td>
                    <td><a href="#target-{idx}" class="target-link">{url}</a></td>
                    <td><span class="badge badge-error">Unreachable</span></td>
                    <td>—</td>
                    <td><span class="grade-pill grade-error">ERR</span></td>
                    <td colspan="3" class="text-muted text-small">{html.escape(error)}</td>
                </tr>
            """)
        else:
            summary_rows_html.append(f"""
                <tr>
                    <td><strong>#{idx}</strong></td>
                    <td><a href="#target-{idx}" class="target-link">{url}</a></td>
                    <td><span class="badge badge-status">{status_code}</span></td>
                    <td><strong>{score}/100</strong></td>
                    <td><span class="grade-pill" style="background:{grade_style['bg']}; color:{grade_style['text']}; border-color:{grade_style['border']}">{grade}</span></td>
                    <td><span class="badge badge-high">{high_cnt}</span></td>
                    <td><span class="badge badge-medium">{med_cnt}</span></td>
                    <td><span class="badge badge-low">{low_cnt}</span></td>
                </tr>
            """)

        # Detailed Findings Table for Target
        if error:
            target_body = f"""
                <div class="error-box">
                    <div class="error-title">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        Connection Error / Target Unreachable
                    </div>
                    <div class="error-desc">{html.escape(error)}</div>
                    <p class="text-small text-muted" style="margin-top: 10px;">
                        The scanner attempted to establish a connection with a 10-second timeout, but the host did not respond or connection was refused. Check your network connection, DNS settings, or verify if the host is operational.
                    </p>
                </div>
            """
        elif not findings:
            target_body = """
                <div class="clean-box">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    <div>
                        <strong>No security misconfigurations found!</strong>
                        <p class="text-muted text-small">All inspected security headers, CORS policies, and cookie flags comply with defensive baselines.</p>
                    </div>
                </div>
            """
        else:
            findings_rows = []
            for f_idx, f in enumerate(findings, start=1):
                sev = f.get("severity", "LOW")
                badge_cls = get_severity_badge_class(sev)
                title = html.escape(f.get("title", ""))
                category = html.escape(f.get("category", "General"))
                desc = html.escape(f.get("description", ""))
                evidence = html.escape(f.get("evidence", "N/A"))
                remediation = html.escape(f.get("remediation", ""))
                owasp = html.escape(f.get("owasp_ref", "A05:2021-Security Misconfiguration"))

                findings_rows.append(f"""
                    <tr class="finding-row severity-{sev.lower()}">
                        <td style="width: 100px;">
                            <span class="badge {badge_cls}">{sev}</span>
                            <div class="category-tag">{category}</div>
                        </td>
                        <td style="width: 32%;">
                            <div class="finding-title">{title}</div>
                            <div class="finding-desc">{desc}</div>
                            <div class="owasp-tag">{owasp}</div>
                        </td>
                        <td style="width: 28%;">
                            <div class="code-evidence"><code>{evidence}</code></div>
                        </td>
                        <td style="width: 32%;">
                            <div class="remediation-box">
                                <div class="remediation-header">Recommended Remediation:</div>
                                <pre><code>{remediation}</code></pre>
                            </div>
                        </td>
                    </tr>
                """)

            target_body = f"""
                <div class="table-container">
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Vulnerability & Description</th>
                                <th>Observed Evidence</th>
                                <th>How to Fix (Remediation)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(findings_rows)}
                        </tbody>
                    </table>
                </div>
            """

        # Append card
        target_sections_html.append(f"""
            <div class="card target-card" id="target-{idx}">
                <div class="target-card-header">
                    <div class="target-meta">
                        <span class="target-index">TARGET #{idx}</span>
                        <h2 class="target-title">{url}</h2>
                        <div class="target-submeta">
                            <span><strong>Final URL:</strong> <code>{final_url}</code></span>
                            <span><strong>Status:</strong> {status_code}</span>
                            <span><strong>Latency:</strong> {response_time}</span>
                            <span><strong>Findings:</strong> {len(findings)}</span>
                        </div>
                    </div>
                    <div class="target-score-badge" style="background:{grade_style['bg']}; border-color:{grade_style['border']}; box-shadow: 0 0 20px {grade_style['glow']};">
                        <div class="score-number" style="color:{grade_style['text']};">{score}<span>/100</span></div>
                        <div class="grade-letter" style="color:{grade_style['text']};">GRADE {grade}</div>
                    </div>
                </div>
                <div class="target-card-body">
                    {target_body}
                </div>
            </div>
        """)

    # Full HTML Template
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Automated Web Scanner - Security Audit and Vulnerability Assessment Report">
    <title>Automated Web Scanner - Audit Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-tertiary: #1f2937;
            --card-bg: rgba(17, 24, 39, 0.85);
            --card-border: rgba(75, 85, 99, 0.35);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --severity-high: #ef4444;
            --severity-high-bg: rgba(239, 68, 68, 0.15);
            --severity-med: #f97316;
            --severity-med-bg: rgba(249, 115, 22, 0.15);
            --severity-low: #eab308;
            --severity-low-bg: rgba(234, 179, 8, 0.15);
            --success: #10b981;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', Consolas, monospace;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.5;
            padding: 30px 20px;
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(59, 130, 246, 0.08) 0%, transparent 40%);
            background-attachment: fixed;
        }}

        .container {{
            max-width: 1350px;
            margin: 0 auto;
        }}

        /* Header */
        header.header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            padding: 24px 30px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            backdrop-filter: blur(12px);
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .logo-icon {{
            width: 52px;
            height: 52px;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
        }}

        .brand-text h1 {{
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ffffff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .brand-text p {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .header-actions {{
            display: flex;
            align-items: center;
            gap: 14px;
        }}

        .btn {{
            background: var(--bg-tertiary);
            color: var(--text-main);
            border: 1px solid var(--card-border);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 500;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }}

        .btn:hover {{
            background: var(--accent-cyan);
            color: #000;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
        }}

        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 18px;
            margin-bottom: 25px;
        }}

        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 20px;
            border-radius: 14px;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
            transition: transform 0.2s;
        }}

        .metric-card:hover {{
            transform: translateY(-2px);
        }}

        .metric-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
        }}

        .metric-card.targets::before {{ background: var(--accent-cyan); }}
        .metric-card.score::before {{ background: #10b981; }}
        .metric-card.high::before {{ background: var(--severity-high); }}
        .metric-card.med::before {{ background: var(--severity-med); }}
        .metric-card.low::before {{ background: var(--severity-low); }}

        .metric-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}

        .metric-value {{
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.5px;
        }}

        .metric-sub {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        /* Cards and Tables */
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 25px;
            backdrop-filter: blur(12px);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}

        .card-title {{
            font-size: 1.15rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        /* Summary Table */
        .summary-table, .findings-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.9rem;
        }}

        .summary-table th, .findings-table th {{
            background: rgba(31, 41, 55, 0.5);
            color: var(--text-muted);
            text-align: left;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--card-border);
        }}

        .summary-table th:first-child, .findings-table th:first-child {{ border-top-left-radius: 8px; }}
        .summary-table th:last-child, .findings-table th:last-child {{ border-top-right-radius: 8px; }}

        .summary-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: middle;
        }}

        .summary-table tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}

        .target-link {{
            color: #38bdf8;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s;
        }}

        .target-link:hover {{
            color: var(--accent-cyan);
            text-decoration: underline;
        }}

        /* Grade Pill */
        .grade-pill {{
            display: inline-block;
            font-weight: 800;
            font-size: 0.85rem;
            padding: 3px 12px;
            border-radius: 9999px;
            border: 1px solid transparent;
            text-align: center;
            min-width: 36px;
        }}

        .grade-error {{
            background: rgba(107, 114, 128, 0.2);
            color: #9ca3af;
            border-color: #4b5563;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-high {{ background: var(--severity-high-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-medium {{ background: var(--severity-med-bg); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-low {{ background: var(--severity-low-bg); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }}
        .badge-status {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-error {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }}

        /* Target Cards */
        .target-card {{
            border-left: 4px solid var(--accent-cyan);
        }}

        .target-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}

        .target-index {{
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--accent-cyan);
            letter-spacing: 1px;
            display: block;
            margin-bottom: 4px;
        }}

        .target-title {{
            font-size: 1.35rem;
            font-weight: 700;
            color: #ffffff;
            word-break: break-all;
        }}

        .target-submeta {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 8px;
        }}

        .target-submeta code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: var(--font-mono);
            color: #e2e8f0;
        }}

        .target-score-badge {{
            padding: 12px 24px;
            border-radius: 12px;
            border: 2px solid;
            text-align: center;
            min-width: 140px;
        }}

        .score-number {{
            font-size: 1.8rem;
            font-weight: 800;
            line-height: 1;
        }}

        .score-number span {{
            font-size: 0.9rem;
            font-weight: 400;
            opacity: 0.7;
        }}

        .grade-letter {{
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 1px;
            margin-top: 4px;
        }}

        /* Findings Table Details */
        .table-container {{
            overflow-x: auto;
        }}

        .findings-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            vertical-align: top;
        }}

        .category-tag {{
            font-size: 0.7rem;
            color: var(--text-muted);
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .finding-title {{
            font-weight: 700;
            color: #ffffff;
            font-size: 0.95rem;
            margin-bottom: 4px;
        }}

        .finding-desc {{
            color: var(--text-muted);
            font-size: 0.82rem;
            line-height: 1.4;
        }}

        .owasp-tag {{
            display: inline-block;
            font-size: 0.7rem;
            color: #38bdf8;
            margin-top: 6px;
            background: rgba(56, 189, 248, 0.1);
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid rgba(56, 189, 248, 0.2);
        }}

        .code-evidence {{
            background: #090d16;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 8px 12px;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: #e2e8f0;
            max-height: 160px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .remediation-box {{
            background: rgba(16, 185, 129, 0.06);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 8px;
            padding: 10px 12px;
            font-size: 0.82rem;
        }}

        .remediation-header {{
            font-weight: 700;
            color: #34d399;
            margin-bottom: 6px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .remediation-box pre {{
            margin: 0;
            background: rgba(0, 0, 0, 0.4);
            padding: 6px 8px;
            border-radius: 4px;
            overflow-x: auto;
        }}

        .remediation-box code {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #a7f3d0;
            white-space: pre-wrap;
            word-break: break-word;
        }}

        /* Error and Clean Boxes */
        .error-box {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 10px;
            padding: 16px 20px;
        }}

        .error-title {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            color: #f87171;
            margin-bottom: 6px;
        }}

        .error-desc {{
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: #fca5a5;
            background: rgba(0, 0, 0, 0.3);
            padding: 8px 12px;
            border-radius: 6px;
        }}

        .clean-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 10px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        /* Filter Controls */
        .filter-bar {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}

        .filter-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 600;
        }}

        .filter-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--card-border);
            color: var(--text-muted);
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .filter-btn.active, .filter-btn:hover {{
            background: var(--accent-cyan);
            color: #000;
            font-weight: 600;
            border-color: var(--accent-cyan);
        }}

        /* Footer */
        footer.footer {{
            text-align: center;
            padding: 30px 20px;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--card-border);
            margin-top: 40px;
        }}

        .disclaimer {{
            background: rgba(234, 179, 8, 0.06);
            border: 1px solid rgba(234, 179, 8, 0.25);
            padding: 12px 16px;
            border-radius: 8px;
            max-width: 900px;
            margin: 0 auto 16px;
            color: #fde047;
            font-size: 0.75rem;
            line-height: 1.4;
        }}

        /* Utilities */
        .text-small {{ font-size: 0.75rem; }}
        .text-muted {{ color: var(--text-muted); }}

        @media print {{
            body {{ background: #ffffff; color: #000000; padding: 0; }}
            .card, header.header {{ background: #ffffff; border: 1px solid #ccc; box-shadow: none; color: #000000; }}
            .btn, .filter-bar {{ display: none; }}
            .target-title, .finding-title {{ color: #000000; }}
            .code-evidence, .remediation-box pre {{ background: #f3f4f6; color: #111827; border-color: #d1d5db; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Main Header -->
        <header class="header">
            <div class="brand">
                <div class="logo-icon">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        <path d="m9 12 2 2 4-4"></path>
                    </svg>
                </div>
                <div class="brand-text">
                    <h1>Automated Web Scanner</h1>
                    <p>Security Headers, CORS & Transport Audit Report &bull; Generated: {report_time}</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn" onclick="window.print()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                    Print / PDF
                </button>
            </div>
        </header>

        <!-- Executive Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card targets">
                <div class="metric-label">Targets Scanned</div>
                <div class="metric-value">{total_targets}</div>
                <div class="metric-sub">{len(successful_scans)} online / {len(failed_scans)} failed</div>
            </div>
            <div class="metric-card score">
                <div class="metric-label">Average Score</div>
                <div class="metric-value">{avg_score}<span>/100</span></div>
                <div class="metric-sub">Across accessible endpoints</div>
            </div>
            <div class="metric-card high">
                <div class="metric-label">High Severity</div>
                <div class="metric-value" style="color: var(--severity-high);">{total_high}</div>
                <div class="metric-sub">Critical fixes needed (-20 pts each)</div>
            </div>
            <div class="metric-card med">
                <div class="metric-label">Medium Severity</div>
                <div class="metric-value" style="color: var(--severity-med);">{total_medium}</div>
                <div class="metric-sub">Moderate risk items (-10 pts each)</div>
            </div>
            <div class="metric-card low">
                <div class="metric-label">Low Severity</div>
                <div class="metric-value" style="color: var(--severity-low);">{total_low}</div>
                <div class="metric-sub">Best practice / leakage (-5 pts each)</div>
            </div>
        </div>

        <!-- Executive Summary Table Card -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
                    Targets Executive Summary
                </h2>
                <div class="text-small text-muted">Total Findings: <strong>{total_findings}</strong></div>
            </div>
            <div class="table-container">
                <table class="summary-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Target URL</th>
                            <th>Status</th>
                            <th>Score</th>
                            <th>Grade</th>
                            <th>High</th>
                            <th>Med</th>
                            <th>Low</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(summary_rows_html)}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Filter Bar for Interactive Findings -->
        <div class="filter-bar">
            <span class="filter-label">Filter Findings:</span>
            <button class="filter-btn active" onclick="filterSeverity('all', this)">All Severities</button>
            <button class="filter-btn" onclick="filterSeverity('high', this)">High Risk Only</button>
            <button class="filter-btn" onclick="filterSeverity('medium', this)">Medium Risk Only</button>
            <button class="filter-btn" onclick="filterSeverity('low', this)">Low Risk Only</button>
        </div>

        <!-- Detailed Target Sections -->
        {''.join(target_sections_html)}

        <!-- Footer & Legal Disclaimer -->
        <footer class="footer">
            <div class="disclaimer">
                <strong>LEGAL DISCLAIMER &amp; ETHICAL USAGE NOTICE:</strong>
                This tool is intended exclusively for authorized cybersecurity auditing, academic research, and defensive evaluation of domains you own or have explicit written permission to test. Unauthorized port scanning or automated vulnerability testing against systems without permission may violate local and international cyber laws.
            </div>
            <p>Automated Web Scanner &bull; College Cybersecurity Project &bull; OWASP A05:2021 Security Misconfiguration Benchmark</p>
        </footer>
    </div>

    <!-- Client-side Interactive Filter Script -->
    <script>
        function filterSeverity(severity, element) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            element.classList.add('active');

            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                if (severity === 'all' || row.classList.contains('severity-' + severity)) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
