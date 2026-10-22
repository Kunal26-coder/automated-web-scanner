"""
=============================================================================
Automated Web Scanner - Interactive Web Application
=============================================================================
A modern, zero-dependency interactive Web GUI for the Automated Web Scanner.
Allows users to enter target URLs directly in their browser, initiate on-demand
security audits, view real-time scorecards, and export reports.

Built strictly with Python Standard Library (http.server) + requests.
Zero external web frameworks required (no Flask/Django needed).

Author: Senior Cybersecurity Engineer
=============================================================================
"""

import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

# Ensure local modules can be imported
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from scanner import SecurityAuditEngine, Colors, enable_windows_ansi
from report_generator import generate_html_report

DEFAULT_PORT = 5000


HTML_UI_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Automated Web Scanner - Interactive Web Vulnerability Assessment Tool">
    <title>Automated Web Scanner &bull; Interactive Audit Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #080c14;
            --bg-secondary: #0f172a;
            --bg-card: rgba(15, 23, 42, 0.85);
            --card-border: rgba(51, 65, 85, 0.6);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-cyan-glow: rgba(6, 182, 212, 0.4);
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
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: var(--font-sans);
            min-height: 100vh;
            padding: 30px 20px;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(6, 182, 212, 0.12) 0%, transparent 40%),
                radial-gradient(circle at 90% 90%, rgba(59, 130, 246, 0.12) 0%, transparent 40%);
            background-attachment: fixed;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Header Navigation */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 28px;
            background: var(--bg-card);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            backdrop-filter: blur(12px);
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .logo-box {
            width: 46px;
            height: 46px;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            box-shadow: 0 0 20px var(--accent-cyan-glow);
        }

        .brand-titles h1 {
            font-size: 1.35rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ffffff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-titles p {
            font-size: 0.78rem;
            color: var(--text-muted);
        }

        .status-badge {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.4);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 10px #10b981;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.85); }
        }

        /* Interactive Scanner Hero Card */
        .hero-card {
            background: var(--bg-card);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 36px 30px;
            backdrop-filter: blur(14px);
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
            position: relative;
            overflow: hidden;
        }

        .hero-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #06b6d4, #3b82f6, #10b981);
        }

        .hero-title {
            text-align: center;
            margin-bottom: 24px;
        }

        .hero-title h2 {
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
        }

        .hero-title p {
            font-size: 0.95rem;
            color: var(--text-muted);
            max-width: 680px;
            margin: 0 auto;
        }

        /* Input Form */
        .scan-form {
            display: flex;
            gap: 12px;
            max-width: 820px;
            margin: 0 auto 16px;
        }

        .input-group {
            position: relative;
            flex: 1;
        }

        .input-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
        }

        .scan-input {
            width: 100%;
            background: rgba(10, 15, 26, 0.9);
            border: 1px solid rgba(100, 116, 139, 0.4);
            border-radius: 12px;
            padding: 16px 16px 16px 48px;
            color: #ffffff;
            font-size: 1rem;
            font-family: var(--font-sans);
            transition: all 0.25s ease;
        }

        .scan-input:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 20px var(--accent-cyan-glow);
            background: rgba(15, 23, 42, 1);
        }

        .btn-scan {
            background: linear-gradient(135deg, #06b6d4, #2563eb);
            color: #ffffff;
            border: none;
            border-radius: 12px;
            padding: 0 28px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.25s ease;
            box-shadow: 0 4px 15px rgba(6, 182, 212, 0.35);
            white-space: nowrap;
        }

        .btn-scan:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(6, 182, 212, 0.55);
        }

        .btn-scan:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        /* Preset Chips */
        .presets {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .presets-label {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .preset-chip {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.5);
            color: #cbd5e1;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
            font-family: var(--font-mono);
        }

        .preset-chip:hover {
            background: rgba(6, 182, 212, 0.15);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        /* Live Loader */
        .loader-box {
            display: none;
            text-align: center;
            padding: 40px 20px;
        }

        .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(6, 182, 212, 0.15);
            border-top: 4px solid var(--accent-cyan);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loader-title {
            font-size: 1.1rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 6px;
        }

        .loader-sub {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }

        /* Results Container */
        #resultsContainer {
            display: none;
        }

        /* Result Overview Header */
        .result-card {
            background: var(--bg-card);
            border: 1px solid var(--card-border);
            border-radius: 18px;
            padding: 28px;
            backdrop-filter: blur(12px);
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }

        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }

        .target-meta h3 {
            font-size: 1.5rem;
            font-weight: 800;
            color: #ffffff;
            word-break: break-all;
            margin-bottom: 8px;
        }

        .meta-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .meta-tag {
            background: rgba(0, 0, 0, 0.35);
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .meta-tag code {
            font-family: var(--font-mono);
            color: #38bdf8;
        }

        .score-badge {
            padding: 16px 30px;
            border-radius: 16px;
            border: 2px solid;
            text-align: center;
            min-width: 160px;
        }

        .score-num {
            font-size: 2.3rem;
            font-weight: 900;
            line-height: 1;
        }

        .score-num span {
            font-size: 1rem;
            font-weight: 400;
            opacity: 0.7;
        }

        .grade-text {
            font-size: 0.9rem;
            font-weight: 800;
            letter-spacing: 1px;
            margin-top: 4px;
        }

        /* KPI Mini Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }

        .kpi-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 16px;
            position: relative;
            overflow: hidden;
        }

        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
        }

        .kpi-card.high::before { background: var(--severity-high); }
        .kpi-card.med::before { background: var(--severity-med); }
        .kpi-card.low::before { background: var(--severity-low); }
        .kpi-card.status::before { background: var(--accent-cyan); }

        .kpi-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .kpi-val {
            font-size: 1.6rem;
            font-weight: 800;
        }

        /* Filter Row & Action Buttons */
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 14px;
            margin-bottom: 20px;
        }

        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .filter-btn {
            background: var(--bg-secondary);
            border: 1px solid var(--card-border);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
            font-weight: 500;
        }

        .filter-btn.active, .filter-btn:hover {
            background: var(--accent-cyan);
            color: #000;
            font-weight: 700;
            border-color: var(--accent-cyan);
        }

        .action-btns {
            display: flex;
            gap: 10px;
        }

        .btn-secondary {
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
            text-decoration: none;
        }

        .btn-secondary:hover {
            background: var(--accent-cyan);
            color: #000;
            border-color: var(--accent-cyan);
        }

        /* Findings Table */
        .table-responsive {
            overflow-x: auto;
        }

        .findings-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.9rem;
        }

        .findings-table th {
            background: rgba(30, 41, 59, 0.5);
            color: var(--text-muted);
            text-align: left;
            padding: 12px 16px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--card-border);
        }

        .findings-table th:first-child { border-top-left-radius: 10px; }
        .findings-table th:last-child { border-top-right-radius: 10px; }

        .findings-table td {
            padding: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: top;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-high { background: var(--severity-high-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-medium { background: var(--severity-med-bg); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
        .badge-low { background: var(--severity-low-bg); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }

        .cat-tag {
            font-size: 0.7rem;
            color: var(--text-muted);
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .vuln-title {
            font-size: 0.95rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 4px;
        }

        .vuln-desc {
            font-size: 0.82rem;
            color: var(--text-muted);
            line-height: 1.4;
        }

        .owasp-pill {
            display: inline-block;
            font-size: 0.7rem;
            color: #38bdf8;
            margin-top: 6px;
            background: rgba(56, 189, 248, 0.1);
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid rgba(56, 189, 248, 0.2);
        }

        .evidence-box {
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
        }

        .remedy-box {
            background: rgba(16, 185, 129, 0.06);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 8px;
            padding: 10px 12px;
        }

        .remedy-label {
            font-weight: 700;
            color: #34d399;
            margin-bottom: 6px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .remedy-box pre {
            margin: 0;
            background: rgba(0, 0, 0, 0.4);
            padding: 6px 8px;
            border-radius: 4px;
            overflow-x: auto;
        }

        .remedy-box code {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #a7f3d0;
            white-space: pre-wrap;
            word-break: break-word;
        }

        /* Error Banner */
        .error-alert {
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .error-alert h4 {
            color: #f87171;
            font-size: 1.1rem;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .error-alert p {
            color: #fca5a5;
            font-size: 0.85rem;
            font-family: var(--font-mono);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 30px 20px;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--card-border);
            margin-top: 40px;
        }

        .legal-box {
            background: rgba(234, 179, 8, 0.06);
            border: 1px solid rgba(234, 179, 8, 0.25);
            padding: 12px 16px;
            border-radius: 8px;
            max-width: 850px;
            margin: 0 auto 16px;
            color: #fde047;
            font-size: 0.75rem;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="brand">
                <div class="logo-box">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        <path d="m9 12 2 2 4-4"></path>
                    </svg>
                </div>
                <div class="brand-titles">
                    <h1>Automated Web Scanner</h1>
                    <p>Live Security Headers &amp; CORS Vulnerability Audit Console</p>
                </div>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                Engine Online (Port 5000)
            </div>
        </header>

        <!-- Hero Card with Interactive URL Input -->
        <section class="hero-card">
            <div class="hero-title">
                <h2>Scan Any Website for Security Flaws</h2>
                <p>Enter any URL below to audit for missing security headers, insecure cookies, CORS leakage, and transport protocol configurations.</p>
            </div>

            <!-- Form -->
            <form class="scan-form" id="scanForm" onsubmit="handleScan(event)">
                <div class="input-group">
                    <svg class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="2" y1="12" x2="22" y2="12"></line>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                    </svg>
                    <input 
                        type="text" 
                        class="scan-input" 
                        id="targetInput" 
                        placeholder="Enter URL to audit (e.g. https://example.com)..." 
                        required 
                        autocomplete="off"
                    >
                </div>
                <button type="submit" class="btn-scan" id="scanButton">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    <span>Audit Website</span>
                </button>
            </form>

            <!-- Presets -->
            <div class="presets">
                <span class="presets-label">Quick Test Targets:</span>
                <span class="preset-chip" onclick="setTarget('https://example.com')">example.com</span>
                <span class="preset-chip" onclick="setTarget('https://httpbin.org/get')">httpbin.org (CORS testbed)</span>
                <span class="preset-chip" onclick="setTarget('http://testphp.vulnweb.com')">testphp.vulnweb.com</span>
                <span class="preset-chip" onclick="setTarget('https://github.com')">github.com</span>
            </div>

            <!-- Animated Live Loader -->
            <div class="loader-box" id="loaderBox">
                <div class="spinner"></div>
                <div class="loader-title">Conducting Deep Security Audit...</div>
                <div class="loader-sub" id="loaderSubText">Evaluating Transport Layer &amp; Security Headers</div>
            </div>
        </section>

        <!-- Dynamic Results Area -->
        <main id="resultsContainer">
            <!-- Results are injected here dynamically via JavaScript -->
        </main>

        <!-- Footer -->
        <footer class="footer">
            <div class="legal-box">
                <strong>LEGAL DISCLAIMER:</strong>
                This tool is intended strictly for educational, defensive, and authorized cybersecurity testing. Do not scan systems without prior written authorization.
            </div>
            <p>Automated Web Scanner &bull; College Cybersecurity Project &bull; OWASP Benchmark A05:2021</p>
        </footer>
    </div>

    <!-- Interactive Client-side Script -->
    <script>
        let currentScanResult = null;

        function setTarget(url) {
            document.getElementById('targetInput').value = url;
            document.getElementById('targetInput').focus();
        }

        async function handleScan(event) {
            event.preventDefault();
            const input = document.getElementById('targetInput');
            const targetUrl = input.value.trim();
            if (!targetUrl) return;

            const scanBtn = document.getElementById('scanButton');
            const loaderBox = document.getElementById('loaderBox');
            const resultsContainer = document.getElementById('resultsContainer');

            // UI Loading state
            scanBtn.disabled = true;
            loaderBox.style.display = 'block';
            resultsContainer.style.display = 'none';

            // Animate progress text
            const steps = [
                'Establishing secure connection...',
                'Auditing HTTP security headers (HSTS, CSP, X-Frame-Options)...',
                'Probing active CORS policy reflection...',
                'Auditing cookie Secure & HttpOnly flags...',
                'Calculating OWASP compliance score...'
            ];
            let stepIdx = 0;
            const stepInterval = setInterval(() => {
                stepIdx = (stepIdx + 1) % steps.length;
                document.getElementById('loaderSubText').innerText = steps[stepIdx];
            }, 1200);

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: targetUrl })
                });

                clearInterval(stepInterval);
                const data = await response.json();
                currentScanResult = data;
                renderResults(data);
            } catch (err) {
                clearInterval(stepInterval);
                renderError(targetUrl, 'Failed to connect to local scanner engine: ' + err.message);
            } finally {
                scanBtn.disabled = false;
                loaderBox.style.display = 'none';
                resultsContainer.style.display = 'block';
                resultsContainer.scrollIntoView({ behavior: 'smooth' });
            }
        }

        function getGradeStyle(grade) {
            const styles = {
                'A': { bg: 'rgba(16, 185, 129, 0.15)', border: '#10b981', text: '#34d399', glow: 'rgba(16, 185, 129, 0.4)' },
                'B': { bg: 'rgba(14, 165, 233, 0.15)', border: '#0ea5e9', text: '#38bdf8', glow: 'rgba(14, 165, 233, 0.4)' },
                'C': { bg: 'rgba(245, 158, 11, 0.15)', border: '#f59e0b', text: '#fbbf24', glow: 'rgba(245, 158, 11, 0.4)' },
                'D': { bg: 'rgba(249, 115, 22, 0.15)', border: '#f97316', text: '#fb923c', glow: 'rgba(249, 115, 22, 0.4)' },
                'F': { bg: 'rgba(239, 68, 68, 0.15)', border: '#ef4444', text: '#f87171', glow: 'rgba(239, 68, 68, 0.4)' }
            };
            return styles[grade] || styles['F'];
        }

        function renderResults(result) {
            const container = document.getElementById('resultsContainer');

            if (result.error) {
                container.innerHTML = `
                    <div class="result-card">
                        <div class="error-alert">
                            <h4>
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                                Target Unreachable / Network Timeout
                            </h4>
                            <p>${escapeHtml(result.error)}</p>
                        </div>
                        <p style="font-size: 0.85rem; color: var(--text-muted);">
                            The scanner attempted to contact <strong>${escapeHtml(result.target_url)}</strong> with a 10s timeout, but the host was unreachable or connection timed out. Verify your internet connection or check if the target is online.
                        </p>
                    </div>
                `;
                return;
            }

            const findings = result.findings || [];
            const highCount = findings.filter(f => f.severity === 'HIGH').length;
            const medCount = findings.filter(f => f.severity === 'MEDIUM').length;
            const lowCount = findings.filter(f => f.severity === 'LOW').length;
            const gradeStyle = getGradeStyle(result.grade);

            let findingsRows = '';
            findings.forEach(f => {
                const badgeCls = f.severity === 'HIGH' ? 'badge-high' : (f.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low');
                findingsRows += `
                    <tr class="finding-row severity-${f.severity.toLowerCase()}">
                        <td style="width: 100px;">
                            <span class="badge ${badgeCls}">${f.severity}</span>
                            <div class="cat-tag">${escapeHtml(f.category || 'General')}</div>
                        </td>
                        <td style="width: 34%;">
                            <div class="vuln-title">${escapeHtml(f.title)}</div>
                            <div class="vuln-desc">${escapeHtml(f.description)}</div>
                            <div class="owasp-pill">${escapeHtml(f.owasp_ref || 'A05:2021')}</div>
                        </td>
                        <td style="width: 28%;">
                            <div class="evidence-box"><code>${escapeHtml(f.evidence)}</code></div>
                        </td>
                        <td style="width: 30%;">
                            <div class="remedy-box">
                                <div class="remedy-label">Remediation:</div>
                                <pre><code>${escapeHtml(f.remediation)}</code></pre>
                            </div>
                        </td>
                    </tr>
                `;
            });

            container.innerHTML = `
                <div class="result-card">
                    <div class="result-header">
                        <div class="target-meta">
                            <h3>${escapeHtml(result.target_url)}</h3>
                            <div class="meta-tags">
                                <span class="meta-tag">Final URL: <code>${escapeHtml(result.final_url)}</code></span>
                                <span class="meta-tag">Status: <code>${result.status_code}</code></span>
                                <span class="meta-tag">Latency: <code>${result.response_time_ms.toFixed(0)}ms</code></span>
                                <span class="meta-tag">IP: <code>${escapeHtml(result.ip_address || 'N/A')}</code></span>
                            </div>
                        </div>
                        <div class="score-badge" style="background:${gradeStyle.bg}; border-color:${gradeStyle.border}; box-shadow: 0 0 25px ${gradeStyle.glow};">
                            <div class="score-num" style="color:${gradeStyle.text};">${result.score}<span>/100</span></div>
                            <div class="grade-text" style="color:${gradeStyle.text};">GRADE ${result.grade}</div>
                        </div>
                    </div>

                    <!-- KPI Cards -->
                    <div class="kpi-grid">
                        <div class="kpi-card high">
                            <div class="kpi-title">High Risk</div>
                            <div class="kpi-val" style="color: var(--severity-high);">${highCount}</div>
                        </div>
                        <div class="kpi-card med">
                            <div class="kpi-title">Medium Risk</div>
                            <div class="kpi-val" style="color: var(--severity-med);">${medCount}</div>
                        </div>
                        <div class="kpi-card low">
                            <div class="kpi-title">Low Risk</div>
                            <div class="kpi-val" style="color: var(--severity-low);">${lowCount}</div>
                        </div>
                        <div class="kpi-card status">
                            <div class="kpi-title">Total Findings</div>
                            <div class="kpi-val" style="color: var(--accent-cyan);">${findings.length}</div>
                        </div>
                    </div>

                    <!-- Toolbar -->
                    <div class="toolbar">
                        <div class="filter-group">
                            <button class="filter-btn active" onclick="filterFindings('all', this)">All (${findings.length})</button>
                            <button class="filter-btn" onclick="filterFindings('high', this)">High (${highCount})</button>
                            <button class="filter-btn" onclick="filterFindings('medium', this)">Medium (${medCount})</button>
                            <button class="filter-btn" onclick="filterFindings('low', this)">Low (${lowCount})</button>
                        </div>
                        <div class="action-btns">
                            <button class="btn-secondary" onclick="exportJson()">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                Export JSON
                            </button>
                        </div>
                    </div>

                    <!-- Findings Table -->
                    ${findings.length === 0 ? `
                        <div style="text-align: center; padding: 40px; color: #10b981;">
                            <h3>No Security Misconfigurations Found!</h3>
                            <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 6px;">All inspected security headers, cookies, and CORS parameters meet recommended security baselines.</p>
                        </div>
                    ` : `
                        <div class="table-responsive">
                            <table class="findings-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Issue &amp; OWASP Ref</th>
                                        <th>Observed Technical Evidence</th>
                                        <th>How to Fix (Remediation)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${findingsRows}
                                </tbody>
                            </table>
                        </div>
                    `}
                </div>
            `;
        }

        function renderError(url, message) {
            const container = document.getElementById('resultsContainer');
            container.innerHTML = `
                <div class="result-card">
                    <div class="error-alert">
                        <h4>Scanner Error</h4>
                        <p>${escapeHtml(message)}</p>
                    </div>
                </div>
            `;
        }

        function filterFindings(sev, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {
                if (sev === 'all' || row.classList.contains('severity-' + sev)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        function exportJson() {
            if (!currentScanResult) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanResult, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", "scan_result.json");
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    </script>
</body>
</html>
"""


class ScannerWebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the interactive web scanner application."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging to keep terminal clean."""
        sys.stdout.write(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}\n")

    def do_GET(self) -> None:
        """Handle GET requests: serve the web GUI or health check."""
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_UI_PAGE.encode("utf-8"))
        elif parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "web-scanner"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self) -> None:
        """Handle POST requests: execute live target scan."""
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                payload = json.loads(body.decode("utf-8"))
                target_url = payload.get("url", "").strip()

                if not target_url:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Target URL is required."}).encode("utf-8"))
                    return

                # Execute audit using core SecurityAuditEngine
                engine = SecurityAuditEngine(timeout=10)
                scan_result = engine.audit_target(target_url)

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(scan_result, indent=2).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Internal scan error: {str(e)}"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def start_server(port: int = DEFAULT_PORT, auto_open: bool = True) -> None:
    """Launch the interactive web application server."""
    enable_windows_ansi()
    server_address = ("127.0.0.1", port)
    
    try:
        httpd = HTTPServer(server_address, ScannerWebHandler)
    except OSError:
        # If port 5000 is occupied, find next available port
        port += 1
        server_address = ("127.0.0.1", port)
        httpd = HTTPServer(server_address, ScannerWebHandler)

    url = f"http://127.0.0.1:{port}"

    print(f"\n{'='*75}")
    print(f" [+] Automated Web Scanner - Interactive Web Console Active!")
    print(f" [*] Local Web Interface: {url}")
    print(f" [*] Open the link above in your browser to type and audit any URL.")
    print(f" [*] Press Ctrl+C in this terminal to stop the server.")
    print(f"{'='*75}\n")

    if auto_open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopping Web Scanner Server...")
        httpd.server_close()
        print("[+] Server stopped successfully.")


if __name__ == "__main__":
    from datetime import datetime
    enable_windows_ansi()
    port = DEFAULT_PORT
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    start_server(port=port, auto_open=True)
