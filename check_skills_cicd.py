#!/usr/bin/env python3
"""
check_skills_cicd.py - Trakr skills architecture vs. CI/CD pipeline checker.

What it does
------------
1. Holds the Trakr skills registry (21 categories, 174 sub-skills). Each skill is
   mapped to the CI "gate" that should automatically verify it (or to None when
   it can only be checked manually / on a device).
2. Reads the GitHub Actions workflows in <repo>/.github/workflows and detects
   which gates the pipeline actually runs.
3. Reports, per skill and per category, whether the pipeline COVERS it, has a
   GAP for it, or whether it is MANUAL.
4. Runs pipeline hygiene checks (PR trigger, deploy gating, permissions,
   pinned actions, timeouts, FTP protocol, hard-coded secrets, ...).
5. Inspects the public web/ folder for SEO, structured-data, AI-crawler and
   security-header readiness (robots.txt, sitemap, JSON-LD, GPTBot rules, ...).
6. Exits non-zero so it can be used as a CI step itself.

Usage
-----
  python check_skills_cicd.py --repo /path/to/Trakr
  python check_skills_cicd.py --repo . --format markdown > report.md
  python check_skills_cicd.py --repo . --min-coverage 60 --fail-on-hygiene
  python check_skills_cicd.py --repo . --suggest          # YAML for missing gates
  python check_skills_cicd.py --repo . --web-dir build/web   # check a built site
  python check_skills_cicd.py --repo . --fail-on-web      # fail on web FAIL results
  python check_skills_cicd.py --self-test                 # validate the registry only
  python check_skills_cicd.py --export-registry skills.json

Exit codes: 0 ok | 1 threshold/hygiene failure | 2 usage or I/O error

Requires Python 3.8+. PyYAML is optional (enables job-level hygiene checks).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

# --------------------------------------------------------------------------- #
# 1. GATES: what a pipeline step must look like to count as a given check
# --------------------------------------------------------------------------- #
# A step is (text, working_directory). `text` is the step's run/uses/with text.

Step = Tuple[str, str]


def _rx(pattern: str) -> Callable[[Step], bool]:
    compiled = re.compile(pattern, re.I | re.S)
    return lambda step: bool(compiled.search(step[0]))


def _in_functions(pattern: str) -> Callable[[Step], bool]:
    compiled = re.compile(pattern, re.I | re.S)

    def check(step: Step) -> bool:
        text, wd = step
        scoped = "functions" in wd.lower() or re.search(r"--prefix\s+\S*functions|cd\s+functions", text, re.I)
        return bool(scoped and compiled.search(text))

    return check


GATES: "OrderedDict[str, dict]" = OrderedDict(
    {
        "analyze": {
            "title": "Static analysis (flutter/dart analyze)",
            "match": _rx(r"\b(flutter|dart)\s+analyze\b"),
            "snippet": "- name: Analyze\n  run: flutter analyze --fatal-infos",
        },
        "format": {
            "title": "Format check (dart format)",
            "match": _rx(r"dart\s+format\b.*(--set-exit-if-changed|-o\s+none)"),
            "snippet": "- name: Check formatting\n  run: dart format --output=none --set-exit-if-changed lib test",
        },
        "test": {
            "title": "Unit & widget tests (flutter test)",
            "match": _rx(r"\bflutter\s+test\b(?!.*integration_test)"),
            "snippet": "- name: Test\n  run: flutter test --coverage",
        },
        "coverage": {
            "title": "Coverage collection / threshold",
            "match": _rx(r"--coverage|lcov|codecov|coveralls"),
            "snippet": "- name: Test with coverage\n  run: flutter test --coverage\n- uses: codecov/codecov-action@v4",
        },
        "integration_test": {
            "title": "Integration tests (integration_test / flutter drive)",
            "match": _rx(r"integration_test|flutter\s+drive"),
            "snippet": "- name: Integration tests\n  run: flutter test integration_test -d chrome",
        },
        "build_web": {
            "title": "Flutter web release build",
            "match": _rx(r"flutter\s+build\s+web"),
            "snippet": "- run: flutter build web --release",
        },
        "build_apk": {
            "title": "Android build (apk / appbundle)",
            "match": _rx(r"flutter\s+build\s+(apk|appbundle)"),
            "snippet": "- run: flutter build apk --debug",
        },
        "functions_build": {
            "title": "Cloud Functions TypeScript build",
            "match": _in_functions(r"npm\s+(ci|install|run\s+build)|\btsc\b"),
            "snippet": "- name: Build functions\n  working-directory: functions\n  run: npm ci && npm run build",
        },
        "functions_lint": {
            "title": "Cloud Functions lint",
            "match": _in_functions(r"npm\s+run\s+lint|eslint"),
            "snippet": "- name: Lint functions\n  working-directory: functions\n  run: npm run lint",
        },
        "functions_test": {
            "title": "Cloud Functions tests",
            "match": _in_functions(r"npm\s+(run\s+)?test|jest|mocha|vitest"),
            "snippet": "- name: Test functions\n  working-directory: functions\n  run: npm test",
        },
        "rules_test": {
            "title": "Firestore rules emulator tests",
            "match": _rx(r"emulators:exec|rules-unit-testing|firebase\s+emulators:start"),
            "snippet": "- name: Rules tests\n  run: npx firebase emulators:exec --only firestore 'npm --prefix scripts test'",
        },
        "secrets_scan": {
            "title": "Secret scanning (gitleaks / trufflehog)",
            "match": _rx(r"gitleaks|trufflehog|detect-secrets"),
            "snippet": "- uses: gitleaks/gitleaks-action@v2",
        },
        "dep_audit": {
            "title": "Dependency audit (npm audit / osv / pub outdated)",
            "match": _rx(r"npm\s+audit|osv-scanner|flutter\s+pub\s+outdated|dependabot|dart\s+pub\s+outdated"),
            "snippet": "- run: flutter pub outdated\n- run: npm --prefix functions audit --audit-level=high",
        },
        "code_metrics": {
            "title": "Complexity / file-size metrics",
            "match": _rx(r"\bdcm\b|dart_code_metrics|code_metrics|cloc|wc\s+-l"),
            "snippet": "- name: Large file guard\n  run: find lib -name '*.dart' -size +120k -print -exec false {} +",
        },
        "policy_check": {
            "title": "Repo policy checks (custom script)",
            "match": _rx(r"scripts/\S*(policy|check)\S*|python3?\s+\S*check_skills\S*|firebase_storage"),
            "snippet": "- name: Repo policy checks\n  run: python3 scripts/check_skills_cicd.py --repo . --min-coverage 60",
        },
        "workflow_lint": {
            "title": "Workflow linting (actionlint)",
            "match": _rx(r"actionlint"),
            "snippet": "- uses: raven-actions/actionlint@v2",
        },
        "bundle_size": {
            "title": "Web bundle size budget",
            "match": _rx(r"main\.dart\.js.*(stat|du|wc)|(stat|du|wc).*main\.dart\.js|bundlesize|size-limit"),
            "snippet": "- run: test $(stat -c%s build/web/main.dart.js) -lt 3500000",
        },
        "lighthouse": {
            "title": "Lighthouse / pa11y (performance + accessibility)",
            "match": _rx(r"lighthouse|lhci|pa11y|axe-core"),
            "snippet": "- uses: treosh/lighthouse-ci-action@v12\n  with:\n    configPath: .lighthouserc.json",
        },
        "sast": {
            "title": "Static application security testing (CodeQL / Semgrep)",
            "match": _rx(r"codeql|semgrep|snyk|sonarcloud|sonarqube"),
            "snippet": "- uses: github/codeql-action/init@v3\n  with:\n    languages: javascript-typescript\n- uses: github/codeql-action/analyze@v3",
        },
        "dast": {
            "title": "Dynamic scan (OWASP ZAP baseline / nuclei)",
            "match": _rx(r"zaproxy|zap-baseline|zap-full|owasp[-/ ]zap|nuclei"),
            "snippet": "- uses: zaproxy/action-baseline@v0.12.0\n  with:\n    target: https://YOUR-STAGING-DOMAIN",
        },
        "load_test": {
            "title": "Load / query-latency test (k6, artillery)",
            "match": _rx(r"\bk6\b|artillery|locust|jmeter"),
            "snippet": "- uses: grafana/k6-action@v0.3.1\n  with:\n    filename: tests/load/checkin.js",
        },
        "seo_audit": {
            "title": "SEO / crawl audit (lighthouse seo, link checker, sitemap)",
            "match": _rx(r"lhci.*seo|lighthouse.*seo|linkinator|broken-link|lychee|seo[-_ ]?(audit|check)|sitemap|robots\.txt"),
            "snippet": "- name: SEO + link check\n  run: npx linkinator https://YOUR-DOMAIN --recurse --skip 'login'",
        },
        "schema_validate": {
            "title": "Structured data / JSON-LD validation",
            "match": _rx(r"schema[-_ ]?(validat|org)|json[-_ ]?ld|structured[-_ ]data"),
            "snippet": "- name: Validate JSON-LD\n  run: python3 scripts/validate_jsonld.py web/index.html",
        },
        "ai_crawler": {
            "title": "AI crawler access check (GPTBot, ClaudeBot, PerplexityBot, llms.txt)",
            "match": _rx(r"ai[-_ ]?crawler|gptbot|claudebot|perplexitybot|google-extended|llms\.txt"),
            "snippet": "- name: AI crawler access\n  run: python3 scripts/check_ai_crawlers.py --url https://YOUR-DOMAIN",
        },
        "ai_visibility": {
            "title": "Scheduled AI-visibility probe (ChatGPT, Perplexity, Gemini, Claude)",
            "match": _rx(r"ai[-_ ]?visibility|visibility[-_ ]?probe|geo[-_ ]?audit|\baeo\b"),
            "snippet": "# separate workflow, on: schedule (weekly)\n- name: AI visibility probe\n  run: python3 scripts/ai_visibility_probe.py --brand TRAKR --out report.json\n  env:\n    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}",
        },
        "functional_test": {
            "title": "Functional / end-to-end tests (integration_test, Playwright, Patrol)",
            "match": _rx(r"integration_test|flutter\s+drive|playwright|cypress|patrol|maestro"),
            "snippet": "- name: Functional tests\n  run: flutter test integration_test -d chrome",
        },
        "deploy_verify": {
            "title": "Post-deploy smoke test / header check",
            "match": _rx(r"\bcurl\b.*(-I|--head|--fail|-f)\b|smoke"),
            "snippet": "- name: Smoke test\n  run: curl --fail --silent --head https://YOUR-DOMAIN/ | grep -i x-content-type-options",
        },
        "deploy_gate": {
            "title": "Deploy gated by tests / environment approval",
            "match": None,  # evaluated structurally, see check_deploy_gate()
            "snippet": "deploy:\n  needs: [verify]\n  environment: production",
        },
    }
)

# --------------------------------------------------------------------------- #
# 2. REGISTRY: category -> [(skill name, gate or None)]
# --------------------------------------------------------------------------- #
REGISTRY: "OrderedDict[str, List[Tuple[str, Optional[str]]]]" = OrderedDict(
    {
        "Attendance Logic Audit": [
            ("Check-In / Check-Out State Machine Validator", "test"),
            ("Temp Exit & Re-Entry Flow Checker", "test"),
            ("Unauthorized Exit Detection", "test"),
            ("Absence Threshold Checker (Half-Day 180 / Full-Day 360 min)", "test"),
            ("Missed Checkout Sync Verifier", "functions_test"),
            ("Duplicate Check-In Prevention", "test"),
            ("Attendance Log Immutability Checker", "rules_test"),
            ("Weekend & Holiday Rule Validator", "test"),
            ("Timezone & Date Boundary Checker", "test"),
        ],
        "QR Token Audit": [
            ("QR Payload Format Validator (JSON & Query String)", "test"),
            ("Token Expiry & Rotation Checker", "functions_test"),
            ("Token Replay Detection", "test"),
            ("Cross-Tenant Token Isolation", "rules_test"),
            ("Live QR Widget Refresh Checker", "test"),
            ("Scanner Permission & Fallback Checker", "test"),
            ("qr_tokens Rules Checker", "rules_test"),
        ],
        "Geofence & Location Audit": [
            ("Radius Calculation Verifier (50 m Default)", "test"),
            ("GPS Accuracy & Safety Margin Checker", "test"),
            ("Office Geo-Config Validator", "test"),
            ("Mock Location / Spoofing Detection", None),
            ("Location Permission Handling", "integration_test"),
            ("Map Tile Provider Checker", None),
            ("Geo-Tag Screen Validator", "test"),
        ],
        "Leave, Permission & Approval Workflow": [
            ("Leave Request Lifecycle Tester", "test"),
            ("Leave Balance Calculator Verifier", "test"),
            ("Approval Chain Validator", "test"),
            ("Step-Out Permission Request Checker", "test"),
            ("Checkout Request Workflow Tester", "test"),
            ("Holiday Calendar Conflict Detector", "test"),
            ("Leave Policy Validator", "test"),
            ("Reporting Hierarchy Consistency Checker", "test"),
        ],
        "Payroll & Reporting Audit": [
            ("Payroll Calculation Verifier", "test"),
            ("Monthly Analysis Accuracy Checker", "test"),
            ("Dashboard Stats Consistency Checker", "test"),
            ("CSV Export Validator", "test"),
            ("Excel Export Validator", "test"),
            ("PDF Report Validator", "test"),
            ("Weekly Trend Chart Data Checker", "test"),
        ],
        "Multi-Tenant & Workspace Provisioning": [
            ("Tenant Isolation Tester", "rules_test"),
            ("Workspace Provisioning Pipeline Checker", "functions_test"),
            ("Firebase Config Parser & Validator", "test"),
            ("Tenant Seeder Verifier", "test"),
            ("Tenant Rules Deployment Verifier", "functions_build"),
            ("Orphaned Tenant Project Auditor", "functions_test"),
            ("Workspace Deletion Safety Checker", "functions_test"),
            ("Super Admin Claim Verifier", "rules_test"),
            ("Cross-Project Analytics Validator", "test"),
            ("White-Label Config Validator", "test"),
        ],
        "Security & Firestore Rules Audit": [
            ("Firestore Rules Static Analyzer", "rules_test"),
            ("Privilege Escalation Guard Tester", "rules_test"),
            ("Catch-All Deny Verifier", "rules_test"),
            ("Row-Level Authorization Checker", "rules_test"),
            ("Hardcoded Secrets Scanner", "secrets_scan"),
            ("Service Account & IAM Roles Auditor", None),
            ("Auth Session & Role Cache Checker", "test"),
            ("Security Headers Checker", "deploy_verify"),
            ("Dependency Vulnerability Scanner", "dep_audit"),
            ("Bootstrap Admin Trust Anchor Checker", "rules_test"),
        ],
        "Notifications & Cloud Functions Audit": [
            ("FCM Foreground / Background Handler Tester", "test"),
            ("Local Notification Checker", "test"),
            ("Scheduled Cron Function Verifier", "functions_test"),
            ("Event Dedupe Checker", "functions_test"),
            ("Callable Function Auth Checker", "functions_test"),
            ("Credential Email Delivery Checker", "functions_test"),
            ("Anniversary & Festival Greeting Checker", "test"),
            ("Functions Build Freshness Checker", "functions_build"),
        ],
        "Code Quality Audit": [
            ("Static Analysis (flutter analyze)", "analyze"),
            ("Formatting Checker", "format"),
            ("Large File Complexity Analyzer", "code_metrics"),
            ("Dead Code Detection", "analyze"),
            ("String-Matching ID Smell Detector", "code_metrics"),
            ("Provider Usage Checker", "analyze"),
            ("Spark-Plan Constraint Checker (No firebase_storage)", "policy_check"),
            ("Documentation Drift Checker", "policy_check"),
            ("Duplicate Directory Detector", "policy_check"),
        ],
        "Testing & CI/CD Audit": [
            ("Unit Test Runner", "test"),
            ("Widget Test Runner", "test"),
            ("Integration Test Runner", "integration_test"),
            ("Firestore Rules Emulator Tests", "rules_test"),
            ("Cloud Functions Tests", "functions_test"),
            ("Test Coverage Analyzer", "coverage"),
            ("Workflow Syntax Validator", "workflow_lint"),
            ("Multi-Platform Build Matrix", "build_apk"),
            ("Deploy Gate & Approval Checker", "deploy_gate"),
            ("Post-Deploy Smoke Test", "deploy_verify"),
        ],
        "Platform, Performance & Accessibility": [
            ("Flutter Web Bundle Size Analyzer", "bundle_size"),
            ("Web Bootstrap / First Load Checker", "lighthouse"),
            ("Firestore Index Coverage Checker", "policy_check"),
            ("Stream Listener Leak Detector", "test"),
            ("Base64 Image Size Limit Checker (1 MiB Doc Cap)", "test"),
            ("Responsive Layout Tester", "test"),
            ("Accessibility Semantics Checker", "lighthouse"),
            ("Browser Compatibility Checker", None),
            ("Android / iOS Permission Manifest Checker", "build_apk"),
        ],
        "Performance Audit": [
            ("Core Web Vitals Monitor (LCP / INP / CLS)", "lighthouse"),
            ("Flutter Web First-Paint & Bootstrap Timing", "lighthouse"),
            ("Main Bundle & Compression Budget (main.dart.js)", "bundle_size"),
            ("Firestore Query Latency & Read-Cost Analyzer", "load_test"),
            ("Concurrent Check-In Load Test (Peak Morning Rush)", "load_test"),
            ("Mobile App Startup & Frame-Jank Profiler", None),
            ("Caching & Static Asset Header Checker", "deploy_verify"),
        ],
        "Web Application Security Audit": [
            ("Security Headers & CSP Enforcer", "deploy_verify"),
            ("HTTPS & HSTS Enforcement Checker", "deploy_verify"),
            ("Google Sign-In & Session Token Security Tester", "test"),
            ("Firebase API Key & Config Exposure Checker", "secrets_scan"),
            ("XSS & Injection Surface Scanner (Web Layer)", "dast"),
            ("Callable Function Abuse & Rate-Limit Tester", "functions_test"),
            ("QR Token Brute-Force Resistance Tester", "test"),
            ("PII & Sensitive Data Exposure Detector", "policy_check"),
        ],
        "Vulnerability Assessment": [
            ("Pub & npm CVE Lockfile Scanner", "dep_audit"),
            ("Outdated Package Detection", "dep_audit"),
            ("Static Application Security Testing (SAST)", "sast"),
            ("Dynamic Scan (OWASP ZAP Baseline)", "dast"),
            ("Exposed File & Directory Detector (.env, Service Accounts)", "secrets_scan"),
            ("Firestore Rules Misconfiguration Scanner", "rules_test"),
            ("OWASP Top 10 Mapping Report", "sast"),
            ("Risk Scoring & Severity Classification", "policy_check"),
        ],
        "Critical Bug & Error Detection": [
            ("Flutter Runtime Exception Detector", "test"),
            ("Unhandled Async Error Detector", "analyze"),
            ("Firestore Permission-Denied Monitor", "rules_test"),
            ("Check-In Critical Path Smoke Test", "functional_test"),
            ("Cloud Function Error-Rate Monitor", None),
            ("Crash Reporting Integration Checker", None),
            ("Data Integrity Checker (Orphan & Duplicate Records)", "functions_test"),
            ("Critical Bug Severity Triage", "policy_check"),
        ],
        "Technical SEO & Crawler Audit": [
            ("Flutter Web Crawlability Checker (Canvas vs HTML Render)", "seo_audit"),
            ("robots.txt Checker", "seo_audit"),
            ("sitemap.xml Checker", "seo_audit"),
            ("Title & Meta Description Analyzer", "seo_audit"),
            ("Canonical URL Checker", "seo_audit"),
            ("Heading Structure Analyzer", "seo_audit"),
            ("Broken Link Checker", "seo_audit"),
            ("Indexability Checker (noindex on Auth Pages)", "seo_audit"),
            ("Open Graph & Social Card Checker", "seo_audit"),
            ("Mobile Viewport & Redirect Checker", "seo_audit"),
        ],
        "Schema & Structured Data Audit": [
            ("JSON-LD Syntax Validator", "schema_validate"),
            ("Organization Schema Checker", "schema_validate"),
            ("SoftwareApplication Schema Checker", "schema_validate"),
            ("WebSite & WebPage Schema Checker", "schema_validate"),
            ("FAQPage Schema Checker", "schema_validate"),
            ("Breadcrumb Schema Checker", "schema_validate"),
            ("Rich Results Eligibility Tester", None),
        ],
        "Local SEO Audit": [
            ("Google Business Profile Consistency Checker", None),
            ("NAP (Name, Address, Phone) Consistency Checker", None),
            ("LocalBusiness Schema Checker", "schema_validate"),
            ("Local Landing Page Checker (City / Region Pages)", "seo_audit"),
            ("Review & Rating Markup Checker", "schema_validate"),
            ("Local Keyword Coverage Analyzer", None),
        ],
        "AI Visibility Audit (AEO / GEO)": [
            ("ChatGPT Visibility Checker", "ai_visibility"),
            ("Perplexity Visibility Checker", "ai_visibility"),
            ("Gemini Visibility Checker", "ai_visibility"),
            ("Claude Visibility Checker", "ai_visibility"),
            ("Google AI Overviews Visibility", "ai_visibility"),
            ("Brand Mention Tracking", "ai_visibility"),
            ("AI Citation Tracking", "ai_visibility"),
            ("Entity Recognition Analysis", "ai_visibility"),
            ("AI Crawler Access Checker (GPTBot, ClaudeBot, PerplexityBot)", "ai_crawler"),
            ("llms.txt & AI-Readable Content Checker", "ai_crawler"),
            ("Server-Rendered Content for AI Crawlers", "ai_crawler"),
        ],
        "Unit Testing": [
            ("Service Logic Unit Tests (Attendance, Leave, Payroll)", "test"),
            ("Model Serialization Tests (toMap / fromMap)", "test"),
            ("Provider & State Tests", "test"),
            ("Firestore Mock Tests (Fake Firestore)", "test"),
            ("Cloud Functions Unit Tests", "functions_test"),
            ("Coverage Threshold Enforcer", "coverage"),
            ("Flaky Test Detector", "test"),
        ],
        "Functional Testing": [
            ("Login & Role-Dispatch Flow Test", "functional_test"),
            ("QR Scan Check-In / Check-Out Flow Test", "functional_test"),
            ("Leave Request & Approval Flow Test", "functional_test"),
            ("Manager Team & Reports-To Flow Test", "functional_test"),
            ("Tenant Onboarding & Provisioning Flow Test", "functional_test"),
            ("Report Export Flow Test (CSV / Excel / PDF)", "functional_test"),
            ("White-Label Branding Flow Test", "functional_test"),
            ("Regression Suite Runner", "functional_test"),
        ],
    }
)

ROADMAP: "OrderedDict[str, List[str]]" = OrderedDict(
    {
        "Stage 1": [
            "Attendance Logic Audit",
            "QR Token Audit",
            "Geofence & Location Audit",
            "Security & Firestore Rules Audit",
            "Testing & CI/CD Audit",
            "Web Application Security Audit",
            "Vulnerability Assessment",
            "Critical Bug & Error Detection",
            "Unit Testing",
        ],
        "Stage 2": [
            "Multi-Tenant & Workspace Provisioning",
            "Leave, Permission & Approval Workflow",
            "Notifications & Cloud Functions Audit",
            "Code Quality Audit",
            "Performance Audit",
            "Functional Testing",
            "Technical SEO & Crawler Audit",
            "Schema & Structured Data Audit",
        ],
        "Stage 3": [
            "Payroll & Reporting Audit",
            "Platform, Performance & Accessibility",
            "Local SEO Audit",
            "AI Visibility Audit (AEO / GEO)",
        ],
    }
)


def total_skills() -> int:
    return sum(len(v) for v in REGISTRY.values())


# --------------------------------------------------------------------------- #
# 3. Registry self-test
# --------------------------------------------------------------------------- #
def self_test() -> List[str]:
    problems: List[str] = []
    seen = set()
    for cat, skills in REGISTRY.items():
        if not skills:
            problems.append(f"Category '{cat}' has no skills")
        for name, gate in skills:
            if name in seen:
                problems.append(f"Duplicate skill name: {name}")
            seen.add(name)
            if gate is not None and gate not in GATES:
                problems.append(f"Skill '{name}' references unknown gate '{gate}'")
    in_roadmap = [c for cats in ROADMAP.values() for c in cats]
    for c in REGISTRY:
        if c not in in_roadmap:
            problems.append(f"Category '{c}' missing from ROADMAP")
    for c in in_roadmap:
        if c not in REGISTRY:
            problems.append(f"ROADMAP references unknown category '{c}'")
    if len(in_roadmap) != len(set(in_roadmap)):
        problems.append("A category appears in more than one roadmap stage")
    return problems


# --------------------------------------------------------------------------- #
# 4. Workflow loading
# --------------------------------------------------------------------------- #
class Workflow:
    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_text(encoding="utf-8", errors="replace")
        self.data: Optional[dict] = None
        self.parse_error: Optional[str] = None
        if yaml is not None:
            try:
                loaded = yaml.safe_load(self.raw)
                self.data = loaded if isinstance(loaded, dict) else None
                if self.data is None:
                    self.parse_error = "top level is not a mapping"
            except yaml.YAMLError as exc:  # type: ignore[attr-defined]
                self.parse_error = str(exc).splitlines()[0]

    # `on:` is parsed as boolean True by YAML 1.1
    @property
    def triggers(self) -> dict:
        if not self.data:
            return {}
        on = self.data.get("on", self.data.get(True))
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {k: None for k in on}
        return on if isinstance(on, dict) else {}

    @property
    def jobs(self) -> dict:
        return (self.data or {}).get("jobs", {}) or {}

    def steps(self) -> List[Step]:
        """Flattened (text, working-directory) for every step."""
        out: List[Step] = []
        if self.data:
            for job in self.jobs.values():
                job_wd = ((job.get("defaults") or {}).get("run") or {}).get("working-directory", "") or ""
                for st in job.get("steps", []) or []:
                    text = " ".join(
                        str(x)
                        for x in (st.get("name", ""), st.get("uses", ""), st.get("run", ""),
                                  json.dumps(st.get("with", {})))
                    )
                    out.append((text, str(st.get("working-directory", job_wd) or "")))
            return out
        # Fallback without PyYAML: split on step markers
        body = "\n".join(l for l in self.raw.splitlines() if not l.strip().startswith("#"))
        for chunk in re.split(r"\n\s*-\s+(?=(?:name|uses|run):)", body):
            m = re.search(r"working-directory:\s*(\S+)", chunk)
            out.append((chunk, m.group(1) if m else ""))
        return out


def load_workflows(wf_dir: Path) -> List[Workflow]:
    if not wf_dir.is_dir():
        return []
    files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    return [Workflow(p) for p in files]


# --------------------------------------------------------------------------- #
# 5. Gate detection
# --------------------------------------------------------------------------- #
DEPLOY_RX = re.compile(r"ftp-deploy|firebase\s+deploy|firebase-tools|deploy-pages|rsync|scp\s", re.I)
VERIFY_RX = re.compile(r"\b(flutter\s+(analyze|test)|npm\s+(test|run\s+(test|lint)))\b", re.I)


def check_deploy_gate(workflows: List[Workflow]) -> Tuple[bool, str]:
    """Every deploy job must `needs` a job that verifies code, or use `environment`."""
    deploy_jobs = 0
    gated = 0
    detail = []
    for wf in workflows:
        if not wf.data:
            continue
        for name, job in wf.jobs.items():
            text = json.dumps(job.get("steps", []))
            if not DEPLOY_RX.search(text):
                continue
            deploy_jobs += 1
            needs = job.get("needs")
            needs = [needs] if isinstance(needs, str) else (needs or [])
            verified_dep = any(
                VERIFY_RX.search(json.dumps(wf.jobs.get(n, {}).get("steps", []))) for n in needs
            )
            if verified_dep or job.get("environment"):
                gated += 1
            else:
                detail.append(f"{wf.path.name}:{name}")
    if deploy_jobs == 0:
        return False, "no deploy job found"
    if gated == deploy_jobs:
        return True, f"{gated} deploy job(s) gated"
    return False, "ungated deploy job(s): " + ", ".join(detail)


def detect_gates(workflows: List[Workflow]) -> Dict[str, Tuple[bool, str]]:
    steps: List[Step] = [s for wf in workflows for s in wf.steps()]
    result: Dict[str, Tuple[bool, str]] = {}
    for gid, g in GATES.items():
        if gid == "deploy_gate":
            result[gid] = check_deploy_gate(workflows)
            continue
        hit = next((s for s in steps if g["match"](s)), None)
        result[gid] = (hit is not None, "detected" if hit else "not found in any workflow")
    return result


# --------------------------------------------------------------------------- #
# 6. Pipeline hygiene checks
# --------------------------------------------------------------------------- #
PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
SECRET_LITERAL_RX = re.compile(
    r"(password|passwd|secret|token|api[_-]?key)\s*:\s*['\"]?(?!\$\{\{)[A-Za-z0-9/+=_\-]{8,}", re.I
)


def hygiene_checks(workflows: List[Workflow], repo: Path) -> List[Tuple[str, str, str]]:
    res: List[Tuple[str, str, str]] = []
    if not workflows:
        return [("Workflow files exist", FAIL, "no .github/workflows/*.yml found")]
    res.append(("Workflow files exist", PASS, ", ".join(w.path.name for w in workflows)))

    bad = [w.path.name for w in workflows if w.parse_error]
    if bad:
        res.append(("Workflows parse as YAML", FAIL, "; ".join(f"{w.path.name}: {w.parse_error}" for w in workflows if w.parse_error)))
    structured = yaml is not None and all(w.data for w in workflows)
    if not structured:
        res.append(("Structured checks", SKIP, "PyYAML missing or workflow unparsable - install pyyaml for job-level checks"))

    # Raw-text checks
    for w in workflows:
        if SECRET_LITERAL_RX.search("\n".join(l for l in w.raw.splitlines() if not l.strip().startswith("#"))):
            res.append((f"No literal secrets ({w.path.name})", FAIL, "value looks hard-coded; use ${{ secrets.NAME }}"))
        else:
            res.append((f"No literal secrets ({w.path.name})", PASS, ""))
        if re.search(r"protocol:\s*ftp\s*$", w.raw, re.I | re.M):
            res.append((f"Encrypted transfer ({w.path.name})", FAIL, "plain FTP in use; use ftps/sftp"))
        elif re.search(r"ftp", w.raw, re.I):
            res.append((f"Encrypted transfer ({w.path.name})", PASS, "ftps/sftp"))
        unpinned = re.findall(r"uses:\s*([\w./-]+)@(master|main|latest)\b", w.raw)
        res.append((f"No floating action refs ({w.path.name})", FAIL if unpinned else PASS,
                    ", ".join(f"{a}@{b}" for a, b in unpinned)))
        non_sha = re.findall(r"uses:\s*([\w./-]+)@(v[\w.]+)\s*$", w.raw, re.M)
        third = [f"{a}@{v}" for a, v in non_sha if not a.startswith(("actions/", "./"))]
        if third:
            res.append((f"Third-party actions pinned to SHA ({w.path.name})", WARN,
                        "tag-pinned only: " + ", ".join(third[:4])))
        if re.search(r"flutter-action", w.raw) and not re.search(r"flutter-version", w.raw):
            res.append((f"Flutter version pinned ({w.path.name})", WARN,
                        "only `channel: stable`; builds can change without a commit"))

    if not structured:
        return res

    triggers_all = set().union(*[set(w.triggers) for w in workflows])
    res.append(("Runs on pull_request", PASS if "pull_request" in triggers_all else FAIL,
                "" if "pull_request" in triggers_all else "code reaches master with no pre-merge check"))
    for w in workflows:
        perms = (w.data or {}).get("permissions")
        res.append((f"Least-privilege permissions ({w.path.name})", PASS if perms else WARN,
                    "" if perms else "no top-level `permissions:` block"))
        res.append((f"Concurrency control ({w.path.name})", PASS if (w.data or {}).get("concurrency") else WARN, ""))
        missing_to = [n for n, j in w.jobs.items() if "timeout-minutes" not in j]
        res.append((f"Job timeouts ({w.path.name})", WARN if missing_to else PASS,
                    ("missing on: " + ", ".join(missing_to)) if missing_to else ""))
    ok, detail = check_deploy_gate(workflows)
    res.append(("Deploy gated behind verification", PASS if ok else FAIL, detail))
    return res


# --------------------------------------------------------------------------- #
# 7. Repo facts (informational)
# --------------------------------------------------------------------------- #
def repo_facts(repo: Path) -> List[Tuple[str, str]]:
    tests = [p for p in (repo / "test").rglob("*_test.dart")] if (repo / "test").is_dir() else []
    fn_tests = [p for p in (repo / "functions").rglob("*.test.*") if "node_modules" not in p.parts] if (repo / "functions").is_dir() else []
    rules_tests = list(repo.rglob("*rules*test*")) if repo.is_dir() else []
    rules_tests = [p for p in rules_tests if "node_modules" not in p.parts and ".git" not in p.parts]
    integ = list((repo / "integration_test").rglob("*.dart")) if (repo / "integration_test").is_dir() else []
    return [
        ("Dart test files (test/)", str(len(tests))),
        ("Integration test files", str(len(integ))),
        ("Cloud Functions test files", str(len(fn_tests))),
        ("Firestore rules test files", str(len(rules_tests))),
        ("firestore.rules present", str((repo / "firestore.rules").exists())),
        ("functions/ present", str((repo / "functions").is_dir())),
    ]


# --------------------------------------------------------------------------- #
# 7b. Web readiness: SEO, structured data, AI crawlers, security headers
# --------------------------------------------------------------------------- #
AI_BOTS = ["GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "Claude-Web", "PerplexityBot",
           "Google-Extended", "CCBot"]


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def web_readiness(web_dir: Path) -> List[Tuple[str, str, str]]:
    """Evidence-based checks of the files that are served publicly."""
    if not web_dir.is_dir():
        return [("Web directory", SKIP, f"{web_dir} not found (use --web-dir)")]
    res: List[Tuple[str, str, str]] = []
    html = _read(web_dir / "index.html")
    if not html:
        return [("index.html", FAIL, "missing or empty")]

    def has(rx: str) -> bool:
        return bool(re.search(rx, html, re.I | re.S))

    res.append(("<title> present", PASS if has(r"<title>\s*\S") else FAIL, ""))
    res.append(("Meta description", PASS if has(r"<meta[^>]+name=[\"']description[\"']") else FAIL, ""))
    res.append(("Canonical URL", PASS if has(r"<link[^>]+rel=[\"']canonical[\"']") else WARN, "no <link rel=canonical>"))
    res.append(("Open Graph tags", PASS if has(r"property=[\"']og:title[\"']") else WARN, "no og:title / og:image for social + AI previews"))
    res.append(("JSON-LD structured data", PASS if has(r"application/ld\+json") else WARN,
                "" if has(r"application/ld\+json") else "no Organization / SoftwareApplication schema"))
    res.append(("Not blocked by noindex", FAIL if has(r"<meta[^>]+robots[^>]+noindex") else PASS, ""))
    # Crawlable text: Flutter's canvas renderer leaves the HTML body nearly empty.
    body = re.sub(r"<(script|style)\b.*?</\1>|<!--.*?-->|<[^>]+>", " ", html, flags=re.S | re.I)
    words = len(re.findall(r"[A-Za-z]{3,}", body))
    if words < 40:
        res.append(("Crawlable body text in initial HTML", WARN,
                    f"~{words} words; Flutter web renders to canvas, so crawlers and AI bots see almost nothing. "
                    "Add a static landing page / prerender / <noscript> content"))
    else:
        res.append(("Crawlable body text in initial HTML", PASS, f"~{words} words"))

    robots = _read(web_dir / "robots.txt")
    res.append(("robots.txt", PASS if robots else FAIL, "" if robots else "missing"))
    sitemap_ok = (web_dir / "sitemap.xml").exists()
    res.append(("sitemap.xml", PASS if sitemap_ok else FAIL, "" if sitemap_ok else "missing"))
    if robots:
        res.append(("robots.txt lists sitemap", PASS if re.search(r"^\s*sitemap:", robots, re.I | re.M) else WARN, ""))
        named = [b for b in AI_BOTS if re.search(re.escape(b), robots, re.I)]
        res.append(("AI crawler rules in robots.txt", PASS if named else WARN,
                    ", ".join(named) if named else "no explicit allow/deny for " + ", ".join(AI_BOTS[:4]) + " ..."))
    llms = (web_dir / "llms.txt").exists()
    res.append(("llms.txt", PASS if llms else WARN, "" if llms else "missing (optional, helps AI assistants summarise the product)"))

    ht = _read(web_dir / ".htaccess")
    if not ht:
        res.append((".htaccess / server config", WARN, "not found; verify headers on the live server"))
    else:
        for label, rx, level in [
            ("HSTS header", r"Strict-Transport-Security", WARN),
            ("Content-Security-Policy", r"Content-Security-Policy", WARN),
            ("X-Content-Type-Options", r"X-Content-Type-Options", WARN),
            ("Clickjacking protection (X-Frame-Options / frame-ancestors)", r"X-Frame-Options|frame-ancestors", WARN),
            ("Referrer-Policy", r"Referrer-Policy", WARN),
            ("HTTPS redirect", r"%\{HTTPS\}\s+off|RewriteCond.*HTTPS", FAIL),
            ("Compression (gzip / brotli)", r"mod_deflate|mod_brotli", WARN),
            ("Cache-Control / Expires", r"Cache-Control|mod_expires|ExpiresActive", WARN),
        ]:
            ok = bool(re.search(rx, ht, re.I))
            res.append((label, PASS if ok else level, "" if ok else "not set in .htaccess"))
    return res


# --------------------------------------------------------------------------- #
# 8. Evaluation + rendering
# --------------------------------------------------------------------------- #
def evaluate(gates: Dict[str, Tuple[bool, str]]):
    rows = []
    for cat, skills in REGISTRY.items():
        for name, gate in skills:
            if gate is None:
                status = "MANUAL"
            else:
                status = "COVERED" if gates[gate][0] else "GAP"
            rows.append({"category": cat, "skill": name, "gate": gate, "status": status})
    return rows


def summarize(rows):
    by_cat = OrderedDict((c, {"COVERED": 0, "GAP": 0, "MANUAL": 0}) for c in REGISTRY)
    for r in rows:
        by_cat[r["category"]][r["status"]] += 1
    tot = {"COVERED": 0, "GAP": 0, "MANUAL": 0}
    for v in by_cat.values():
        for k in tot:
            tot[k] += v[k]
    auto = tot["COVERED"] + tot["GAP"]
    pct = round(100 * tot["COVERED"] / auto, 1) if auto else 0.0
    return by_cat, tot, pct


def render_text(rows, gates, hygiene, facts, only_gaps=False, web=None) -> str:
    by_cat, tot, pct = summarize(rows)
    out = []
    out.append("TRAKR SKILLS vs CI/CD PIPELINE")
    out.append("=" * 72)
    out.append(f"Skills in registry : {total_skills()} across {len(REGISTRY)} categories")
    out.append(f"Covered by pipeline: {tot['COVERED']}   Gaps: {tot['GAP']}   Manual: {tot['MANUAL']}")
    out.append(f"Automatable coverage: {pct}%")
    out.append("")
    out.append("Pipeline gates")
    out.append("-" * 72)
    for gid, (ok, _) in gates.items():
        out.append(f"  [{'x' if ok else ' '}] {gid:<17} {GATES[gid]['title']}")
    out.append("")
    out.append("Category coverage")
    out.append("-" * 72)
    for c, v in by_cat.items():
        out.append(f"  {c:<42} covered {v['COVERED']:>2} | gap {v['GAP']:>2} | manual {v['MANUAL']:>2}")
    out.append("")
    out.append("Skill detail" + (" (gaps only)" if only_gaps else ""))
    out.append("-" * 72)
    cur = None
    for r in rows:
        if only_gaps and r["status"] != "GAP":
            continue
        if r["category"] != cur:
            cur = r["category"]
            out.append(f"\n{cur}")
        out.append(f"  {r['status']:<8} {r['skill']}" + (f"   <- needs '{r['gate']}'" if r["status"] == "GAP" else ""))
    out.append("")
    out.append("Pipeline hygiene")
    out.append("-" * 72)
    for name, st, detail in hygiene:
        out.append(f"  {st:<5} {name}" + (f" - {detail}" if detail else ""))
    out.append("")
    out.append("Repo facts")
    out.append("-" * 72)
    for k, v in facts:
        out.append(f"  {k:<32} {v}")
    if web:
        out.append("")
        out.append("Web readiness (SEO / structured data / AI crawlers / headers)")
        out.append("-" * 72)
        for name, st, detail in web:
            out.append(f"  {st:<5} {name}" + (f" - {detail}" if detail else ""))
    return "\n".join(out)


def render_markdown(rows, gates, hygiene, facts, web=None) -> str:
    by_cat, tot, pct = summarize(rows)
    md = ["# Trakr skills vs CI/CD pipeline", "",
          f"**{total_skills()} skills / {len(REGISTRY)} categories** - covered {tot['COVERED']}, gaps {tot['GAP']}, manual {tot['MANUAL']} - **{pct}% automatable coverage**", "",
          "## Category coverage", "", "| Category | Covered | Gap | Manual |", "|---|---|---|---|"]
    for c, v in by_cat.items():
        md.append(f"| {c} | {v['COVERED']} | {v['GAP']} | {v['MANUAL']} |")
    md += ["", "## Pipeline gates", "", "| Gate | Status |", "|---|---|"]
    for gid, (ok, _) in gates.items():
        md.append(f"| {GATES[gid]['title']} | {'present' if ok else 'missing'} |")
    md += ["", "## Hygiene", "", "| Check | Result | Detail |", "|---|---|---|"]
    for n, s, d in hygiene:
        md.append(f"| {n} | {s} | {d} |")
    md += ["", "## Repo facts", ""] + [f"- {k}: {v}" for k, v in facts]
    if web:
        md += ["", "## Web readiness", "", "| Check | Result | Detail |", "|---|---|---|"]
        for n, st, d in web:
            md.append(f"| {n} | {st} | {d} |")
    return "\n".join(md)


def render_suggestions(gates) -> str:
    missing = [g for g, (ok, _) in gates.items() if not ok]
    if not missing:
        return "All gates present."
    out = ["# Suggested steps for missing gates (adapt before use)\n"]
    for g in missing:
        out.append(f"# {GATES[g]['title']}  [{g}]")
        out.append(GATES[g]["snippet"])
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# 9. CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check Trakr skills against the CI/CD pipeline.")
    ap.add_argument("--repo", default=".", help="path to the Trakr repo root")
    ap.add_argument("--workflows", help="workflow dir (default: <repo>/.github/workflows)")
    ap.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    ap.add_argument("--gaps-only", action="store_true", help="text format: list only skills with gaps")
    ap.add_argument("--min-coverage", type=float, default=None, help="fail if automatable coverage %% is below this")
    ap.add_argument("--fail-on-hygiene", action="store_true", help="fail if any hygiene check is FAIL")
    ap.add_argument("--web-dir", help="public web folder to inspect (default: <repo>/web)")
    ap.add_argument("--fail-on-web", action="store_true", help="fail if any web readiness check is FAIL")
    ap.add_argument("--suggest", action="store_true", help="print YAML snippets for missing gates")
    ap.add_argument("--self-test", action="store_true", help="validate the skills registry and exit")
    ap.add_argument("--export-registry", metavar="FILE", help="write the registry to JSON and exit")
    args = ap.parse_args(argv)

    problems = self_test()
    if args.self_test:
        if problems:
            print("Registry problems:\n  " + "\n  ".join(problems))
            return 1
        print(f"Registry OK: {len(REGISTRY)} categories, {total_skills()} skills, {len(GATES)} gates")
        return 0
    if problems:
        print("Registry problems:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 2

    if args.export_registry:
        payload = {"categories": [{"name": c, "skills": [{"name": n, "gate": g} for n, g in s]} for c, s in REGISTRY.items()],
                   "roadmap": ROADMAP, "total": total_skills()}
        Path(args.export_registry).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {args.export_registry}")
        return 0

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"Repo path not found: {repo}", file=sys.stderr)
        return 2
    wf_dir = Path(args.workflows) if args.workflows else repo / ".github" / "workflows"
    workflows = load_workflows(wf_dir)

    gates = detect_gates(workflows)
    rows = evaluate(gates)
    hygiene = hygiene_checks(workflows, repo)
    facts = repo_facts(repo)
    web = web_readiness(Path(args.web_dir) if args.web_dir else repo / "web")
    by_cat, tot, pct = summarize(rows)

    if args.format == "json":
        print(json.dumps({
            "total_skills": total_skills(), "coverage_percent": pct, "totals": tot,
            "gates": {g: {"present": ok, "detail": d} for g, (ok, d) in gates.items()},
            "skills": rows,
            "hygiene": [{"check": n, "result": s, "detail": d} for n, s, d in hygiene],
            "repo_facts": dict(facts),
            "web_readiness": [{"check": n, "result": s, "detail": d} for n, s, d in web],
        }, indent=2))
    elif args.format == "markdown":
        print(render_markdown(rows, gates, hygiene, facts, web))
    else:
        print(render_text(rows, gates, hygiene, facts, args.gaps_only, web))
    if args.suggest:
        print("\n" + render_suggestions(gates))

    failed = False
    if args.min_coverage is not None and pct < args.min_coverage:
        print(f"\nFAIL: coverage {pct}% < required {args.min_coverage}%", file=sys.stderr)
        failed = True
    if args.fail_on_hygiene and any(s == FAIL for _, s, _ in hygiene):
        print("\nFAIL: one or more hygiene checks failed", file=sys.stderr)
        failed = True
    if args.fail_on_web and any(s == FAIL for _, s, _ in web):
        print("\nFAIL: one or more web readiness checks failed", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
