---
name: trakr-cicd-audit
description: Audit the Trakr repo's CI/CD pipeline against the skills registry. Use when the user asks about pipeline coverage, missing gates, GitHub Actions hygiene, or runs /security-check.
---

# Trakr CI/CD audit

1. Run `python3 scripts/check_skills_cicd.py --repo . --format json`.
2. Read `coverage_percent`, `gates` (present/missing), `hygiene` and `web_readiness`.
3. Report in this order: hygiene FAILs, missing high-value gates (secrets_scan, sast, dep_audit, test, analyze), coverage %, web FAILs.
4. For each issue give the file to change and a ready YAML snippet (use `--suggest`).
5. Exit codes: 0 ok, 1 threshold/hygiene failure, 2 usage/IO error.
Never modify workflows without confirmation.
