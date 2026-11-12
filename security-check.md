---
description: Run the Trakr skills vs CI/CD pipeline check and summarize
allowed-tools: Bash(python3 scripts/check_skills_cicd.py:*)
argument-hint: [extra checker flags]
---

Run the checker and summarize the results:

!`python3 scripts/check_skills_cicd.py --repo . $ARGUMENTS`

Then:
1. List every FAIL and WARN, grouped by severity.
2. Give the coverage percentage and the 5 most valuable missing gates.
3. Suggest a concrete fix for each FAIL.
Do not modify any files unless asked.
