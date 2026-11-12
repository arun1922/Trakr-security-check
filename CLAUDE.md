# Trakr project memory

Trakr is a Flutter app (web + Android) with Firebase (Firestore rules, Cloud Functions in `functions/`).
The CI/CD checker lives at `scripts/check_skills_cicd.py` (registry: 21 categories, 174 skills).

@.claude/rules/security.md
@.claude/rules/cicd.md

## Common commands
- Full check:         `python3 scripts/check_skills_cicd.py --repo .`
- Gaps only:          `python3 scripts/check_skills_cicd.py --repo . --gaps-only`
- Suggest YAML:       `python3 scripts/check_skills_cicd.py --repo . --suggest`
- Registry self-test: `python3 scripts/check_skills_cicd.py --self-test`
- Slash commands:     `/security-check`, `/cicd-gaps`, `/web-readiness`, `/suggest-gates`
