# Trakr Claude / Antigravity kit

## Setup
1. Copy these files into your Trakr repo root (or open this folder as-is).
2. `cp .claude/settings.local.json.example .claude/settings.local.json`, then paste your NEW OpenRouter key.
3. Fix or empty `~/.claude/settings.json` if malformed: `python3 -m json.tool ~/.claude/settings.json`
4. Run `claude`, then `/security-check`.

## Layout
- `CLAUDE.md` + `.claude/rules/`   project rules
- `.claude/commands/`              slash commands
- `.claude/skills/`, `.claude/agents/`
- `.agent/`                        Antigravity rules, workflows, skills
- `trakr-security-plugin/`         packaged plugin
- `scripts/check_skills_cicd.py`   your checker
