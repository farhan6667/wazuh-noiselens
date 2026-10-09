# Changelog

## 0.2.0: 2026-10-09

- HTML reports are now readable pages (summary cards, a verdict banner, per-suppression and per-rule bars) instead of a JSON dump. Still one offline file with no scripts and a strict Content Security Policy.
- `--markdown` writes a summary for CI, for example `$GITHUB_STEP_SUMMARY`.
- `--breakdown RULE_ID:FIELD` prints the most common values of one field for one rule, to help write a narrow exception. Values go to the terminal only, never into a report; control characters are neutralised and long values are cut.
- The policy now has a JSON Schema (`noiselens/policy.schema.json`, `noiselens --print-schema`), and a policy may carry a `$schema` key.
- Container image published to GitHub Packages (ghcr.io) on every release, built from the new Dockerfile and smoke tested in CI.
- Licence changed from MIT to Apache-2.0 for future versions, with a NOTICE file. Earlier commits stay under MIT.
- README redesigned with a banner, a how-it-works diagram and brand footer.

## 0.1.0: 2026-10-05: local prototype

Initial wazuh-noiselens implementation, CLI, synthetic examples, documentation and unit tests.
Prepared for Python 3.10+. Local verification used Python 3.12 on Windows.
No public release or live engine compatibility certification has been completed.
