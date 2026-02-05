# AGENTS Instructions

These instructions apply to all contributors and automation working in this repo.

## Documentation Sync Policy
- Keep the CLI help output, `README.md`, and `CHANGELOG.md` consistent.
- Whenever you change a command, flag, default, or behavior, update:
  - the CLI help text
  - `README.md`
- Before any build, release, or version bump, verify the help output matches `README.md`.

## Release / Versioning Policy
- Every version bump requires a `CHANGELOG.md` entry under a dated version header.
- Every git tag must correspond to a version already documented in `CHANGELOG.md`.
- When tagging a release:
  - confirm `README.md` install instructions match the GitHub Actions artifacts
  - confirm help output matches the docs

## Build / Release Checklist
- Run tests (or clearly note why they were skipped).
- Regenerate artifacts if the CLI interface or output format changed.
- Update `README.md` and `CHANGELOG.md` before tagging.

## Style
- Keep documentation concise and task-focused.
- Prefer explicit examples over vague descriptions.
