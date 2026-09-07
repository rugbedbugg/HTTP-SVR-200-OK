# Repository standards baseline

Adapted from ReAgent's `.github/STANDARDS.md` shared baseline.

- CI: pushes to main and CI branches, pull requests, manual and reusable calls.
- Toolchain: system GCC and Bash on Linux x86-64; mise pins ShellCheck and
  exposes identical local/CI lint, build and smoke-test tasks. mise-action caches
  its tools. There are no project dependencies or useful compiler caches here.
- Validation: ShellCheck and Bash syntax, native build, HTTP routing and an
  end-to-end registration/login/files/logout test in a temporary working directory.
- Permissions: read-only; obsolete CI runs are cancelled and jobs have timeouts.
- Artifacts: upload the tested executable with its SHA-256 checksum. This is an
  integrity record, not a signed provenance attestation or a release pipeline.
- CD: none currently; future releases must depend on successful CI and reuse
  tested artifacts with protected publication credentials and remote verification.
- README: purpose, installation, quick start, usage, configuration, development
  checks and license; linked CI badge. Preserve existing versioning policy.

Validate workflow syntax and run `mise run check` before integration; require
GitHub CI to pass. Adapt this structure for other repositories rather than
adding irrelevant tests or deployment workflows.
