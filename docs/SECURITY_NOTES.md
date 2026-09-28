# Security notes

What each scanner checks, what it found, and how each finding was handled. Update the
"Findings" table from the reports archived by each build (`reports/security/`).

## What runs in the Security stage

| Tool | Looks at | Fails the build when |
|---|---|---|
| Bandit | Our Python code | any MEDIUM or HIGH issue |
| pip-audit | `requirements.txt` against the PyPI advisory database | any known vulnerability |
| Trivy (secret) | every file in the repo | a credential/key is committed |
| Trivy (image) | OS packages + Python packages inside the Docker image | a HIGH/CRITICAL CVE that already has a fix |

Code Quality (SonarQube) is a separate stage - that's about maintainability. This stage is
about attackers.

## Findings and decisions

These are the real results from the pipeline runs.

| # | Tool | Finding | Severity | Decision |
|---|---|---|---|---|
| 1 | Bandit | B608 "possible SQL injection" in `app/database.py` - `list_incidents` (line ~109) and `update_incident` (line ~134) | Medium | **Reviewed - false positive, documented in code.** Only fixed clauses / column names from the `UPDATABLE_FIELDS` whitelist are formatted into the SQL; every user value is bound with a `?` placeholder. Marked `# nosec B608` with the reasoning in a comment above each line |
| 2 | Trivy (image) | `msgpack` 1.1.2 - GHSA-6v7p-g79w-8964, out-of-bounds read / crash on Unpacker reuse | HIGH | **Fixed (build #5).** It was a library vendored *inside pip*, which the running app never uses. The Dockerfile now uninstalls pip (and `ensurepip`) after installing dependencies. Build #4 was blocked by this finding |
| 3 | Trivy (image) | `setuptools` 70.3.0 - CVE-2025-47273, path traversal in PackageIndex | HIGH | **Fixed (build #5)** - same root cause and same fix as #2 |
| 4 | Trivy (image) | Debian 13 OS packages | - | **Prevented.** `apt-get upgrade` in the Dockerfile pulls security patches released after the base image; scan shows 0 |
| 5 | pip-audit | Our pinned dependencies (FastAPI, Starlette, Uvicorn, Pydantic, prometheus-client) | - | Clean. Pins mean a new advisory shows up as a failing build rather than a silent upgrade |
| 6 | Trivy (secret) | Repo scan | - | Clean. `.env` is git-ignored; attack payloads in `tests/` and `scripts/attack_sim.py` are test strings, not credentials |

### Supply-chain note

The pipeline's own tools are part of the attack surface too. Older Trivy releases were removed
from GitHub after the 2026 Trivy supply-chain incident, so the Jenkins image pins **Trivy 0.69.3**
and verifies the download against the release's published SHA-256 checksum before installing it.

## Security features in the app itself

- API keys compared with `hmac.compare_digest` (no timing leaks)
- Role separation: analysts can't delete or read the audit log
- Input validation on every field (enums for severity/status, length limits) - bad input gets a 422
- Parameterised SQL everywhere
- Attack detection + automatic incident creation + brute-force tracking
- Container runs as a non-root user (uid 10001)
- Secrets never in git: `.env` is ignored, Jenkins credentials come from config-as-code
  variables, the Gmail password is injected into Alertmanager at start-up only

## Known trade-offs (fine for a lab, not for a real company)

- Jenkins runs as root to reach Docker Desktop's socket. In production you'd use a dedicated
  build agent or rootless Docker.
- SonarQube's Elasticsearch bootstrap checks are disabled because WSL's default
  `vm.max_map_count` is too low.
- The local registry is plain HTTP on localhost.
- The detector is pattern-based; a determined attacker can evade regexes. It's there to catch
  the noisy 95% and to feed monitoring, not to replace a WAF.
