<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.6

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.6** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block in action.yml directly interpolates GitHub Actions expressions into shell commands without quoting. Specifically: `VERSION=${{ steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are unquoted shell variable assignments from expression interpolation (rule a). The value of `inputs.url` is attacker-controllable and is also used unquoted in `$(echo $URL | sed ...)` (rule b). An attacker can inject shell metacharacters via these inputs.

Locations:

- `action.yml:57`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL=$FINAL_URL >> $GITHUB_ENV` where FINAL_URL is derived from `${{ inputs.url }}` (attacker-controlled) and `${{ steps.latest_release.outputs.result }}` without any sanitization step (`printf '%s' ... | tr -d '\n\r'`). A newline injected into these values could allow an attacker to inject arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:60`

### unpinned-uses (severity: high)

Multiple `uses:` references use mutable tags or branch names instead of pinned 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or overwritten. Failing references:
- action.yml: `actions/github-script@v7` (two steps), `michidk/run-komac@v2`
- .github/workflows/pr-stale.yml: `actions/stale@v9`
- .github/workflows/pr-title.yml: `aslafy-z/conventional-pr-title-action@v3`
- .github/workflows/versioning.yml: `Actions-R-Us/actions-tagger@latest`

Locations:

- `action.yml:33`
- `action.yml:43`
- `action.yml:71`
- `.github/workflows/pr-stale.yml:16`
- `.github/workflows/pr-title.yml:14`
- `.github/workflows/versioning.yml:9`

### missing-permissions (severity: medium)

The workflow file versioning.yml has no top-level `permissions:` key and its only job (`actions-tagger`) also has no job-level `permissions:` key. Without explicit permissions, the job inherits the default repository token permissions, which may be broader than necessary.

Locations:

- `.github/workflows/versioning.yml:1`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all 5 findings:
1. script-injection + static-inline-injection: Moved `${{ steps.latest_release.outputs.result }}` and `${{ inputs.url }}` from the 'Compose URL' run: block into an env: block as VERSION and INPUT_URL respectively. Shell script now uses safe env var references.
2. github-env-injection: Added `tr -d '\n\r'` sanitization via printf before writing FINAL_URL to $GITHUB_ENV. Also quoted $GITHUB_ENV reference.
3. unpinned-uses: Pinned all 6 action references to full 40-char SHAs: actions/github-script@v7 → f28e40c7f34bde8b3046d885e986cb6290c5673b (×2), michidk/run-komac@v2 → 9b27eadc6e9235c252444a437d246c139da2f57f, actions/stale@v9 → 5bef64f19d7facfb25b37b414482c7164d639639, aslafy-z/conventional-pr-title-action@v3 → 2ce59b07f86bd51b521dd088f0acfb0d7fdac55e, Actions-R-Us/actions-tagger@latest → 330ddfac760021349fef7ff62b372f2f691c20fb.
4. missing-permissions: Added top-level and job-level `permissions: contents: write` to versioning.yml (needed for the tagger action to update tags).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all three script-injection findings in hardened/action/action.yml:
1. 'Check if Package Exists' step: Moved `inputs.identifier` out of the JavaScript script block into an `env:` field as `INPUT_IDENTIFIER`, then accessed it safely via `process.env.INPUT_IDENTIFIER` in the script.
2. 'Detect Latest Release' step: Moved `inputs.repo` out of the JavaScript script block into an `env:` field as `INPUT_REPO`, then accessed it safely via `process.env.INPUT_REPO.split('/')` in the script.
3. 'Compose URL' step: Added an `ESCAPED_VERSION` variable that escapes forward slashes and ampersands in `$VERSION` using `sed 's/[\/&]/\&/g'` before using it in the sed replacement expression, preventing shell metacharacters from breaking out of the sed argument.

