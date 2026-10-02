<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.7

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.7** was hardened automatically. 5 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Three `uses:` references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs. This exposes the action to supply-chain attacks if the upstream action is compromised or the tag is moved. Failing references: `actions/github-script@v8` (used twice) and `michidk/run-komac@v2`.

Locations:

- `action.yml:35`
- `action.yml:48`
- `action.yml:79`

### script-injection (severity: high)

Sub-rule (a): The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell command strings without routing through env: variables. `VERSION=${{ inputs.version || steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are expanded by the Actions template engine before the shell ever sees them, allowing an attacker-controlled value (e.g. a malicious `inputs.url` or `inputs.version`) to inject arbitrary shell commands. These values are also unquoted, compounding the risk.

Locations:

- `action.yml:68`
- `action.yml:69`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` and `VERSION` — both derived from unsanitized user-controlled inputs (`inputs.url` and `inputs.version` / `steps.latest_release.outputs.result`) — directly to `$GITHUB_ENV` without the required `printf '%s' ... | tr -d '\n\r'` sanitization step. A newline embedded in either input value can inject arbitrary environment variable definitions into subsequent steps. Offending lines: `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` and `echo "VERSION=$VERSION" >> $GITHUB_ENV`.

Locations:

- `action.yml:71`
- `action.yml:72`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version || steps.latest_release.outputs.result }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:85`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:86`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in action.yml:
1. Pinned actions/github-script@v8 to SHA ed597411d8f924073f98dfc5c65a23a2325f34cd (used twice)
2. Pinned michidk/run-komac@v2 to SHA b5627eaf2c8b839aa3be7580be1e2e5b72c13f91
3. Moved ${{ inputs.version || steps.latest_release.outputs.result }} and ${{ inputs.url }} expressions from the 'Compose URL' run: block into an env: block as INPUT_VERSION and INPUT_URL, eliminating script injection risk
4. Added printf '%s' ... | tr -d '\n\r' sanitization for all values written to $GITHUB_ENV (FINAL_URL and VERSION), preventing newline injection attacks

