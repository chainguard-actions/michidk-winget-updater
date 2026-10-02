<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.5** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

All three `uses:` references in action.yml use mutable tags instead of pinned full 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if the referenced action is compromised or the tag is moved:
- `actions/github-script@v7` (line 32)
- `actions/github-script@v7` (line 47)
- `michidk/run-komac@v2` (line 70)

Locations:

- `action.yml:32`
- `action.yml:47`
- `action.yml:70`

### script-injection (severity: high)

The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands (sub-rule a), allowing an attacker to inject arbitrary shell commands via workflow inputs or step outputs:
- Line 62: `VERSION=${{ steps.latest_release.outputs.result }}` — step output interpolated directly into shell
- Line 63: `URL=${{ inputs.url }}` — user-controlled input interpolated directly into shell
- Line 67: `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"` — step output interpolated directly into shell
An attacker controlling `inputs.url` or the release tag name could inject shell metacharacters (`;`, `|`, `$(...)`, etc.) to execute arbitrary commands.

Locations:

- `action.yml:62`
- `action.yml:63`
- `action.yml:67`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` — derived from the untrusted `${{ inputs.url }}` and `${{ steps.latest_release.outputs.result }}` expressions — to `$GITHUB_ENV` without sanitization (no `printf '%s' ... | tr -d '\n\r'` step). An attacker who controls `inputs.url` or the release tag name can inject newlines into the value to set arbitrary environment variables for subsequent steps, potentially overriding sensitive variables like `PATH` or injecting new ones.

Offending line: `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`

Locations:

- `action.yml:65`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all four findings in action.yml:
1. Pinned actions/github-script@v7 to full SHA f28e40c7f34bde8b3046d885e986cb6290c5673b (both occurrences)
2. Pinned michidk/run-komac@v2 to full SHA b5627eaf2c8b839aa3be7580be1e2e5b72c13f91
3. Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} expressions from the 'Compose URL' run: block into the step's env: block (as LATEST_VERSION and INPUT_URL), eliminating script injection risk
4. Added printf '%s' ... | tr -d '\n\r' sanitization for all values before writing to $GITHUB_ENV, preventing newline injection attacks

