<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **michidk--winget-updater/v1.1.4** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands without quoting or env-var indirection. Specifically:
- Line 60: `VERSION=${{ steps.latest_release.outputs.result }}` — sub-rule (a): expression interpolated directly into shell
- Line 61: `URL=${{ inputs.url }}` — sub-rule (a): attacker-controlled `inputs.url` interpolated directly into shell
- Line 64: `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"` — sub-rule (a): expression interpolated directly into shell
Additionally, `$URL` and `$VERSION` are used unquoted on line 62 (`echo $URL | sed ...`), violating sub-rule (b).

Locations:

- `action.yml:60`
- `action.yml:61`
- `action.yml:62`
- `action.yml:64`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL=$FINAL_URL >> $GITHUB_ENV` (line 63) where FINAL_URL is derived from `inputs.url` (an attacker-controlled input) and `steps.latest_release.outputs.result` without any sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker can inject newlines into the URL input to poison GITHUB_ENV with arbitrary key-value pairs.

Locations:

- `action.yml:63`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable tags instead of full 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if the referenced tags are moved:
- `uses: actions/github-script@v7` (line 32)
- `uses: actions/github-script@v7` (line 44)
- `uses: michidk/run-komac@v2` (line 67)
All should be pinned to a full commit SHA (e.g. `actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7`).

Locations:

- `action.yml:32`
- `action.yml:44`
- `action.yml:67`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all four findings in action.yml:
1. Pinned actions/github-script@v7 to full SHA f28e40c7f34bde8b3046d885e986cb6290c5673b (both occurrences at lines 32 and 44).
2. Pinned michidk/run-komac@v2 to full SHA 9b27eadc6e9235c252444a437d246c139da2f57f.
3. Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} out of the 'Compose URL' run: block into the step's env: block as LATEST_VERSION and INPUT_URL, eliminating script injection.
4. Added sanitization (printf '%s' ... | tr -d '\n\r') for all values before writing to $GITHUB_ENV, preventing newline injection attacks on GITHUB_ENV.

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection vulnerabilities in action.yml:
1. 'Check if Package Exists' step (line 33): Moved `inputs.identifier` from direct `${{ }}` interpolation in the JavaScript `script:` block into an `env:` block as `INPUT_IDENTIFIER`, then read it via `process.env.INPUT_IDENTIFIER` inside the script.
2. 'Detect Latest Release' step (line 47): Moved `inputs.repo` from direct `${{ }}` interpolation in the JavaScript `script:` block into an `env:` block as `INPUT_REPO`, then read it via `process.env.INPUT_REPO` inside the script.
Both fixes prevent attackers from injecting arbitrary JavaScript by supplying crafted values containing quotes, backticks, or semicolons in the `identifier` or `repo` inputs.

