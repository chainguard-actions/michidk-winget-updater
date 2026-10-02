<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.4** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Compose URL' run: block directly interpolates ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} as unquoted expressions inside a shell script. These values are substituted by the Actions template engine before the shell parses the command, allowing an attacker-controlled value to inject arbitrary shell commands. Offending lines: `VERSION=${{ steps.latest_release.outputs.result }}`, `URL=${{ inputs.url }}`, and `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"`

Locations:

- `action.yml:63`
- `action.yml:64`
- `action.yml:66`

### script-injection (severity: high)

Sub-rule (a): The 'Check if Package Exists' step interpolates ${{ inputs.identifier }} directly into a JavaScript string literal inside the github-script script: block (`const pkgid = "${{ inputs.identifier }}";`). The ${{ }} substitution occurs before the JS engine processes the code, enabling an attacker to inject arbitrary JavaScript via the identifier input.

Locations:

- `action.yml:35`

### script-injection (severity: high)

Sub-rule (a): The 'Detect Latest Release' step interpolates ${{ inputs.repo }} directly into a JavaScript string literal inside the github-script script: block (`const [owner, repo] = '${{ inputs.repo }}'.split('/');`). The ${{ }} substitution occurs before the JS engine processes the code, enabling an attacker to inject arbitrary JavaScript via the repo input.

Locations:

- `action.yml:50`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes FINAL_URL to $GITHUB_ENV without sanitization. FINAL_URL is derived from ${{ inputs.url }} (untrusted input) and ${{ steps.latest_release.outputs.result }} (untrusted step output), both interpolated directly into shell variables. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before the write, allowing newline injection to set arbitrary environment variables. Offending line: `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`

Locations:

- `action.yml:65`

### unpinned-uses (severity: high)

Three `uses:` references are pinned to mutable version tags instead of immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if the tag is moved: (1) `actions/github-script@v7` (line 32), (2) `actions/github-script@v7` (line 47), (3) `michidk/run-komac@v2` (line 70). Each should be pinned to a full SHA, e.g. `actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7`.

Locations:

- `action.yml:32`
- `action.yml:47`
- `action.yml:70`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in hardened/action/action.yml:

1. **unpinned-uses**: Pinned actions/github-script@v7 → @f28e40c7f34bde8b3046d885e986cb6290c5673b # v7 (both occurrences) and michidk/run-komac@v2 → @b5627eaf2c8b839aa3be7580be1e2e5b72c13f91 # v2.

2. **script-injection (Check if Package Exists)**: Moved ${{ inputs.identifier }} to env block as INPUT_IDENTIFIER; script now reads process.env.INPUT_IDENTIFIER instead of interpolating the expression directly into JS code.

3. **script-injection (Detect Latest Release)**: Moved ${{ inputs.repo }} to env block as INPUT_REPO; script now reads process.env.INPUT_REPO.split('/') instead of interpolating the expression directly into JS code.

4. **script-injection (Compose URL)**: Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} to env block as LATEST_RELEASE_RESULT and INPUT_URL; shell script references them as $LATEST_RELEASE_RESULT and $INPUT_URL.

5. **github-env-injection**: Added printf '%s' ... | tr -d '\n\r' sanitization for all values written to $GITHUB_ENV, preventing newline injection attacks. Also quoted $GITHUB_ENV reference.

