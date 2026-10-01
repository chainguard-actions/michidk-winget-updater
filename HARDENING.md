<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.7

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.7** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Three `uses:` references in action.yml are pinned to mutable tags instead of full 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved:
- `actions/github-script@v8` (step: Check if Package Exists)
- `actions/github-script@v8` (step: Detect Latest Release)
- `michidk/run-komac@v2` (step: Run Komac)

Locations:

- `action.yml:38`
- `action.yml:53`
- `action.yml:82`

### script-injection (severity: high)

Sub-rule (a): The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands without going through an env: variable. `${{ inputs.version || steps.latest_release.outputs.result }}` and `${{ inputs.url }}` are substituted by the Actions template engine before the shell parses the script, allowing an attacker-controlled value to inject arbitrary shell commands. Offending lines:
  `VERSION=${{ inputs.version || steps.latest_release.outputs.result }}`
  `URL=${{ inputs.url }}`

Locations:

- `action.yml:76`
- `action.yml:77`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes values derived from untrusted inputs (`${{ inputs.url }}` → `URL`/`FINAL_URL`, and `${{ inputs.version || steps.latest_release.outputs.result }}` → `VERSION`) to `$GITHUB_ENV` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). A newline injected into these values can define arbitrary environment variables for subsequent steps.
  `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`
  `echo "VERSION=$VERSION" >> $GITHUB_ENV`

Locations:

- `action.yml:78`
- `action.yml:79`

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
1. Pinned actions/github-script@v8 to full SHA ed597411d8f924073f98dfc5c65a23a2325f34cd (both occurrences).
2. Pinned michidk/run-komac@v2 to full SHA b5627eaf2c8b839aa3be7580be1e2e5b72c13f91.
3. Moved ${{ inputs.version || steps.latest_release.outputs.result }} and ${{ inputs.url }} from the 'Compose URL' run: block into an env: map as INPUT_VERSION and INPUT_URL, eliminating shell injection risk.
4. Sanitized both values with printf '%s' ... | tr -d '\n\r' before writing to $GITHUB_ENV, preventing newline injection attacks.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection vulnerabilities in action.yml:
1. 'Check if Package Exists in winget-pkgs Repository' step: Moved `${{ inputs.identifier }}` to an `env:` block as `INPUT_IDENTIFIER` and updated the JavaScript to use `process.env.INPUT_IDENTIFIER` instead of direct string interpolation.
2. 'Detect Latest Release' step: Moved `${{ inputs.repo }}`, `${{ github.api_url }}`, and `${{ inputs.ghes-token }}` to an `env:` block as `INPUT_REPO`, `INPUT_API_URL`, and `INPUT_GHES_TOKEN` respectively, and updated the JavaScript to use `process.env.*` references instead of direct string interpolation. This prevents attacker-controlled input values from injecting arbitrary JavaScript into the github-script execution context.

