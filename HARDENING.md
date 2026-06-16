<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.7

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **michidk--winget-updater/v1.1.7** was hardened automatically. 5 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands (sub-rule a): `VERSION=${{ inputs.version || steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are interpolated directly into the shell script before the shell ever sees them, allowing an attacker-controlled value to break out of the assignment and inject arbitrary shell commands. Additionally (sub-rule b), the variables $URL, $VERSION, and $FINAL_URL are used unquoted in shell expansions: `FINAL_URL=$(echo $URL | sed "s/{VERSION}/$VERSION/g")`, allowing shell metacharacter injection.

Locations:

- `action.yml:83`
- `action.yml:84`
- `action.yml:85`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes values derived from untrusted inputs to $GITHUB_ENV without sanitization. `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` and `echo "VERSION=$VERSION" >> $GITHUB_ENV` write values ultimately sourced from `inputs.url`, `inputs.version`, and `steps.latest_release.outputs.result` — all attacker-controllable — without first applying `printf '%s' ... | tr -d '\n\r'`. A newline in any of these values can inject arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:86`
- `action.yml:87`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable tag refs instead of pinned full 40-character SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the repository is compromised:
- `uses: actions/github-script@v8` (line 39, 'Check if Package Exists' step)
- `uses: actions/github-script@v8` (line 54, 'Detect Latest Release' step)
- `uses: michidk/run-komac@v2` (line 91, 'Run Komac' step)

Locations:

- `action.yml:39`
- `action.yml:54`
- `action.yml:91`

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
1. Pinned actions/github-script@v8 to SHA ed597411d8f924073f98dfc5c65a23a2325f34cd (both occurrences)
2. Pinned michidk/run-komac@v2 to SHA 9b27eadc6e9235c252444a437d246c139da2f57f
3. Moved ${{ inputs.version || steps.latest_release.outputs.result }} and ${{ inputs.url }} from the run: block into an env: block (INPUT_VERSION and INPUT_URL) to prevent script injection
4. Added printf '%s' ... | tr -d '\n\r' sanitization for all values written to $GITHUB_ENV to prevent newline injection
5. Quoted all shell variable expansions ($URL, $VERSION, $FINAL_URL) to prevent shell metacharacter injection

