<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **michidk--winget-updater/v1.1.5** was hardened automatically. 4 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands (sub-rule a), and uses unquoted shell variable expansions of those values (sub-rule b). Specifically: `VERSION=${{ steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are interpolated directly into the shell script without quoting, and then `$URL` and `$VERSION` are used unquoted in `$(echo $URL | sed "s/{VERSION}/$VERSION/g")`. An attacker controlling `inputs.url` or the release tag name can inject arbitrary shell commands.

Locations:

- `action.yml:60`
- `action.yml:61`
- `action.yml:62`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` to `$GITHUB_ENV` without sanitizing newlines. `FINAL_URL` is derived from `${{ inputs.url }}` (user-controlled) and `${{ steps.latest_release.outputs.result }}` (step output, also workflow-controllable). An attacker can inject newlines into these values to add arbitrary environment variables. The required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`) is absent before the `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` write.

Locations:

- `action.yml:63`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable version tags instead of pinned 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved or overwritten:
- `uses: actions/github-script@v7` (step: 'Check if Package Exists in winget-pkgs Repository')
- `uses: actions/github-script@v7` (step: 'Detect Latest Release')
- `uses: michidk/run-komac@v2` (step: 'Run Komac')

Locations:

- `action.yml:32`
- `action.yml:46`
- `action.yml:70`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, static-inline-injection, github-env-injection

**Notes:**

Fixed all four findings in action.yml:
1. unpinned-uses: Pinned actions/github-script@v7 to SHA f28e40c7f34bde8b3046d885e986cb6290c5673b and michidk/run-komac@v2 to SHA 9b27eadc6e9235c252444a437d246c139da2f57f.
2. script-injection + static-inline-injection: Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} from the run: block into an env: block (as VERSION and URL), then referenced them as properly double-quoted shell variables ($VERSION, $URL) in the script.
3. github-env-injection: Added newline sanitization using `printf '%s' "$FINAL_URL" | tr -d '\n\r'` before writing to $GITHUB_ENV, and quoted $GITHUB_ENV reference.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability in the 'Compose URL' step of action.yml. Replaced `sed "s/{VERSION}/$VERSION/g"` with `awk -v ver="$VERSION" '{gsub(/\{VERSION\}/, ver); print}'`. The awk -v assignment passes the VERSION value directly to awk without shell interpretation, eliminating any risk of command substitution or shell metacharacter injection. The VERSION and URL values were already correctly sourced from the env: block.

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection vulnerabilities in action.yml:

1. 'Check if Package Exists in winget-pkgs Repository' step (line 36): Moved `inputs.identifier` from direct interpolation in the JavaScript string literal (`const pkgid = "${{ inputs.identifier }}";`) to the step's `env:` block as `INPUT_IDENTIFIER`. The JS code now reads it safely via `process.env.INPUT_IDENTIFIER`.

2. 'Detect Latest Release' step (line 50): Moved `inputs.repo` from direct interpolation in the JavaScript string literal (`'${{ inputs.repo }}'.split('/')`) to the step's `env:` block as `INPUT_REPO`. The JS code now reads it safely via `process.env.INPUT_REPO.split('/')`.

Both fixes prevent attacker-controlled input values from being interpreted as JavaScript source code by GitHub Actions' template substitution engine.

