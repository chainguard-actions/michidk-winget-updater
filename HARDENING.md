<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **michidk--winget-updater/v1.1.3** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

All three `uses:` references in action.yml use mutable tags instead of pinned 40-character SHA digests, making the action vulnerable to supply-chain attacks if the referenced tags are moved:
- `actions/github-script@v7` (line 32)
- `actions/github-script@v7` (line 44)
- `michidk/run-komac@v2` (line 65)

Locations:

- `action.yml:32`
- `action.yml:44`
- `action.yml:65`

### script-injection (severity: high)

Rule (a): The 'Compose URL' run: block directly interpolates GitHub Actions expressions inside shell commands. These expressions are template-substituted before the shell executes them, allowing an attacker to inject arbitrary shell commands:
- Line 57: `VERSION=${{ steps.latest_release.outputs.result }}` — step output interpolated directly into shell assignment
- Line 58: `URL=${{ inputs.url }}` — user-controlled input interpolated directly into shell assignment
- Line 62: `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"` — step output interpolated into echo command

Rule (b): On line 59, `$URL` and `$VERSION` (both set from direct `${{ }}` interpolation) are used unquoted: `FINAL_URL=$(echo $URL | sed "s/{VERSION}/$VERSION/g")`. Unquoted expansions allow shell metacharacter injection.

Locations:

- `action.yml:57`
- `action.yml:58`
- `action.yml:59`
- `action.yml:62`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` to `$GITHUB_ENV` without sanitization. `FINAL_URL` is derived from `${{ inputs.url }}` (user-controlled) and `${{ steps.latest_release.outputs.result }}` (step output), both of which are untrusted. A newline character in either value could inject arbitrary environment variables into subsequent steps. The required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`) is absent before the write on line 60: `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`.

Locations:

- `action.yml:60`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all four findings in action.yml:
1. Pinned actions/github-script@v7 to SHA f28e40c7f34bde8b3046d885e986cb6290c5673b (both occurrences)
2. Pinned michidk/run-komac@v2 to SHA 9b27eadc6e9235c252444a437d246c139da2f57f
3. Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} out of the 'Compose URL' run: block into an env: map (as VERSION and URL), fixing script-injection and static-inline-injection
4. Added newline sanitization (printf + tr -d '\n\r') for all values before writing FINAL_URL to $GITHUB_ENV, fixing github-env-injection
5. All variable expansions in the shell script are now properly double-quoted

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection vulnerabilities in action.yml:

1. Step 'Check if Package Exists in winget-pkgs Repository' (line 35): Moved `${{ inputs.identifier }}` out of the `script:` block into an `env:` block as `INPUT_IDENTIFIER`, then replaced the inline string interpolation `"${{ inputs.identifier }}"` with `process.env.INPUT_IDENTIFIER` in the JavaScript code.

2. Step 'Detect Latest Release' (line 50): Moved `${{ inputs.repo }}` out of the `script:` block into an `env:` block as `INPUT_REPO`, then replaced the inline string interpolation `'${{ inputs.repo }}'` with `process.env.INPUT_REPO` in the JavaScript code.

Both fixes prevent attacker-controlled values containing JS metacharacters (quotes, etc.) from breaking out of their string context and executing arbitrary JavaScript code.

