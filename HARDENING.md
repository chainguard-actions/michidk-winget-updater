<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.3** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell commands, violating sub-rule (a): `VERSION=${{ steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are substituted directly into the shell script before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands. Additionally, sub-rule (b) is violated: the resulting shell variables `$URL` and `$VERSION` are used unquoted (e.g. `echo $URL | sed ...` and `s/{VERSION}/$VERSION/g`), allowing shell metacharacter injection. All expressions must be passed via env: vars and all shell expansions must be double-quoted.

Locations:

- `action.yml:57`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` to `$GITHUB_ENV` without sanitization. `FINAL_URL` is derived from `${{ inputs.url }}` (user-controlled) and `${{ steps.latest_release.outputs.result }}` (step output, also untrusted). The line `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` does not apply `printf '%s' ... | tr -d '\n\r'` before the write, allowing newline injection that can set arbitrary environment variables for subsequent steps.

Locations:

- `action.yml:61`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml are pinned to mutable tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `actions/github-script@v7` (Check if Package Exists step), (2) `actions/github-script@v7` (Detect Latest Release step), (3) `michidk/run-komac@v2` (Run Komac step). Each should be pinned to a full commit SHA, e.g. `actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7`.

Locations:

- `action.yml:33`
- `action.yml:44`
- `action.yml:67`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, static-inline-injection, github-env-injection

**Notes:**

Fixed all four findings in action.yml:
1. Pinned actions/github-script@v7 to SHA f28e40c7f34bde8b3046d885e986cb6290c5673b (both occurrences at lines 33 and 44).
2. Pinned michidk/run-komac@v2 to SHA b5627eaf2c8b839aa3be7580be1e2e5b72c13f91 (line 67).
3. Fixed script-injection and static-inline-injection in 'Compose URL' step: moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} into an env: block as VERSION and URL respectively; all shell variable expansions are now double-quoted.
4. Fixed github-env-injection: sanitized FINAL_URL with `printf '%s' "$FINAL_URL" | tr -d '\n\r'` before writing to $GITHUB_ENV; also quoted $GITHUB_ENV reference.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all three script-injection findings in hardened/action/action.yml:
1. 'Check if Package Exists' step: Moved ${{ inputs.identifier }} from inline JavaScript string literal to env block as INPUT_IDENTIFIER, accessed via process.env.INPUT_IDENTIFIER in the script.
2. 'Detect Latest Release' step: Moved ${{ inputs.repo }} from inline JavaScript string literal to env block as INPUT_REPO, accessed via process.env.INPUT_REPO.split('/') in the script.
3. 'Compose URL' step: Fixed unquoted $VERSION in sed expression by breaking the double-quoted string around the variable: sed "s/{VERSION}/""$VERSION""/g" — this ensures the shell treats $VERSION as a quoted word, preventing metacharacter injection.

