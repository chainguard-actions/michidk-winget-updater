<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.3** was hardened automatically. 5 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block in action.yml directly interpolates GitHub Actions expressions inside shell commands (rule a) and uses unquoted shell variable expansions (rule b).

Rule (a) violations — ${{ ... }} expressions embedded directly in the shell script:
  Line 57: `VERSION=${{ steps.latest_release.outputs.result }}`
  Line 58: `URL=${{ inputs.url }}`
  Line 60: `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"`

Rule (b) violations — unquoted shell variable expansions of untrusted data:
  Line 59: `FINAL_URL=$(echo $URL | sed "s/{VERSION}/$VERSION/g")` — both $URL and $VERSION are unquoted, allowing shell metacharacter injection.

Locations:

- `action.yml:57`
- `action.yml:58`
- `action.yml:59`
- `action.yml:60`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes FINAL_URL to $GITHUB_ENV without sanitization. FINAL_URL is derived from ${{ inputs.url }} (caller-controlled) and ${{ steps.latest_release.outputs.result }} (step output), both of which are untrusted. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before the write. An attacker-controlled newline in the URL value could inject arbitrary environment variables.

Offending line: `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`

Locations:

- `action.yml:61`

### unpinned-uses (severity: high)

Multiple `uses:` references are pinned to mutable tags or branch names instead of immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if the referenced tag is moved or overwritten.

In action.yml:
  - `uses: actions/github-script@v7` (appears twice, steps 'Check if Package Exists' and 'Detect Latest Release')
  - `uses: michidk/run-komac@v2` (step 'Run Komac')

In .github/workflows/pr-stale.yml:
  - `uses: actions/stale@v9`

In .github/workflows/pr-title.yml:
  - `uses: aslafy-z/conventional-pr-title-action@v3`

In .github/workflows/versioning.yml:
  - `uses: Actions-R-Us/actions-tagger@latest`

Locations:

- `action.yml:31`
- `action.yml:44`
- `action.yml:68`
- `.github/workflows/pr-stale.yml:16`
- `.github/workflows/pr-title.yml:14`
- `.github/workflows/versioning.yml:9`

### missing-permissions (severity: medium)

The workflow file versioning.yml has no top-level `permissions:` key and its only job ('actions-tagger') also has no job-level `permissions:` key. Without explicit permissions, the workflow inherits the default repository token permissions, which may be overly broad (write access to contents, etc.).

Locations:

- `.github/workflows/versioning.yml:1`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions, static-inline-injection

**Notes:**

Fixed all 5 findings across action.yml and the 3 workflow files:

1. script-injection + static-inline-injection (action.yml): Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} from the 'Compose URL' run: block into the step's env: map as VERSION and URL. Shell script now uses properly quoted "$URL" and "$VERSION" variables.

2. github-env-injection (action.yml): Added `printf '%s' "$FINAL_URL" | tr -d '\n\r'` sanitization before writing to $GITHUB_ENV to prevent newline injection.

3. unpinned-uses: Pinned all 5 mutable action references to full 40-char commit SHAs with tag comments preserved: actions/github-script@v7 (×2), michidk/run-komac@v2, actions/stale@v9, aslafy-z/conventional-pr-title-action@v3, Actions-R-Us/actions-tagger@latest.

4. missing-permissions (versioning.yml): Added `permissions: contents: write` at top-level and job-level (required for actions-tagger to create/update tags).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection vulnerabilities in action.yml:
1. 'Check if Package Exists' step (line 34): Moved `${{ inputs.identifier }}` from inline JavaScript string `const pkgid = "${{ inputs.identifier }}";` into an `env:` block as `INPUT_IDENTIFIER`, then accessed it safely via `process.env.INPUT_IDENTIFIER` in the script.
2. 'Detect Latest Release' step (line 51): Moved `${{ inputs.repo }}` from inline JavaScript string `'${{ inputs.repo }}'.split('/')` into an `env:` block as `INPUT_REPO`, then accessed it safely via `process.env.INPUT_REPO.split('/')` in the script.
Both fixes prevent attacker-controlled inputs from being interpolated directly into JavaScript code execution contexts.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability in the 'Compose URL' step (action.yml line 68). Replaced the unsafe `sed "s/{VERSION}/$VERSION/g"` command — where $VERSION was expanded unquoted inside a double-quoted sed argument, allowing shell metacharacters to break out — with bash's built-in parameter expansion `"${URL//\{VERSION\}/$VERSION}"`. Bash parameter expansion treats the replacement string literally without shell metacharacter interpretation, eliminating the injection vector while preserving the same URL template substitution functionality.

