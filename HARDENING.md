<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.4** was hardened automatically. 5 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block in action.yml directly interpolates GitHub Actions expressions into shell commands (rule a): `VERSION=${{ steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are expanded by the template engine before the shell sees them, allowing an attacker-controlled value to inject arbitrary shell commands. Additionally (rule b), the shell variables $URL and $VERSION are used unquoted in `$(echo $URL | sed "s/{VERSION}/$VERSION/g")`, allowing shell metacharacter injection from those values.

Locations:

- `action.yml:62`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL=$FINAL_URL >> $GITHUB_ENV` where FINAL_URL is derived from `${{ inputs.url }}` (untrusted input) and `${{ steps.latest_release.outputs.result }}` (step output, workflow-controllable). No sanitization step (`printf '%s' ... | tr -d '\n\r'`) is applied before the write, allowing newline injection into GITHUB_ENV which can override arbitrary environment variables.

Locations:

- `action.yml:65`

### unpinned-uses (severity: high)

Multiple `uses:` references are pinned to mutable tags or branch names instead of immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved:
- action.yml: `actions/github-script@v7` (two steps), `michidk/run-komac@v2`
- .github/workflows/pr-stale.yml: `actions/stale@v9`
- .github/workflows/pr-title.yml: `aslafy-z/conventional-pr-title-action@v3`
- .github/workflows/versioning.yml: `Actions-R-Us/actions-tagger@latest`

Locations:

- `action.yml:31`
- `action.yml:43`
- `action.yml:75`
- `.github/workflows/pr-stale.yml:16`
- `.github/workflows/pr-title.yml:14`
- `.github/workflows/versioning.yml:10`

### missing-permissions (severity: medium)

The workflow file versioning.yml has no top-level `permissions:` key and its only job (`actions-tagger`) also has no job-level `permissions:` key. Without explicit permissions, the job inherits the default repository token permissions, which may be broader than necessary.

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

Fixed all 5 findings:
1. script-injection & static-inline-injection: Moved `${{ steps.latest_release.outputs.result }}` and `${{ inputs.url }}` from the run: block into the step's env: map as VERSION and URL. Shell script now uses properly quoted "$URL" and "$VERSION".
2. github-env-injection: Added `printf '%s' "$FINAL_URL" | tr -d '\n\r'` sanitization before writing to $GITHUB_ENV.
3. unpinned-uses: Pinned all 6 action references to full 40-char SHAs: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b (x2), michidk/run-komac@9b27eadc6e9235c252444a437d246c139da2f57f, actions/stale@5bef64f19d7facfb25b37b414482c7164d639639, aslafy-z/conventional-pr-title-action@2ce59b07f86bd51b521dd088f0acfb0d7fdac55e, Actions-R-Us/actions-tagger@330ddfac760021349fef7ff62b372f2f691c20fb.
4. missing-permissions: Added `permissions: {}` at top level and `permissions: contents: write` at job level in versioning.yml (actions-tagger needs contents:write to manage tags).

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Fixed the sed delimiter issue in the 'Compose URL' step. Changed `sed "s/{VERSION}/$VERSION/g"` to `sed "s|{VERSION}|$VERSION|g"` to use '|' as the delimiter instead of '/'. This prevents the sed expression from breaking if $VERSION contains a '/' character, which could cause command injection or expression breakage. The $VERSION variable was already correctly placed in the step's env block rather than being inlined as a ${{ }} expression in the run block.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability in the 'Compose URL' step of action.yml. Replaced the vulnerable `sed "s|{VERSION}|$VERSION|g"` command (where $VERSION could contain shell metacharacters like |, ;, or $(...) that break out of the sed argument) with bash's built-in string substitution: `FINAL_URL="${URL//\{VERSION\}/$VERSION}"`. Bash parameter expansion treats the replacement value literally without invoking a subprocess, eliminating the injection risk. The $VERSION and $URL values were already correctly placed in the step's env: block.

