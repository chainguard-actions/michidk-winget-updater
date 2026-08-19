<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.7

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.7** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block in action.yml directly interpolates GitHub Actions expressions into shell commands, violating rule (a). Specifically: `VERSION=${{ inputs.version || steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` are expanded by the YAML template engine before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands. These must be moved to an `env:` block and the shell variables must be double-quoted.

Locations:

- `action.yml:72`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes values derived from untrusted inputs (`inputs.version`, `inputs.url`, `steps.latest_release.outputs.result`) to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). The lines `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` and `echo "VERSION=$VERSION" >> $GITHUB_ENV` allow newline injection that can override subsequent environment variables in the same workflow run.

Locations:

- `action.yml:75`
- `action.yml:76`

### unpinned-uses (severity: high)

Multiple `uses:` references are pinned to mutable tags or version strings instead of full 40-character commit SHAs, making the action vulnerable to supply-chain attacks if the referenced tag is moved or overwritten. Failing references in action.yml: `actions/github-script@v8` (two steps), `michidk/run-komac@v2`. Failing references in workflow files: `actions/stale@v10` (pr-stale.yml), `amannn/action-semantic-pull-request@v6.1.1` (pr-title.yml), `Actions-R-Us/actions-tagger@latest` (versioning.yml — especially dangerous as `@latest` is always mutable).

Locations:

- `action.yml:36`
- `action.yml:51`
- `action.yml:83`
- `.github/workflows/pr-stale.yml:16`
- `.github/workflows/pr-title.yml:14`
- `.github/workflows/versioning.yml:11`

### missing-permissions (severity: medium)

The workflow file versioning.yml has no top-level `permissions:` key and its only job (`actions-tagger`) also has no job-level `permissions:` key. Without explicit permissions, the job inherits the default repository permissions (which may include broad write access), violating the principle of least privilege.

Locations:

- `.github/workflows/versioning.yml:1`

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

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions, static-inline-injection

**Notes:**

Fixed all findings in action.yml and the three workflow files:

1. script-injection / static-inline-injection: Moved `${{ inputs.version || steps.latest_release.outputs.result }}` and `${{ inputs.url }}` from the 'Compose URL' run: block into an env: block (as INPUT_VERSION and INPUT_URL), then referenced them as plain shell variables.

2. github-env-injection: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization for all values written to $GITHUB_ENV (FINAL_URL and VERSION), and quoted $GITHUB_ENV reference.

3. unpinned-uses: Pinned all mutable action references to full 40-character commit SHAs:
   - actions/github-script@v8 → @ed597411d8f924073f98dfc5c65a23a2325f34cd (action.yml, 2 occurrences)
   - michidk/run-komac@v2 → @9b27eadc6e9235c252444a437d246c139da2f57f (action.yml)
   - actions/stale@v10 → @1e223db275d687790206a7acac4d1a11bd6fe629 (pr-stale.yml)
   - amannn/action-semantic-pull-request@v6.1.1 → @48f256284bd46cdaab1048c3721360e808335d50 (pr-title.yml)
   - Actions-R-Us/actions-tagger@latest → @330ddfac760021349fef7ff62b372f2f691c20fb (versioning.yml)

4. missing-permissions: Added `permissions: {}` at top level and `permissions: contents: write` at job level in versioning.yml (contents:write needed for tag creation).

