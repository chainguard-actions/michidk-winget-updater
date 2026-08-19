<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.5** was hardened automatically. 5 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Compose URL' run: block in action.yml directly interpolates GitHub Actions expressions into shell commands, violating sub-rule (a). `VERSION=${{ steps.latest_release.outputs.result }}` and `URL=${{ inputs.url }}` embed untrusted step-output and input values directly into the shell script before the shell ever sees them, allowing an attacker to inject arbitrary shell commands. Additionally, sub-rule (b) is violated: `$URL` and `$VERSION` are used unquoted in `FINAL_URL=$(echo $URL | sed "s/{VERSION}/$VERSION/g")`, allowing shell metacharacter injection from those values.

Locations:

- `action.yml:57`
- `action.yml:58`
- `action.yml:59`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` to `$GITHUB_ENV` without sanitization. `FINAL_URL` is derived from `${{ inputs.url }}` (user-controlled input) and `${{ steps.latest_release.outputs.result }}` (step output), both of which are untrusted. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before the write (`echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV`), allowing a newline-injection attack to set arbitrary environment variables for subsequent steps.

Locations:

- `action.yml:60`

### unpinned-uses (severity: high)

Multiple `uses:` references are pinned to mutable tags or branch names instead of immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved or hijacked.

In action.yml:
- `uses: actions/github-script@v7` (appears twice, lines 33 and 45)
- `uses: michidk/run-komac@v2` (line 68)

In .github/workflows/pr-stale.yml:
- `uses: actions/stale@v9` (line 16)

In .github/workflows/pr-title.yml:
- `uses: aslafy-z/conventional-pr-title-action@v3` (line 14)

In .github/workflows/versioning.yml:
- `uses: Actions-R-Us/actions-tagger@latest` (line 8) — `@latest` is a mutable branch reference.

Locations:

- `action.yml:33`
- `action.yml:45`
- `action.yml:68`
- `.github/workflows/pr-stale.yml:16`
- `.github/workflows/pr-title.yml:14`
- `.github/workflows/versioning.yml:8`

### missing-permissions (severity: medium)

The workflow file versioning.yml has no top-level `permissions:` key and its only job (`actions-tagger`) also has no job-level `permissions:` key. Without explicit permissions, the workflow runs with the default repository token permissions, which may be overly broad (e.g., write access to contents). Explicit minimal permissions should be declared.

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

1. **script-injection**: Moved `${{ steps.latest_release.outputs.result }}` and `${{ inputs.url }}` from the `run:` block into the step's `env:` block as `VERSION` and `URL`. Both are now properly double-quoted in shell (`"$URL"`, `"$VERSION"`).

2. **github-env-injection**: Added `printf '%s' "$FINAL_URL" | tr -d '\n\r'` sanitization before writing to `$GITHUB_ENV`, preventing newline-injection attacks.

3. **unpinned-uses**: Pinned all 6 action references to full 40-char commit SHAs: `actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b` (×2), `michidk/run-komac@9b27eadc6e9235c252444a437d246c139da2f57f`, `actions/stale@5bef64f19d7facfb25b37b414482c7164d639639`, `aslafy-z/conventional-pr-title-action@2ce59b07f86bd51b521dd088f0acfb0d7fdac55e`, `Actions-R-Us/actions-tagger@330ddfac760021349fef7ff62b372f2f691c20fb`.

4. **missing-permissions**: Added `permissions: contents: write` at both top-level and job-level in `versioning.yml` (the actions-tagger needs write access to push tags).

5. **static-inline-injection**: Resolved as part of the script-injection fix — `${{ inputs.url }}` moved to `env:` block.

