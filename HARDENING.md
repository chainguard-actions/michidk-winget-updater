<!-- markdownlint-disable -->

# Hardening Report: michidk--winget-updater/v1.1.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **michidk--winget-updater/v1.1.3** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable version tags instead of pinned 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved:
- `actions/github-script@v7` (step: Check if Package Exists)
- `actions/github-script@v7` (step: Detect Latest Release)
- `michidk/run-komac@v2` (step: Run Komac)
All should be pinned to full SHA digests, e.g. `actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7`.

Locations:

- `action.yml:31`
- `action.yml:42`
- `action.yml:68`

### script-injection (severity: high)

Rule (a): The 'Compose URL' run: block directly interpolates GitHub Actions expressions into shell command strings before the shell processes them. This allows an attacker to inject arbitrary shell commands via the `inputs.url` or `steps.latest_release.outputs.result` values:
  `VERSION=${{ steps.latest_release.outputs.result }}`
  `URL=${{ inputs.url }}`
  `echo "Detected latest Version: ${{ steps.latest_release.outputs.result }}"`
These values are template-substituted into the shell script verbatim, enabling command injection. They must be passed via `env:` variables and then referenced as quoted shell variables (e.g., `"$VERSION"`).

Locations:

- `action.yml:57`

### github-env-injection (severity: high)

The 'Compose URL' run: block writes `FINAL_URL` to `$GITHUB_ENV` without sanitization. `FINAL_URL` is derived from `${{ inputs.url }}` (untrusted input) and `${{ steps.latest_release.outputs.result }}` (untrusted step output), both interpolated directly into the shell script. The write `echo "FINAL_URL=$FINAL_URL" >> $GITHUB_ENV` does not apply the required `printf '%s' ... | tr -d '\n\r'` sanitization before writing to the special environment file, allowing newline injection to set arbitrary environment variables for subsequent steps.

Locations:

- `action.yml:62`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.url }}" appears directly in run: block of step "Compose URL"; move to env: map

Locations:

- `action.yml:66`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all four findings in action.yml:
1. Pinned actions/github-script@v7 → @f28e40c7f34bde8b3046d885e986cb6290c5673b # v7 (both occurrences)
2. Pinned michidk/run-komac@v2 → @b5627eaf2c8b839aa3be7580be1e2e5b72c13f91 # v2
3. Moved ${{ steps.latest_release.outputs.result }} and ${{ inputs.url }} out of the 'Compose URL' run: block into an env: map (as VERSION and INPUT_URL), then referenced them as quoted shell variables
4. Sanitized FINAL_URL before writing to $GITHUB_ENV using `printf '%s' "$FINAL_URL" | tr -d '\n\r'`

