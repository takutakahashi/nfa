---
description: Merge a PR and cut a new semver release for the nfa project. Creates a git tag, GitHub release, and waits for the container image to build on ghcr.io.
---

# Release Workflow

This skill merges a PR to `main` and cuts a semver release for the `nfa` project.

## Steps

### 1. Confirm readiness

Before starting, verify:

```bash
# All CI checks on the PR must be green
gh pr checks <PR_NUMBER>

# Tests must pass locally
mise exec -- go test ./...
```

### 2. Merge the PR

```bash
gh pr merge <PR_NUMBER> --squash --auto
```

Wait for merge:
```bash
until gh pr view <PR_NUMBER> --json state -q '.state' | grep -q MERGED; do sleep 5; done
echo "merged"
```

### 3. Update local main

```bash
git checkout main && git pull origin main
```

### 4. Determine the next version

Follow [semver](https://semver.org/):
- Bug fixes / small changes → patch (`v0.1.0` → `v0.1.1`)
- New features (backwards-compatible) → minor (`v0.1.0` → `v0.2.0`)
- Breaking changes → major (`v0.1.0` → `v1.0.0`)

Check the latest tag:
```bash
git tag --sort=-v:refname | head -5
```

### 5. Create and push the tag

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### 6. Create the GitHub release

```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z — <short summary>" \
  --notes "$(cat <<'EOF'
## What's changed

- <bullet points from PR descriptions or git log>

## Container image

\`\`\`
ghcr.io/takutakahashi/nfa:vX.Y.Z
\`\`\`
EOF
)"
```

### 7. Wait for the container image to build

The CI workflow (`ci.yaml`) automatically builds and pushes the Docker image to
`ghcr.io/takutakahashi/nfa` when a tag is pushed.

Monitor the workflow run:
```bash
# Find the run triggered by the tag
gh run list --branch vX.Y.Z --limit 5

# Watch it
gh run watch <RUN_ID>
```

Or poll until all checks pass:
```bash
until gh run list --branch vX.Y.Z --json status -q '.[0].status' | grep -q completed; do sleep 15; done
gh run list --branch vX.Y.Z --json conclusion -q '.[0].conclusion'
```

The image will be available at:
```
ghcr.io/takutakahashi/nfa:vX.Y.Z
ghcr.io/takutakahashi/nfa:sha-<commit-sha>
```

### 8. Notify

```bash
agentapi-proxy client send-notification \
  --title "nfa vX.Y.Z リリース完了" \
  --body "ghcr.io/takutakahashi/nfa:vX.Y.Z が公開されました" \
  --notify-session-id "$AGENTAPI_SESSION_ID"
```

## Notes

- The `ghcr.io` push requires `packages: write` permission — already configured in `ci.yaml`.
- `--squash` merge keeps the main branch history clean.
- Tag format must be `vMAJOR.MINOR.PATCH` — the `metadata-action` semver pattern in CI depends on this.
- Do **not** force-push tags. If you need to move a tag, delete it first: `git push origin :vX.Y.Z && git tag -d vX.Y.Z`.
