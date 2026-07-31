# INFRA-0370 — action pinning: a 40-hex SHA is not proof of a valid pin

**Date:** 2026-07-31
**Context:** Pinning every third-party GitHub Action in `.github/workflows/` to an
immutable reference.

## Finding

Two of the thirteen pins carried a well-formed 40-hex SHA that GitHub could not
resolve to a commit:

| reference | pinned SHA | what it actually was | correct commit |
| --- | --- | --- | --- |
| `Swatinem/rust-cache@v2` | `42dc69e1aa15d09112580998cf2ef0119e2e91ae` | annotated tag object for `refs/tags/v2` | `c19371144df3bb44fab255c43d04cbc2ab54d1c4` (v2.9.1) |
| `softprops/action-gh-release@v3` | `c12583777ecdfd3be55c69cf75464299dc01057e` | annotated tag object for `refs/tags/v3` | `3d0d9888cb7fd7b750713d6e236d1fcb99157228` (v3.0.2) |

`GET /repos/{owner}/{repo}/git/refs/tags` returns `.object.sha`, which for an
**annotated** tag is the SHA of the *tag object*, not of the commit it points
at. Lightweight tags return the commit directly, which is why most pins in the
same batch were correct and only these two were wrong — the failure is silent
and depends on how each upstream maintainer happens to tag releases.

`uses: owner/repo@<tag-object-sha>` does not resolve at job start. The failure
surfaces only when the workflow runs, i.e. after merge.

## Why the obvious guard misses it

A pin guard that checks reference *shape* (`@[0-9a-f]{40}$`) passes a tag-object
SHA — it is 40 hex characters. Shape alone cannot distinguish the two.

## What was done

`scripts/check-actions-pinned.sh` gained `--verify-remote`, which resolves each
pin through `GET /repos/{repo}/commits/{sha}` and fails on 404/422 while
degrading to a warning when the API is unreachable (rate limit, offline runner).
CI runs it with `GITHUB_TOKEN`. Negative control: reintroducing the tag-object
SHA is rejected by `--verify-remote` and accepted by the offline shape check,
which demonstrates both the gap and the fix.

## Rule of thumb

To pin an action, dereference the tag rather than reading the ref:

```bash
gh api repos/OWNER/REPO/git/ref/tags/TAG --jq '.object.sha'   # may be a tag object
gh api repos/OWNER/REPO/git/tags/TAG_OBJECT_SHA --jq '.object.sha'  # the commit
gh api repos/OWNER/REPO/commits/SHA --jq '.sha'   # always confirm before committing
```

## Related

Also observed while auditing runner labels: `release-deploy.yml` targets the
label `arcana-dev`, which no runner in the `Arcanada-one` org carries (the dev
pool is `arcana-devs` / `dev`). That dev-deploy job cannot be picked up. Left
unchanged as out of scope for INFRA-0370; recorded here and in the PR body.
