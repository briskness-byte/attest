#!/bin/sh
# Is a dependency pull request safe to merge?
#
#   sh check-dep-pr.sh 1
#
# The question that matters for a signer is not "are these packages newer" but "does anything I
# ship change". Almost every dependency here is build tooling — esbuild plugins, sass, eslint —
# and a bump to those cannot reach a user, however alarming the advisory count looks. The only way
# to know that rather than assume it is to build both ways and compare the bytes.
#
# So this does four things and refuses to guess at any of them:
#
#   1. what the branch changes against its own merge base, not against your tip — a Dependabot
#      branch is usually behind, and `git diff main..pr` makes that look like it deletes your work
#   2. whether merging would actually lose anything of yours
#   3. whether the built output differs, file by file
#   4. whether the tests still pass
#
# It puts the branch, the lockfile and node_modules back afterwards, including when it fails.
set -eu
cd "$(dirname "$0")"

PR="${1:?usage: check-dep-pr.sh <pr-number>}"
REPO="${REPO:-https://github.com/briskness-byte/attest}"
WORK=$(mktemp -d)
START=$(git rev-parse --abbrev-ref HEAD)

[ -z "$(git status --porcelain -- src tests package.json yarn.lock 2>/dev/null)" ] || {
    echo "! uncommitted changes — this checks out other branches, so it needs a clean tree"; exit 1; }

cleanup() {
    git merge --abort 2>/dev/null || true
    git checkout -q "$START" 2>/dev/null || true
    git branch -D "dep-probe-$PR" 2>/dev/null >/dev/null || true
    git branch -D "dep-pr-$PR" 2>/dev/null >/dev/null || true
    # node_modules is left matching whichever lockfile ran last; put it back.
    if [ -f "$WORK/needs-restore" ]; then
        echo "restoring node_modules to $START"
        yarn install --silent >/dev/null 2>&1 || echo "  ! yarn install failed — run it by hand"
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "== building $START, to compare against =="
yarn run build >/dev/null 2>&1 || { echo "! the build is already broken before we start"; exit 1; }
find dist -type f -exec sha256sum {} \; | sort -k2 > "$WORK/before"
echo "   $(wc -l < "$WORK/before") files"

echo
echo "== fetching pull request $PR =="
git fetch -q "$REPO" "refs/pull/$PR/head:dep-pr-$PR"

# An already-merged pull request has nothing left to differ, so every check below comes back clean
# and the verdict reads SAFE — which is true and useless, and looks exactly like a real pass.
if git merge-base --is-ancestor "dep-pr-$PR" "$START"; then
    echo "   already merged into $START — nothing to check"
    exit 0
fi

BASE=$(git merge-base "$START" "dep-pr-$PR")
echo "   merge base: $(git log --oneline -1 "$BASE" | cut -c1-58)"
echo "   $(git rev-list --count "$BASE..$START") commits behind $START"

echo
echo "== what it changes, against its own base =="
git diff --stat "$BASE..dep-pr-$PR" | sed 's/^/   /'
OTHER=$(git diff --name-only "$BASE..dep-pr-$PR" | grep -v '^yarn.lock$' | grep -v '^package.json$' || true)
if [ -n "$OTHER" ]; then
    echo
    echo "   ! this touches more than the lockfile:"
    echo "$OTHER" | sed 's/^/     /'
    echo "   ! read those before merging — the rest of this check assumes a dependency bump"
fi

echo
echo "== test merge =="
git checkout -q -b "dep-probe-$PR"
git merge -q --no-edit "dep-pr-$PR"
LOST=$(git diff --name-only "$START..HEAD" -- src tests release.sh signed.sh make-update-manifest.sh | wc -l)
echo "   files of yours changed by the merge, outside the lockfile: $LOST"

touch "$WORK/needs-restore"
yarn install --silent >/dev/null 2>&1 || { echo "! yarn install failed on the new lockfile"; exit 1; }
yarn run build >/dev/null 2>&1 || { echo "! the build fails with the new lockfile"; exit 1; }
find dist -type f -exec sha256sum {} \; | sort -k2 > "$WORK/after"

echo
echo "== does anything you ship change? =="
if diff -q "$WORK/before" "$WORK/after" >/dev/null; then
    SAME=yes
    echo "   no — all $(wc -l < "$WORK/after") files are byte for byte identical"
else
    SAME=no
    echo "   YES:"
    diff "$WORK/before" "$WORK/after" | grep '^[<>]' | awk '{print "     " $1 " " $3}' | sort -u -k2 | head -20
fi

echo
echo "== tests =="
if node tests/security-boundary.mjs 2>&1 | tail -1; then TESTS=pass; else TESTS=fail; fi

echo
if [ "$SAME" = yes ] && [ "$LOST" = "0" ] && [ "$TESTS" = pass ] && [ -z "$OTHER" ]; then
    echo "SAFE — nothing you ship changes, nothing of yours is lost, tests pass."
else
    echo "LOOK AT IT — one of the checks above did not come back clean."
fi
