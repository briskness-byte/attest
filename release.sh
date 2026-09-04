#!/bin/sh
# Bump, build, package. One command, because doing it by hand means doing it wrong once.
#
#   sh release.sh            patch bump  (1.20.3 -> 1.20.4)
#   sh release.sh 1.21.0     an exact version
#
# AMO refuses a version it has already seen, so the bump is not optional and there is no reason to
# think about it. Everything else — the id, the update_url, the min versions — is read from the
# manifest rather than repeated here, so this file cannot disagree with what ships.
set -eu
cd "$(dirname "$0")"

[ -z "$(git status --porcelain -- src build.js package.json 2>/dev/null)" ] || {
    echo "! uncommitted changes in src/ — commit them first, so the tag matches the build"; exit 1; }

NEW=$(python3 - "${1:-}" <<'PY'
import json, sys
cur = json.load(open('src/manifest.json'))['version']
want = sys.argv[1] if len(sys.argv) > 1 else ''
if want:
    print(want)
else:
    p = cur.split('.')
    p[-1] = str(int(p[-1]) + 1)
    print('.'.join(p))
PY
)

python3 - "$NEW" <<'PY'
import json, sys, collections, pathlib
for f in ('src/manifest.json', 'package.json'):
    p = pathlib.Path(f)
    d = json.loads(p.read_text(), object_pairs_hook=collections.OrderedDict)
    d['version'] = sys.argv[1]
    p.write_text(json.dumps(d, indent=2) + '\n')
PY

# The boundary between a web page and the background has been wrong twice, in opposite
# directions, and neither failure showed a symptom. Nothing ships without checking it.
if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "running tests"
    node tests/security-boundary.mjs || { echo "! tests failed — not building"; exit 1; }
    echo
fi

echo "building $NEW"
yarn run build >/dev/null 2>&1 || { echo "! build failed"; exit 1; }

rm -f var/releases/*
mkdir -p var/releases
( cd dist && zip -qr archive * ) && mv dist/archive.zip "var/releases/attest-$NEW.xpi"
( cd src && zip -qr "../var/releases/attest-$NEW-src.zip" . )

# What is actually inside the file, rather than what the source says should be.
python3 - "$NEW" <<'PY'
import json, sys, zipfile
z = zipfile.ZipFile(f'var/releases/attest-{sys.argv[1]}.xpi')
m = json.loads(z.read('manifest.json'))
g = m['browser_specific_settings']['gecko']
assert m['version'] == sys.argv[1], 'version in the package does not match'
print(f"  name {m['name']}   version {m['version']}   id {g['id']}")
print(f"  update_url {g.get('update_url','MISSING')}")
PY

ls -1sh var/releases/
cat <<TXT

next:
  1. upload var/releases/attest-$NEW.xpi at addons.mozilla.org  (On your own / unlisted)
     the -src.zip goes with it when AMO asks for sources
  2. download the SIGNED file it gives back and install that, not the one you uploaded
  3. git commit -am "Version $NEW"

when the disclosure window closes, point the update manifest at the signed file:
  sh make-update-manifest.sh ~/Downloads/attest-$NEW-signed.xpi
TXT
