#!/bin/sh
# Builds the update manifest Firefox polls for self-distributed builds.
#
# AMO signs unlisted add-ons but does not distribute them, so nothing checks for a new version
# unless the manifest names an update_url and something answers at it. That URL is recorded at
# install time and an installed copy never learns a different one — so it has to be right before
# anyone installs, and whatever serves it has to stay where it is.
#
# Run this against the SIGNED xpi that AMO gives back, not the one that was uploaded. The hash has
# to match the bytes Firefox will actually download.
#
#   sh make-update-manifest.sh var/releases/attest-1.20.2-signed.xpi
set -eu
cd "$(dirname "$0")"

XPI="${1:?usage: make-update-manifest.sh <signed .xpi>}"
[ -f "$XPI" ] || { echo "not a file: $XPI"; exit 1; }

ID=$(python3 -c "import json;print(json.load(open('src/manifest.json'))['browser_specific_settings']['gecko']['id'])")
VER=$(python3 -c "import json;print(json.load(open('src/manifest.json'))['version'])")
BASE=https://briskness-byte.github.io/attest
HASH=$(sha256sum "$XPI" | cut -d' ' -f1)

mkdir -p var/pages
cat > var/pages/updates.json <<JSON
{
  "addons": {
    "$ID": {
      "updates": [
        {
          "version": "$VER",
          "update_link": "$BASE/attest-$VER.xpi",
          "update_hash": "sha256:$HASH"
        }
      ]
    }
  }
}
JSON
cp "$XPI" "var/pages/attest-$VER.xpi"

echo "var/pages/ holds what goes on the site:"
ls -1 var/pages/
echo
echo "copy both into the landing page repo under attest/ and push:"
echo "  cp var/pages/* ~/Projects/briskness-byte.github.io/attest/"
