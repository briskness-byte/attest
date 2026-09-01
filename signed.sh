#!/bin/sh
# Check what AMO gave back, and put it somewhere Firefox will accept.
#
# AMO serves the signed package as application/zip, so the browser saves it as .zip with the
# add-on's internal slug for a name. Firefox's "Install Add-on From File" filters on .xpi and will
# not offer it. Renaming is the whole job — but it is worth checking first that this really is the
# signed build and not the file that was uploaded, because those look identical in a file listing
# and only one of them installs.
#
#   sh signed.sh ~/Downloads/3dc5bda67be94333829f-1.20.4.zip
#   sh signed.sh                      # picks the newest download that looks like one
set -eu
cd "$(dirname "$0")"

F="${1:-}"
[ -n "$F" ] || F=$(ls -t "$HOME/Downloads"/*.zip "$HOME/Downloads"/*.xpi 2>/dev/null | head -1)
[ -n "$F" ] && [ -f "$F" ] || { echo "! nothing to check — pass the downloaded file"; exit 1; }

unzip -l "$F" 2>/dev/null | grep -q 'META-INF/mozilla.rsa' || {
    echo "! $F is NOT signed — this is the file you uploaded, not what AMO gave back"
    echo "  get it from: addons.mozilla.org -> Manage My Submissions -> Attest"
    exit 1; }

VER=$(unzip -p "$F" manifest.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')
WANT=$(python3 -c 'import json;print(json.load(open("src/manifest.json"))["version"])')
OUT="$HOME/Downloads/attest-$VER-signed.xpi"
[ "$F" = "$OUT" ] || cp "$F" "$OUT"

echo "signed, version $VER"
[ "$VER" = "$WANT" ] || echo "  ! the source tree is at $WANT — you are installing something older"
cat <<TXT

install it:
  about:addons -> gear -> Install Add-on From File
  $OUT

then check in about:addons that it says $VER.

when the disclosure window closes:
  sh make-update-manifest.sh $OUT
TXT
