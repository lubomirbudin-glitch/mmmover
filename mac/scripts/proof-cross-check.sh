#!/bin/bash
# Plan 11 (Offload Proof, M5b): the Mac CLI and the independent verifier shared/proof/verify_proof.py agree — the same
# SHA-256 line, the same RESULT line and the same exit code — on a proof the Mac CLI made and on the Windows fixtures.
# Run from mac/ after `swift build -c release` (CI: the arm64 and the Intel job; it needs only .build/release/mmmover and
# python3). The card is a small exFAT disk image with random clips (the CLI copies only from another volume), copied onto two
# folders of $RUNNER_TEMP with the settings, the queue and the locks in $RUNNER_TEMP too (OFFLOAD_SETTINGS_DIR). The
# copy's stamp after the job asks the real calendars once (only a nonce'd commitment of random data leaves); nothing here
# depends on their answer: pending or "waiting for network", both verifiers say NOT YET (exit 2).
set -euo pipefail

CLI="$PWD/.build/release/mmmover"
PY="$(cd .. && pwd)/shared/proof/verify_proof.py"
FIX="$PWD/Tests/OffloadKitTests/Fixtures"
WORK="${RUNNER_TEMP:-$(mktemp -d)}/proof-cross-check"
rm -rf "$WORK"
mkdir -p "$WORK/settings" "$WORK/d1" "$WORK/d2"
export OFFLOAD_SETTINGS_DIR="$WORK/settings"

fail() {
  echo "::error::$*"
  exit 1
}

# run <out file> <command…>: stdout into the file (and the log), the exit code into $code; never stops the script.
run() {
  local out=$1
  shift
  set +e
  "$@" >"$out"
  code=$?
  set -e
  cat "$out"
}

# line <prefix> <file>: the file's line that starts with the prefix ("" when there is none).
line() { grep -m 1 "^$1" "$2" || true; }

# agree <what> <mmmover out> <verify_proof.py out> <mmmover exit> <verify_proof.py exit> <expected exit> <prefix…>:
# both exit as expected and print the same line for every prefix (the first one must be there).
agree() {
  local what=$1 mac=$2 py=$3 mc=$4 pc=$5 want=$6
  shift 6
  echo "== $what"
  echo "mmmover proof verify: exit $mc"
  echo "verify_proof.py:      exit $pc"
  local first=1 p m y
  for p in "$@"; do
    m=$(line "$p" "$mac")
    y=$(line "$p" "$py")
    echo "mmmover proof verify: $m"
    echo "verify_proof.py:      $y"
    if [[ $first == 1 && -z $m ]]; then fail "$what: mmmover printed no '$p' line"; fi
    [[ $m == "$y" ]] || fail "$what: the '$p' lines differ"
    first=0
  done
  [[ $mc == "$want" ]] || fail "$what: mmmover proof verify exited $mc, expected $want"
  [[ $pc == "$want" ]] || fail "$what: verify_proof.py exited $pc, expected $want"
}

"$CLI" --version
python3 --version

# 1. A card the Mac CLI copies, with the proof on (the default where the CPU has SHA instructions, as the app).
sha=1
if [[ $(uname -m) == x86_64 ]]; then
  features=" $(sysctl -n machdep.cpu.leaf7_features 2>/dev/null || true) "
  [[ $features == *" SHA "* ]] || sha=0
fi
echo "SHA instructions: $sha"
CARD="$WORK/card"
mkdir -p "$CARD"
hdiutil create -size 20m -fs ExFAT -volname XCARD -o "$WORK/card.dmg" >/dev/null
hdiutil attach -nobrowse -noverify -mountpoint "$CARD" "$WORK/card.dmg" >/dev/null
trap 'hdiutil detach "$CARD" -force >/dev/null 2>&1 || true' EXIT
mkdir -p "$CARD/CLIP"
head -c 300000 /dev/urandom >"$CARD/CLIP/A001C001.mov"
head -c 12345 /dev/urandom >"$CARD/CLIP/A001C002.mov"
"$CLI" copy "$CARD" --dest "$WORK/d1" --dest "$WORK/d2" --name A001 --date 2026-11-20 --no-history --no-analyze \
  --no-day-report --allow-same-device

C1="$WORK/d1/2026-11-20/A001"
C2="$WORK/d2/2026-11-20/A001"
if [[ -f $C1/_REPORT/offload_proof.json ]]; then
  cmp "$C1/_REPORT/offload_proof.json" "$C2/_REPORT/offload_proof.json" || fail "the two destinations hold different proof manifests"
  ls -l "$C1/_REPORT"
  run "$WORK/mac-clip.txt" "$CLI" proof verify "$C1/CLIP/A001C001.mov"
  mc=$code
  run "$WORK/py-clip.txt" python3 -I "$PY" "$C1/CLIP/A001C001.mov"
  pc=$code
  agree "a clip of the card the Mac CLI copied" "$WORK/mac-clip.txt" "$WORK/py-clip.txt" "$mc" "$pc" 2 \
    "SHA-256:" "File:" "RESULT:"
  run "$WORK/mac-card.txt" "$CLI" proof verify "$C2"
  mc=$code
  run "$WORK/py-card.txt" python3 -I "$PY" "$C2"
  pc=$code
  agree "the card folder on the second destination" "$WORK/mac-card.txt" "$WORK/py-card.txt" "$mc" "$pc" 2 \
    "Files:" "Proof:" "RESULT:"
  "$CLI" proof status
elif [[ $sha == 1 ]]; then
  fail "the copy made no proof manifest ($C1/_REPORT)"
else
  echo "::notice::This CPU has no SHA instructions: the proof is off by default in the Mac CLI (as Windows without --project), so the card copied here has none."
fi

# 2. The Windows fixture (made by the Windows CLI, pending at the four calendars).
W="$FIX/proof-windows/A001/Clip 01.mov"
run "$WORK/mac-windows.txt" "$CLI" proof verify "$W"
mc=$code
run "$WORK/py-windows.txt" python3 -I "$PY" "$W"
pc=$code
agree "the Windows fixture proof-windows/A001" "$WORK/mac-windows.txt" "$WORK/py-windows.txt" "$mc" "$pc" 2 \
  "SHA-256:" "File:" "RESULT:"

# 3. The Windows fixture anchored in Bitcoin block 976695 — offline (OK would need the real block explorers).
A="$FIX/proof-windows-anchored/A001/CLIP/A001C000.bin"
run "$WORK/mac-anchored.txt" "$CLI" proof verify "$A" --offline
mc=$code
run "$WORK/py-anchored.txt" python3 -I "$PY" "$A" --offline
pc=$code
agree "the anchored Windows fixture proof-windows-anchored/A001, offline" "$WORK/mac-anchored.txt" "$WORK/py-anchored.txt" \
  "$mc" "$pc" 2 "SHA-256:" "Anchor:" "RESULT:"

echo "The Mac CLI and verify_proof.py agree."
