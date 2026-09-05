#!/usr/bin/env bash
# Wake a sleeping Render free-tier instance and block until it actually serves.
#
# WHY THIS EXISTS
#   The free plan sleeps after ~15 min idle. A scan issues hundreds of sequential
#   requests; if the first one lands on a cold instance it times out, and red-prompt
#   scores that as the target having RESISTED the attack. The scan then completes
#   looking clean while being full of false negatives. Run this immediately before
#   every scan and every demo.
#
# USAGE
#   ./scripts/warm.sh https://redprompt-target.onrender.com
#   ./scripts/warm.sh                     # uses $RP_TARGET_URL
#
# Exits 0 only once /health has answered 200 twice in a row.
set -euo pipefail

BASE="${1:-${RP_TARGET_URL:-}}"
if [ -z "$BASE" ]; then
  echo "usage: $0 <base-url>   (or set RP_TARGET_URL)" >&2
  exit 2
fi
BASE="${BASE%/}"

DEADLINE=$(( $(date +%s) + 180 ))
STREAK=0

printf 'warming %s ' "$BASE"
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  # --max-time 30, not the default: a cold Render container legitimately takes
  # 30-60s to answer its first request. Anything shorter reports a false failure.
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$BASE/health" || echo 000)
  if [ "$code" = "200" ]; then
    STREAK=$((STREAK + 1))
    # Two in a row: one 200 can come from the proxy before the app is really ready.
    if [ "$STREAK" -ge 2 ]; then
      echo " awake"
      curl -s "$BASE/health"; echo
      exit 0
    fi
  else
    STREAK=0
  fi
  printf '.'
  sleep 3
done

echo
echo "FAILED: $BASE/health did not return 200 within 180s (last code: ${code})." >&2
echo "Do not start a scan — a cold target produces false negatives, not errors." >&2
exit 1
