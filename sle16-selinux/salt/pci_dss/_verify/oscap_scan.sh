#!/bin/sh
# oscap evaluation: produces an HTML + ARF report WITHOUT changing the system.
set -eu
DS="${1:-/usr/share/xml/scap/ssg/content/ssg-sle16-ds.xml}"
PROFILE="xccdf_org.ssgproject.content_profile_pci-dss-4"
OUT="${2:-/var/log/pci_dss-scan}"
mkdir -p "$OUT"
oscap xccdf eval \
  --profile "$PROFILE" \
  --results-arf "$OUT/arf.xml" \
  --report "$OUT/report.html" \
  "$DS" || true   # non-zero exit == some rules failed; report is still written
echo "Report: $OUT/report.html"
