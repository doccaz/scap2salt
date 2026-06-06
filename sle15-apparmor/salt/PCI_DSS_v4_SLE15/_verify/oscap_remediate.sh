#!/bin/sh
# Cross-check / fallback: let oscap remediate directly (independent of Salt).
# Use only to compare against the Salt result, not as the primary path.
set -eu
DS="${1:-/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml}"
oscap xccdf eval --profile "xccdf_org.ssgproject.content_profile_pci-dss-4" --remediate \
  --results-arf /var/log/pci_dss-remediate-arf.xml "$DS" || true
