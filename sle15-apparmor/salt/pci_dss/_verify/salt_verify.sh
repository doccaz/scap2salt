#!/bin/sh
# Dry-run the generated Salt states: shows drift without applying.
set -eu
salt-call --local state.apply pci_dss test=True
