#!/bin/sh
# Real APT installation/upgrade tests with synthetic packages in a disposable container.
# No tunnels, network capabilities, services or host package database are used.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec docker run --rm --network none \
    -v "$ROOT:/source:ro" -w /source \
    -e PYTHONDONTWRITEBYTECODE=1 -e NETORCH_INSTALLER_APT_E2E=1 \
    python:3.12-slim-bookworm python3 e2e/linux/test_installers.py
