#!/bin/bash
# Execute only inside the disposable pinned Termux builder image.
set -euo pipefail
cd /home/builder/termux-packages
mode=${1:-proof}
case "$mode" in proof|bootstrap|catalog) ;; *) echo 'Expected proof, bootstrap or catalog' >&2; exit 64;; esac
export TERMUX_PKG_API_LEVEL=26
export TERMUX_PKG_MAKE_PROCESSES=2
export TERMUX_INSTALL_DEPS=false
export TERMUX_PACKAGES_OFFLINE=false
export TERMUX_SCRIPTDIR="$PWD"
export SOURCE_DATE_EPOCH=$(python3 -c 'import json; print(json.load(open("/home/builder/source.json"))["source_date_epoch"])')
# properties.sh assigns this value itself; preparation must patch it before build.
source ./scripts/properties.sh
test "$TERMUX_APP__PACKAGE_NAME" = com.terminal.nextgen
test "$TERMUX_PREFIX" = /data/data/com.terminal.nextgen/files/usr
mkdir -p /home/builder/artifacts
cp /home/builder/upstream.lock.json /home/builder/patches.json /home/builder/source.json /home/builder/artifacts/
exec > >(tee /home/builder/artifacts/build.log) 2>&1
printf 'TERMI_BUILD_START mode=%s prefix=%s arch=aarch64 api=26\n' "$mode" "$TERMUX_PREFIX"
if [ "$mode" = catalog ]; then
    # Explicit owner-approved expansion; dependencies are source-built and the
    # published runtime closure is selected separately from build-only outputs.
    for root in git gh; do
        ./build-package.sh -a aarch64 -j 2 "$root"
    done
elif [ "$mode" = proof ]; then
    ./build-package.sh -a aarch64 -j 2 hello
else
    # Upstream build-bootstraps extracts every built .deb, including build-only
    # tools. Build the roots here and let host APT select the runtime closure.
    for root in apt bash termux-exec termux-tools hello; do
        ./build-package.sh -a aarch64 -j 2 "$root"
    done
fi
python3 /home/builder/collect_artifacts.py output /home/builder/artifacts
if [ "$mode" = bootstrap ]; then
    python3 /home/builder/assemble_bootstrap.py --debs output \
        --hello output/hello_2.12.3-1_aarch64.deb --output /home/builder/artifacts/bootstrap
fi
cd /home/builder/artifacts
sha256sum ./*.deb ./*.json > SHA256SUMS
if [ "$mode" = bootstrap ]; then sha256sum bootstrap/* >> SHA256SUMS; fi
printf 'TERMI_BUILD_CANDIDATE_COMPLETE; no installation or release approval\n'
