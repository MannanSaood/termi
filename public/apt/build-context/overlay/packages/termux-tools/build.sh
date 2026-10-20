TERMUX_PKG_HOMEPAGE=https://termux.dev/
TERMUX_PKG_DESCRIPTION="Basic system tools for Termux"
TERMUX_PKG_LICENSE="GPL-3.0"
TERMUX_PKG_MAINTAINER="@termux"
TERMUX_PKG_VERSION="1.46.0+really1.45.0"
TERMUX_PKG_REVISION=1
TERMUX_PKG_SRCURL=https://github.com/termux/termux-tools/archive/refs/tags/v1.45.0.tar.gz
TERMUX_PKG_SHA256=1ae29b1b875d95cc626dae323b45a2ace759969862d96094b2fa6d13bffe20d2
TERMUX_PKG_ESSENTIAL=true
#TERMUX_PKG_AUTO_UPDATE=true
TERMUX_PKG_UPDATE_TAG_TYPE="newest-tag"
TERMUX_PKG_BREAKS="termux-keyring (<< 1.9)"
TERMUX_PKG_CONFLICTS="procps (<< 3.3.15-2)"
TERMUX_PKG_SUGGESTS="termux-api"

# Some of these packages are not dependencies and used only to ensure
# that core packages are installed after upgrading (we removed busybox
# from essentials).
TERMUX_PKG_DEPENDS="apt, bash, coreutils, dash, grep, sed, termux-exec"

# Optional packages that are distributed as part of bootstrap archives.
TERMUX_PKG_RECOMMENDS=""

termux_step_configure() { :; }
termux_step_make() { :; }
termux_step_make_install() {
    python3 - "$TERMUX_PKG_SRCDIR/scripts/pkg.in" "$TERMUX_PREFIX" "$TERMUX_CACHE_DIR" <<'PY'
import pathlib, sys
p, prefix, cache = sys.argv[1:]
cache = prefix + '/var/cache'
s = pathlib.Path(p).read_text()
old = 'source "@TERMUX_PREFIX@/bin/termux-setup-package-manager" || exit 1'
assert s.count(old) == 1
s = s.replace(old, 'TERMUX_APP_PACKAGE_MANAGER=apt')
start = s.index('select_mirror() {')
end = s.index('\nupdate_apt_cache() {', start)
s = s[:start] + 'select_mirror() { :; }\n' + s[end:]
s = s.replace('#!/bin/bash', '#!' + prefix + '/bin/bash', 1)
s = s.replace('@TERMUX_PREFIX@', prefix).replace('@TERMUX_CACHE_DIR@', cache)
s = s.replace('@PACKAGE_VERSION@', '1.45.0-termi').replace('@TERMUX_APP_PACKAGE@', 'com.terminal.nextgen')
path = pathlib.Path(prefix) / 'bin/pkg'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(s)
path.chmod(0o700)
PY
}
