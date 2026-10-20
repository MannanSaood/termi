TERMUX_PKG_HOMEPAGE=https://github.com/termux
TERMUX_PKG_DESCRIPTION="GPG public keys for the official Termux repositories"
TERMUX_PKG_LICENSE="Apache-2.0"
TERMUX_PKG_MAINTAINER="@termux"
TERMUX_PKG_VERSION=3.14
TERMUX_PKG_AUTO_UPDATE=false
TERMUX_PKG_SKIP_SRC_EXTRACT=true
TERMUX_PKG_PLATFORM_INDEPENDENT=true
TERMUX_PKG_ESSENTIAL=true

termux_step_make_install() {
    install -d "$TERMUX_PREFIX/share/termux-keyring"
    printf '%s\n' 'Termi uses an APK-provisioned, repository-scoped signed-by key.' > "$TERMUX_PREFIX/share/termux-keyring/README.termi"
}
