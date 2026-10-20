TERMUX_PKG_HOMEPAGE=https://cli.github.com/
TERMUX_PKG_DESCRIPTION="GitHub’s official command line tool"
TERMUX_PKG_LICENSE="MIT"
TERMUX_PKG_MAINTAINER="Krishna kanhaiya @kcubeterm"
TERMUX_PKG_VERSION="2.102.0"
TERMUX_PKG_REVISION=1
TERMUX_PKG_SRCURL=https://github.com/cli/cli/archive/refs/tags/v${TERMUX_PKG_VERSION}.tar.gz
TERMUX_PKG_SHA256=08bf0ef8b4409893889175e0f5279d30d6edd96465816042c0d7c72eac598158
TERMUX_PKG_RECOMMENDS="openssh"
TERMUX_PKG_AUTO_UPDATE=true

termux_step_make() {
	termux_setup_golang
	python3 /home/builder/patch_go_exec.py "$GOROOT"

	cd "$TERMUX_PKG_SRCDIR"
	# v1.4.15 was retracted for quadratic CDF parsing; pin the upstream fix.
	go mod edit -require=github.com/gabriel-vasile/mimetype@v1.4.16
	printf '%s\n' 'github.com/gabriel-vasile/mimetype v1.4.16 h1:5izNFuvA37st1dDRAcA7TtmngBmRgiIPDmTtiEvjx1E=' 'github.com/gabriel-vasile/mimetype v1.4.16/go.mod h1:3oFFwxX8kTklZwzIl2aQEDZT0lKY8xH92ST88bAwba4=' >> go.sum
	go mod download github.com/gabriel-vasile/mimetype
	(
		unset GOOS GOARCH CGO_LDFLAGS
		unset CC CXX CFLAGS CXXFLAGS LDFLAGS
		go run ./cmd/gen-docs --man-page --doc-path $TERMUX_PREFIX/share/man/man1/
	)
	export GOPATH=$TERMUX_PKG_BUILDDIR
	mkdir -p "$GOPATH"/src/github.com/cli/
	mkdir -p "$TERMUX_PREFIX"/share/doc/gh
	cp -a "$TERMUX_PKG_SRCDIR" "$GOPATH"/src/github.com/cli/cli
	cd "$GOPATH"/src/github.com/cli/cli/cmd/gh
	go get -d -v
	go build -ldflags="-X github.com/cli/cli/v${TERMUX_PKG_VERSION%%.*}/internal/build.Version=$TERMUX_PKG_VERSION"
}

termux_step_make_install() {
	install -Dm700 -t "$TERMUX_PREFIX"/bin "$GOPATH"/src/github.com/cli/cli/cmd/gh/gh

	install -Dm644 /dev/null "$TERMUX_PREFIX"/share/bash-completion/completions/gh.bash
	install -Dm644 /dev/null "$TERMUX_PREFIX"/share/zsh/site-functions/_gh
	install -Dm644 /dev/null "$TERMUX_PREFIX"/share/fish/vendor_completions.d/gh.fish
}

termux_step_create_debscripts() {
	cat <<-EOF >./postinst
		#!${TERMUX_PREFIX}/bin/sh
		gh completion -s bash > ${TERMUX_PREFIX}/share/bash-completion/completions/gh.bash
		gh completion -s zsh > ${TERMUX_PREFIX}/share/zsh/site-functions/_gh
		gh completion -s fish > ${TERMUX_PREFIX}/share/fish/vendor_completions.d/gh.fish
	EOF
}
