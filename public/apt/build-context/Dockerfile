FROM ghcr.io/termux/package-builder@sha256:44999857244619e25bc8e3427904a16d36cc0c0e087704af039e5bdf94814ac9
USER root
ADD --chown=builder:builder source.tar /home/builder/termux-packages/
COPY --chown=builder:builder overlay/ /home/builder/termux-packages/
COPY --chown=builder:builder build-in-container.sh collect_artifacts.py assemble_bootstrap.py patch_go_exec.py upstream.lock.json patches.json source.json /home/builder/
RUN find /home/builder/termux-packages -name "*.sh" -exec chmod u+x {} +
USER builder
WORKDIR /home/builder/termux-packages
ENTRYPOINT ["/bin/bash", "/home/builder/build-in-container.sh"]
