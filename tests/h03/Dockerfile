ARG BASE=docker.arvancloud.ir/library/ubuntu:24.04
FROM ${BASE}
ARG BUILD_TOOLS="gcc libc6-dev binutils dpkg-dev"
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d \
    && printf 'Acquire::Retries "2"; Acquire::http::Timeout "20"; Acquire::https::Timeout "20";\n' > /etc/apt/apt.conf.d/80-drill-network \
    && apt-get update \
    && apt-get install -y --no-install-recommends systemd systemd-sysv dbus adduser python3 \
       postgresql postgresql-client ca-certificates libzstd1 ${BUILD_TOOLS} \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
