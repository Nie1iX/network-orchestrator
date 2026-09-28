# Disposable Ubuntu 26.04 "client" for the Linux E2E harness: systemd as
# PID 1, polkit, resolved and the tunnel tools the daemon drives. The repo
# build output is bind-mounted at run time; nothing here is app-specific.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv systemd-resolved dbus polkitd iproute2 \
      wireguard-tools openvpn python3 ca-certificates procps curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 alice \
    && useradd --create-home --uid 1002 bob
STOPSIGNAL SIGRTMIN+3
# Docker mounts cgroup2 read-only; systemd needs it writable to start.
ENTRYPOINT ["sh", "-c", "mount -o remount,rw /sys/fs/cgroup && exec /sbin/init"]
