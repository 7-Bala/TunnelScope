# Libreswan image for EXP-07 (cross-implementation generalisation).
# Libreswan gained RFC 9370 / ML-KEM-768 only in v5.4 (2026-08-13), and it needs
# NSS >= 3.118.1. Debian bookworm ships libreswan 4.10 / NSS 3.87, so we use
# Fedora rawhide, which packages 5.4 with NSS 3.127. Rawhide moves constantly,
# so the base image is pinned by digest and the libreswan NVR is pinned too.
FROM fedora@sha256:a9bab18d01cf2c2cf62f3e79c72623405bce14ac062995cc6651a3073c802e41
RUN dnf -y --setopt=install_weak_deps=False install \
        libreswan-5.4-5.fc46 nss-tools iproute iputils tcpdump procps-ng python3 \
    && dnf clean all
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
