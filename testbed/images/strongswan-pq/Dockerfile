# Post-quantum strongSwan image, built from source, for EXP-04 (PQ key-exchange
# observability). Debian bookworm's apt package (5.9.8) predates RFC 9370/ML-KEM
# support, which landed in strongSwan 6.0.0 (Dec 2024).
#
# CORRECTION vs the original plan: our research (07-DISCOVER) described PQ
# support as arriving "via Botan 3.6+ or the oqs plugin (liboqs)". On inspecting
# the actual strongSwan 6.0.2 source, ML-KEM ships as a NATIVE, dependency-free
# plugin (`ml` — src/libstrongswan/plugins/ml/ml_kem.c) with no liboqs or Botan
# requirement. We build that instead; this is simpler and has no third-party PQ
# crypto library in the trust chain. Recorded in testbed/NOTES.md.
#
# Reproducibility: pinned tag below; exact commit SHA recorded in
# testbed/MANIFEST.md after a successful build.
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git pkg-config \
        libssl-dev libgmp-dev libcurl4-openssl-dev \
        gettext bison flex libtool autoconf automake gperf \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG STRONGSWAN_TAG=6.0.2
RUN git clone --depth 1 --branch ${STRONGSWAN_TAG} https://github.com/strongswan/strongswan.git /src/strongswan
WORKDIR /src/strongswan
RUN ./autogen.sh && ./configure \
      --prefix=/usr --sysconfdir=/etc \
      --enable-swanctl --enable-vici \
      --enable-openssl --enable-ml \
      --enable-curl --enable-charon --enable-ikev2 \
      --enable-nonce --enable-random --enable-x509 --enable-pubkey --enable-pem \
      --enable-constraints --enable-pki --enable-eap-identity --enable-updown \
      --enable-kernel-netlink --enable-socket-default --enable-resolve --enable-attr \
      --enable-aes --enable-sha1 --enable-sha2 --enable-sha3 --enable-md5 \
      --enable-gmp --enable-curve25519 --enable-hmac --enable-gcm --enable-ctr \
      --enable-ccm --enable-chapoly --enable-drbg --enable-x509 --enable-revocation \
      --enable-constraints --enable-pkcs1 --enable-pkcs7 --enable-pkcs8 \
 && make -j"$(nproc)" \
 && make install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libgmp10 libcurl4 \
        iproute2 iputils-ping tcpdump tshark python3 procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr /usr
COPY --from=builder /etc/strongswan.d /etc/strongswan.d
COPY --from=builder /etc/strongswan.conf /etc/strongswan.conf.dist
RUN ldconfig \
    && mkdir -p /etc/swanctl/conf.d /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/rsa

# Our own explicit-load strongswan.conf — see file for why load_modular
# doesn't work with this source build. This is overridden at container run
# time by the volume-mounted testbed/configs/{alice,bob}/strongswan.conf,
# same as the classical image, but ships a working default for standalone use.
COPY strongswan.conf /etc/strongswan.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
