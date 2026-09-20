# EXP-16 real-application traffic: real client and server software, lab-only.
# Chromium (real browser + TLS/HTTP2), nginx (real HTTPS server), OpenSSH
# (real interactive session + SFTP), Postfix + swaks (real SMTP submission),
# Prosody + a real XMPP client library (slixmpp), ffmpeg (real RTP media).
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium nginx openssh-server openssh-client postfix swaks prosody \
        ffmpeg python3 python3-slixmpp ca-certificates openssl iproute2 iputils-ping \
        tcpdump procps sudo expect \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
