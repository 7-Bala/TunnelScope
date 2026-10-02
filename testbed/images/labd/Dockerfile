# Lab D (EXP-43): the final, untouched test for EXP-42's chosen model. Every tool differs from our shipped generators,
# labs A and B, and lab C (see experiments/exp42-generalise/PREREG.md, "Final test").
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        aria2 lighttpd httrack \
        gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
        ngircd ii msmtp opensmtpd mosh openssh-server openssh-client fping \
        python3 iproute2 iputils-ping procps expect ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
