# Labs H (training, three link speeds) and G (final test) for EXP-51. One image holds every tool; experiments/exp51-rate-invariance/PREREG.md
# and testbed/scripts/labgh_gen.sh fix which tool belongs to which lab. Two real browsers (Chromium for H, Firefox for G) give the
# fast page loads no earlier lab had.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server openssh-client expect curl wget axel nginx chromium firefox-esr w3m \
        ffmpeg gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
        python3 python3-websockets dovecot-imapd dovecot-pop3d postfix bsd-mailx \
        mtr-tiny iputils-ping socat mc bc less iproute2 openssl ca-certificates procps tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY labgh_tool.py /usr/local/bin/labgh_tool.py
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
