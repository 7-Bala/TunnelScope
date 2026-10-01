# Lab C (EXP-41): a third traffic lab. Generators chosen to differ from our shipped ones (tgen, EXP-16 apps) and from the two
# public labs (python servers/ffmpeg HLS+RTP/aiosmtpd/websockets; curl/scp/ffmpeg ranges/SIPp/ping).
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        iperf3 wget curl busybox mosquitto mosquitto-clients ffmpeg python3 iproute2 iputils-ping procps expect telnet socat \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
