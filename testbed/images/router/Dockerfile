# The "router" is a deliberately dumb IP-forwarding relay with no strongSwan,
# no keys, no IPsec awareness of any kind. It exists solely to be a genuine
# third-party vantage point (T0): everything captured here is exactly what a
# passive observer on the path — with no endpoint access — would see.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        tcpdump \
        tshark \
        python3 \
        procps \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
