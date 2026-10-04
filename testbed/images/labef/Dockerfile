# Labs E (training zoo) and F (final test) for EXP-45. One image holds every tool; experiments/exp45-more-diversity/PREREG.md fixes
# which tool belongs to which lab. None is used in labs A-D or in the shipped training sets.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server openssh-client rsync lftp vsftpd curl nginx siege lynx tmux vim-tiny nano htop procps expect \
        ffmpeg gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
        redis-server redis-tools mosquitto mosquitto-clients netcat-openbsd pv \
        dovecot-imapd dovecot-pop3d swaks libnet-ssleay-perl libio-socket-ssl-perl postfix bsd-mailx \
        hping3 nmap traceroute iputils-ping \
        nghttp2 nghttp2-client python3 python3-zmq cmatrix iproute2 ca-certificates openssl tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
