FROM debian:bookworm-slim

LABEL maintainer="xXSp4d3Xx <noreply@github.com>"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      curl \
      jq \
      nmap \
      arp-scan \
      p0f \
      smbclient \
      snmp \
      python3 \
      git \
      net-tools \
      iproute2 \
      sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hybrid-recon
COPY . /opt/hybrid-recon
RUN chmod +x /opt/hybrid-recon/*.sh || true

ENTRYPOINT ["/bin/bash"]
