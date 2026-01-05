FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. System deps
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    openvswitch-switch \
    mininet \
    sudo \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y \
    xterm \
    x11-xserver-utils


# 2. Working directory
WORKDIR /simulation

# 3. Python deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 4. Copy full simulation code
COPY . .

# 5. Entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
