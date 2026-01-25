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
    git \
    cmake \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs
RUN git clone https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake .. && \
    make && \
    make install && \
    ldconfig && \
    cd / && rm -rf liboqs

# Set LD_LIBRARY_PATH for liboqs
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

RUN apt-get update && apt-get install -y \
    xterm \
    x11-xserver-utils


# 2. Working directory
WORKDIR /simulation

# 3. Python deps
COPY simulation/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 4. Copy full simulation code
COPY simulation/ .

# 5. Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
