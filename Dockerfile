FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. System deps
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
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
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs C library (version 0.15.0)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -G Ninja \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DBUILD_SHARED_LIBS=ON .. && \
    ninja install && \
    cd / && rm -rf liboqs

RUN ldconfig /usr/local/lib

# Set LD_LIBRARY_PATH for liboqs
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

RUN apt-get update && apt-get install -y \
    xterm \
    x11-xserver-utils && \
    rm -rf /var/lib/apt/lists/*

# 2. Working directory
WORKDIR /simulation

# 3. Python deps - install liboqs-python with C library already present
COPY simulation/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 4. Copy full simulation code
COPY simulation/ .

# 5. Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
