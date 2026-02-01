FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. System dependencies
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
    xterm \
    x11-xserver-utils \
    && rm -rf /var/lib/apt/lists/*

# 2. Install liboqs C library
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -G Ninja \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DBUILD_SHARED_LIBS=ON .. && \
    ninja install && \
    cd / && rm -rf liboqs && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf && \
    ldconfig

# Optional but safe
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

# 3. Working directory
WORKDIR /simulation

# 4. Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 5. Copy full simulation code
COPY . .

# 6. Entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

