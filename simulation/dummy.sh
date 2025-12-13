apt update
apt install -y wget

wget https://github.com/sflow/host-sflow/releases/download/v2.1.19-1/hsflowd_amd64.deb
dpkg -i hsflowd_amd64.deb
