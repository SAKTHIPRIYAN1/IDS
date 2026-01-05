ip link set veth-so up
ip addr add 172.17.250.2/24 dev veth-so
ip route add default via 172.17.250.1