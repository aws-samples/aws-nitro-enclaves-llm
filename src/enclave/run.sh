#!/bin/sh

# Assign an IP address to local loopback 
ip addr add 127.0.0.1/32 dev lo

ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   kms.us-east-1.amazonaws.com" >> /etc/hosts

touch /app/libnsm.so

#Start the traffic_forwarder and server
python3.8 /app/traffic_forwarder.py 127.0.0.1 443 3 8000 &
python3.8 /app/server.py
