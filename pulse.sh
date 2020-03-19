

sudo ip tuntap add vpn0 mode tun user $USERNAME
exec /usr/bin/sudo /usr/sbin/openconnect --juniper --servercert $CERT --user=$USERNAME $HOST -i vpn0
