echo "1" > /proc/sys/net/ipv4/ip_forward

/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -Z
/sbin/iptables -F -t nat
/sbin/iptables -X -t nat
/sbin/iptables -Z -t nat

/sbin/iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-ports 2323
