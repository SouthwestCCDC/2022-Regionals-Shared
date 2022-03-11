#!/bin/bash

TCP_PORTS_IN = (22)
TCP_PORTS_OUT = (22 80 443)
PING=true
DNS=true

#Flush existing rules
iptables -F

#Set defaults
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#Allow ping
if $PING; then
	iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
	iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
fi

#Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -i lo -j ACCEPT

#Allow DNS
if $DNS; then
	iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
fi

#Set ingress rules
for port in TCP_PORTS_IN
do
	iptables -A INPUT -p tcp --dport $port -j ACCEPT
done

#Set egress rules
for port in TCP_PORTS_OUT
do
	iptables -A OUTPUT -p tcp --dport $port -j ACCEPT
done

#Backup rules
iptables-save > /etc/network/iptables.rules
