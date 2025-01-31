#! /bin/bash

# dump nftables via 'nft list ruleset'
# dump iptables via iptables-save, ip6tables-save

for i in /proc/sys/net/ipv6/conf/{default,all}/disable_ipv6 ; do
	echo "$i = "`cat $i`
done

for FAMILY in 4 6; do
	echo
	ip -$FAMILY route show table all | grep -Fv " dev lo "
done