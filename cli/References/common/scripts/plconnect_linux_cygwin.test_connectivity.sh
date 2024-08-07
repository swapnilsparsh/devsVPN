#! /bin/sh

plcc status

# This will test HTTP GET connectivity to hosts internal to PL network. They are on private IP addresses, they'll be reachable only if PL VPN is connected.
for PLHOST in im.privateline.network imnode01.privateline.network ; do
	echo "-------------------------------------------------"
	curl -s -m 5.0 https://$PLHOST | head -n5
done
