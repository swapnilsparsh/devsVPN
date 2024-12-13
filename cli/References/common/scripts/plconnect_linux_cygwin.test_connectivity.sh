#! /bin/sh

for CLI in plcc privateline-connect-cli "/cygdrive/c/Program Files/privateLINE Connect/cli/privateline-connect-cli.exe" ; do
	command -v "$CLI" >/dev/null && { "$CLI" status; break; }
done

# This will test HTTP GET connectivity to hosts internal to PL network. They are on private IP addresses, they'll be reachable only if PL VPN is connected.
for PLHOST in privateline.io im.privateline.network imnode01.privateline.network ; do
	echo "-------------------------------------------------"
	host -t A $PLHOST
	curl -s -m 5.0 https://$PLHOST | head -n2
done
