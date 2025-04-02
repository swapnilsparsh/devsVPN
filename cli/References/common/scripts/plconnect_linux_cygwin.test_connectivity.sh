#! /bin/bash

for CLI in plcc privateline-connect-cli "/cygdrive/c/Program Files/privateLINE Connect/cli/privateline-connect-cli.exe" ; do
	command -v "$CLI" >/dev/null && { "$CLI" status; break; }
done

declare -A TEST_HOST_IPs_BY_HOSTNAME=( [meet.privateline.network]=10.0.5.20 [im.privateline.network]= [imnode01.privateline.network]=10.0.5.12 )

# This will test HTTP GET connectivity to hosts internal to PL network. They are on private IP addresses, they'll be reachable only if PL VPN is connected.
for HOST in "${!TEST_HOST_IPs_BY_HOSTNAME[@]}"; do
	echo "---- Testing $HOST -----------------------------------------"
	if command -v host >/dev/null; then
		echo -e "DNS:\t\t\t$(host -t A $HOST)"
	else
		echo -e "DNS:\t\t\t$(nslookup $HOST)"
	fi

	STATIC_IP=${TEST_HOST_IPs_BY_HOSTNAME[$HOST]}
	if [[ ${STATIC_IP} != "" ]]; then
		echo -e "GET / by IP:\t\t$(curl -s -m 5.0 http://${STATIC_IP} | head -n1)"
	fi

	echo -e "GET / by hostname:\t$(curl -s -m 5.0 https://$HOST | head -n1)"
done
