#! /bin/bash

export RED='\e[1;31m'
export GREEN='\e[1;32m'
export NC='\033[0m' # No Color

set -o pipefail

for CLI in plcc privateline-connect-cli "/cygdrive/c/Program Files/privateLINE Connect/cli/privateline-connect-cli.exe" ; do
	command -v "$CLI" >/dev/null && { "$CLI" status; break; }
done

declare -A TEST_HOST_IPs_BY_HOSTNAME=( [meet.privateline.network]=10.0.5.20 [im.privateline.network]= [imnode01.privateline.network]=10.0.5.12 )

# This will test HTTP GET connectivity to hosts internal to PL network. They are on private IP addresses, they'll be reachable only if PL VPN is connected.
for HOST in "${!TEST_HOST_IPs_BY_HOSTNAME[@]}"; do
	echo "---- Testing $HOST -----------------------------------------"
	DNSCMD=
	if command -v host >/dev/null; then
		DNSCMD="host -t A $HOST"
	else
		DNSCMD="nslookup $HOST"
	fi

	if ! DNS=$($DNSCMD) ; then
		echo -e "DNS:\t\t\t${RED}FAILED${NC}"
	else
		echo -e "DNS:\t\t\t${GREEN}$DNS${NC}"
	fi

	STATIC_IP=${TEST_HOST_IPs_BY_HOSTNAME[$HOST]}
	if [[ ${STATIC_IP} != "" ]]; then
		RESPONSE=$(curl -sS -m 5.0 http://${STATIC_IP})
		if [[ $? -ne 0 ]]; then
			echo -e "GET / by IP:\t\t${RED}FAILED${NC}"
		else
			echo -e "GET / by IP:\t\t${GREEN}$(head -n 1 <<< $RESPONSE)${NC}"
		fi
	fi

	RESPONSE=$(curl -sS -m 5.0 https://$HOST)
	if [[ $? -ne 0 ]]; then
		echo -e "GET / by hostname:\t${RED}FAILED${NC}"
	else
		echo -e "GET / by hostname:\t${GREEN}$(head -n 1 <<< $RESPONSE)${NC}"
	fi
done
