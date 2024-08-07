#! /bin/bash

[[ $EUID -eq 0 ]]									|| { >&2 echo "ERROR: must run $0 as root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get purge -y "privateline*"

for CONFDIR in {/root,/home/*}/.config/*privateline* /etc/opt/privateline-connect/mutable ; do
	[[ -d $CONFDIR ]] && rm -rf $CONFDIR
done