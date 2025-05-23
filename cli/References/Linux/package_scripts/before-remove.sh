#!/bin/sh

echo "[*] Before remove (<%= version %> : <%= pkg %> : <%= name %> : $1)"

# When removing package: $1==0 for RPM; $1 == "remove" for DEB
_IS_REMOVE=0
if [ "$1" = "remove" -o "$1" = "0" ]; then
  _IS_REMOVE=1
fi

# Erasing Split Tunnel leftovers
# (we can not do it in 'after-remove' script, because it is executed after package/files removal)
#echo "[+] Trying to erase Firewall rules ..."
# Vlad: disabled firewall.sh calls
#if [ -f /opt/privateline-connect/etc/firewall.sh ]; then
#  printf "    * /opt/privateline-connect/etc/firewall.sh -only_dns_off: "
#  /opt/privateline-connect/etc/firewall.sh -only_dns_off >/dev/null 2>&1 && echo "OK" || echo "NOK"
#fi

echo "[+] Trying to disconnect (before-remove) ..."
/usr/bin/privateline-connect-cli disconnect || echo "[-] Failed to disconnect"

if [ $_IS_REMOVE = 1 ]; then
	# Vlad: firewall command disabled in CLI
    #echo "[+] Disabling firewall persistency (before-remove) ..."
    #/usr/bin/privateline-connect-cli firewall -persistent_off

    #echo "[+] Disabling firewall (before-remove) ..."
    #/usr/bin/privateline-connect-cli firewall -off || echo "[-] Failed to disable firewall"

	# CLI required VPN to be disconnected, or else it won't allow the logout command
    echo "[+] Logging out (before-remove) ..."
    yes | /usr/bin/privateline-connect-cli logout || echo "[-] Failed to log out"

	if [ -f /opt/privateline-connect/etc/firewall-helper.sh ]; then
	  printf "    * /opt/privateline-connect/etc/firewall-helper.sh uninstall    : "
	  /opt/privateline-connect/etc/firewall-helper.sh uninstall >/dev/null 2>&1         && echo "OK" || echo "NOK"
	fi
fi

echo "[+] Trying to delete wgprivateline interface manually, just in case ..."
/usr/sbin/ip link delete wgprivateline || echo "[-] Apparently wgprivateline interface is already down, no problem"
