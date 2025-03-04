#!/bin/sh

echo "[*] Before remove (<%= version %> : <%= pkg %> : <%= name %> : $1)"

# When removing package: $1==0 for RPM; $1 == "remove" for DEB
_IS_REMOVE=0
if [ "$1" = "remove" -o "$1" = "0" ]; then
  _IS_REMOVE=1
fi

echo "[+] Trying to disconnect (before-remove) ..."
/usr/bin/privateline-connect-cli disconnect || echo "[-] Failed to disconnect"

# Erasing Split Tunnel leftovers
# (we can not do it in 'after-remove' script, because it is executed after package/files removal)
echo "[+] Trying to erase Split Tunnel rules ..."
# Vlad: disabled firewall.sh calls
#if [ -f /opt/privateline-connect/etc/firewall.sh ]; then
#  printf "    * /opt/privateline-connect/etc/firewall.sh -only_dns_off: "
#  /opt/privateline-connect/etc/firewall.sh -only_dns_off >/dev/null 2>&1 && echo "OK" || echo "NOK"
#fi
if [ -f /opt/privateline-connect/etc/firewall-helper.sh ]; then
  printf "    * /opt/privateline-connect/etc/firewall-helper.sh reset        : "
  /opt/privateline-connect/etc/firewall-helper.sh reset >/dev/null 2>&1         && echo "OK" || echo "NOK"
  printf "    * /opt/privateline-connect/etc/firewall-helper.sh stop         : "
  /opt/privateline-connect/etc/firewall-helper.sh stop >/dev/null 2>&1          && echo "OK" || echo "NOK"
fi

if [ $_IS_REMOVE = 1 ]; then
    echo "[+] Disabling firewall persistency (before-remove) ..."
    /usr/bin/privateline-connect-cli firewall -persistent_off

    echo "[+] Disabling firewall (before-remove) ..."
    /usr/bin/privateline-connect-cli firewall -off || echo "[-] Failed to disable firewall"

    echo "[+] Logging out (before-remove) ..."
    yes | /usr/bin/privateline-connect-cli logout || echo "[-] Failed to log out"
fi
