#!/bin/sh

echo "[*] Before install (<%= version %> : <%= pkg %> : $1)"

# Skip installation if 'privateline' snap pachage already installed
snap list privateline > /dev/null 2>&1 && echo "[!] INSTALLATION CANCELED: The snap package 'privateline' is already installed. Please, uninstall the 'privateline' snap package first." && exit 1

PRIVATELINE_BIN="/usr/bin/privateline"
if [ ! -f ${PRIVATELINE_BIN} ] && [ -f /usr/local/bin/privateline ]; then
  # old installation path (used till v3.3.20)
  PRIVATELINE_BIN="/usr/local/bin/privateline"
  echo "[ ] Detected old installation path: '$PRIVATELINE_BIN'"
fi

if [ -f ${PRIVATELINE_BIN} ]; then
  #echo "[+] Trying to disable firewall (before install)..."
  #${PRIVATELINE_BIN} firewall -off || echo "[-] Failed to disable firewall"

  echo "[+] Trying to disconnect (before install) ..."
  ${PRIVATELINE_BIN} disconnect || echo "[-] Failed to disconnect"
fi

# Erasing Split Tunnel leftovers from old installation
# Required for: 
# - RPM upgrade
# - compatibility with old package versions (v3.12.0 and older)
if [ -f /opt/privateline/etc/firewall.sh ] || [ -f /opt/privateline/etc/splittun.sh ]; then 
  echo "[+] Trying to erase old Split Tunnel rules ..."
  if [ -f /opt/privateline/etc/firewall.sh ]; then
    printf "    * /opt/privateline/etc/firewall.sh -only_dns_off: "
    /opt/privateline/etc/firewall.sh -only_dns_off >/dev/null 2>&1 && echo "OK" || echo "NOK"
  fi
  if [ -f /opt/privateline/etc/splittun.sh ]; then
    printf "    * /opt/privateline/etc/splittun.sh reset        : "
    /opt/privateline/etc/splittun.sh reset >/dev/null 2>&1         && echo "OK" || echo "NOK"
    printf "    * /opt/privateline/etc/splittun.sh stop         : "
    /opt/privateline/etc/splittun.sh stop >/dev/null 2>&1          && echo "OK" || echo "NOK"
  fi
fi

# ########################################################################################
#
# Next lines is in use only for compatibility with old package versions (v3.10.10 and older)
#
# ########################################################################################
# Folders changed:
# "/opt/privateline/mutable" -> "/etc/opt/privateline/mutable" 
# "/opt/privateline/log"     -> "/var/log/privateline" 
if [ -d /opt/privateline/mutable ]; then 
  echo "[+] Migrating old-style mutable data from the previous installation ..."
  mkdir -p /etc/opt/privateline
  mv /opt/privateline/mutable /etc/opt/privateline/mutable
fi
if [ -d /opt/privateline/log ]; then 
  echo "[+] Migrating old-style logs from the previous installation ..." 
  mv /opt/privateline/log /var/log/privateline
fi

# ########################################################################################
#
# Next lines is in use only for compatibility with old package versions (v3.8.20 and older)
#
# ########################################################################################

# DEB: 'before-remove' script (old versions) saving account credentials into 'upgradeID.tmp' and doing logout,
# here we have to rename it to 'toUpgradeID.tmp' (to be compatible with old installation script style)
if [ -f /opt/privateline/mutable/upgradeID.tmp ]; then
    echo "[ ] Upgrade detected (before-install: old-style)"
    mv /opt/privateline/mutable/upgradeID.tmp /opt/privateline/mutable/toUpgradeID.tmp || echo "[-] Failed to prepare accountID to re-login"
fi

# RPM: in order to sckip 'before-remove.sh \ after-remove.sh' scripts from the old-style installer
# we have to create file '/opt/privateline/mutable/rpm_upgrade.lock'
if [ "<%= pkg %>" = "rpm" ]; then
  if [ -f ${PRIVATELINE_BIN} ]; then
    mkdir -p /opt/privateline/mutable
    echo "upgrade" > /opt/privateline/mutable/rpm_upgrade.lock || echo "[-] Failed to save rpm_upgrade.lock"
  fi
fi
