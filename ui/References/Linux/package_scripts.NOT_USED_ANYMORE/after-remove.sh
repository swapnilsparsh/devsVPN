#!/bin/sh

echo "[*] After remove (<%= version %> : <%= pkg %> : $1)"

# Obtaining information about user running the script
# (script can be executed with 'sudo', but we should get real user)
USER="${SUDO_USER:-$USER}"
UI_APP_USER_DIR="/home/${USER}/.config/privateline-connect-ui"
UI_APP_USER_DIR_OLD="/home/${USER}/.config/privateline-connect-ui" # (old productName='privateline-connect-ui')

AUTOSTART_FILE="/home/${USER}/.config/autostart/privateline-connect-ui.desktop"

DESKTOP_FILE_DIR=/usr/share/applications
DESKTOP_FILE=/usr/share/applications/privateline-connect-ui.desktop

silent() {
  "$@" > /dev/null 2>&1
}

# STOPPING APPLICATION (same functionality implemented also in 'before-install.sh')
echo "[+] Checking for 'privateline-connect-ui' running processes ..."
ps aux | grep /opt/privateline-connect/ui/bin/privateline-connect-ui %u | grep -v grep  > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "[!] Detected: privateLINE app is running"

  # We should be careful here: WE SHOULD NOT KILL THIS SCRIPT :)
  # (which also can have 'privateline-connect-ui' in process description)
  silent kill -TERM $(ps aux | grep /opt/privateline-connect/ui/bin/privateline-connect-ui %u | grep -v grep | awk '{print $2}')
  silent sleep 2
  silent kill -KILL $(ps aux | grep /opt/privateline-connect/ui/bin/privateline-connect-ui %u | grep -v grep | awk '{print $2}')
fi

# DEB argument on upgrade - 'upgrade'; RPM - '1'
if [ "$1" = "upgrade" ] || [ "$1" = "1" ] ; then
  # UPGRADE

  if [ -d $UI_APP_USER_DIR ] ; then
    echo "[!] Upgrade detected"
    echo "    Keeping application cache data from the previous version:"
    echo "    '$UI_APP_USER_DIR'"
  else
    # this is necessary for old application version (old productName='privateline-connect-ui')
    if [ -d $UI_APP_USER_DIR_OLD ] ; then 
      echo "[!] Upgrade detected"
      echo "[+] Upgrading application old app version cache data ..."
      mv $UI_APP_USER_DIR_OLD $UI_APP_USER_DIR || echo "[-] Failed"
    fi
  fi

else
  # REMOVE
  if [ -e $DESKTOP_FILE ] ; then
    echo "[+] Uninstalling .desktop file: '$DESKTOP_FILE' ..."
    rm $DESKTOP_FILE || echo "[-] Failed"
  fi

  if [ -d $UI_APP_USER_DIR ] ; then
    echo "[+] Removing application cache data: '$UI_APP_USER_DIR' ..."
    rm -rf $UI_APP_USER_DIR || echo "[-] Failed"
  fi

  if [ -f $AUTOSTART_FILE ]; then
    echo "[+] Removing application autostart file: '$AUTOSTART_FILE' ..."
    rm $AUTOSTART_FILE || echo "[-] Failed"
  fi

fi

# removing old application version cache (old productName='privateline-connect-ui')
if [ -d $UI_APP_USER_DIR_OLD ] ; then 
  echo "[+] Removing application cache data (old app version): '$UI_APP_USER_DIR_OLD' ..."
  rm -rf $UI_APP_USER_DIR_OLD || echo "[-] Failed"
fi
