#!/bin/sh

echo "[*] After remove (<%= version %> : <%= pkg %> : $1)"

# Obtaining information about user running the script
# (script can be executed with 'sudo', but we should get real user)
USER="${SUDO_USER:-$USER}"

# When removing package: $1==0 for RPM; $1 == "remove" for DEB
_IS_REMOVE=0
if [ "$1" = "remove" -o "$1" = "0" ]; then
  _IS_REMOVE=1
fi

# ########################################################################################
#
# COMPATIBILITY BLOCK (BEGIN)
#
# Next block is in use only for compatibility with old package versions (v3.8.20 and older)
#
# ########################################################################################
# RPM: do not forget to remove file '/opt/privateline-connect/mutable/rpm_upgrade.lock' (if exists)
if [ "<%= pkg %>" = "rpm" ]; then
    if [ -f /opt/privateline-connect/mutable/rpm_upgrade.lock ]; then
        rm /opt/privateline-connect/mutable/rpm_upgrade.lock || echo "[-] Failed to remove rpm_upgrade.lock"
    fi
fi
# ########################################################################################
# COMPATIBILITY BLOCK (END)
# ########################################################################################

if [ $_IS_REMOVE = 0 ]; then
 	echo "[ ] Not a removal operation. Skipping base after-remove operations."
 	exit 0
fi

silent() {
  "$@" > /dev/null 2>&1
}

has_systemd() {
  # Some OS vendors put systemd in ... different places ...
  [ -d "/lib/systemd/system/" -o -d "/usr/lib/systemd/system" ] && silent command -v systemctl
}

try_systemd_stop() {
    if has_systemd ; then
        echo "[ ] systemd detected. Trying to stop service ..."

        echo "[+] Stopping service"
        silent systemctl stop privateline-connect-svc

        echo "[+] Disabling service"
        silent systemctl disable privateline-connect-svc

        if [ -f "/etc/systemd/system/privateline-connect-svc.service" ]; then
            echo "[+] Removing service"
            rm /etc/systemd/system/privateline-connect-svc.service
        fi
        if [ -f "/usr/lib/systemd/system/privateline-connect-svc.service" ]; then
            echo "[+] Removing service"
            rm /usr/lib/systemd/system/privateline-connect-svc.service
        fi
    fi
}

uninstall_bash_completion() {
    # get bash completion folder (according to https://github.com/scop/bash-completion)
    bash_competion_folder=$(pkg-config --variable=completionsdir bash-completion 2>&1)
    if [ $? -eq 0 ] && [ ! -z $bash_competion_folder ] ; then
      completion_file=${bash_competion_folder}/privateline-connect-cli
      if [ -f ${completion_file} ] ; then
        echo "[+] Uninstalling bash completion ('${completion_file}')"
        rm "${completion_file}"
      fi
    fi
}

# stop & disable service
try_systemd_stop

uninstall_bash_completion

PLEASERUN_DIR="/usr/share/pleaserun/privateline-connect-svc"
if [ -d $PLEASERUN_DIR ] ; then
  echo "[+] Service cleanup (pleaserun) ..."
  silent sh $PLEASERUN_DIR/cleanup.sh
  rm -fr $PLEASERUN_DIR
fi

#PRIVATELINE_DIR="/opt/privateline-connect"
#if [ -d $PRIVATELINE_DIR ] ; then
#  echo "[+] Removing other files ..."
#  # Normally, all files which were installed, deleted automatically.
#  # But privateline-connect-svc also writing to 'mutable' additional temporary files (uninstaller know nothing about them).
#  # Therefore, we are completely removing all content of '/opt/privateline-connect/mutable'.
#  # Also, there could stay empty dirs which were not deleted automatically.
#  rm -rf $PRIVATELINE_DIR || echo "[-] Removing '$PRIVATELINE_DIR' folder failed"
#fi

echo "[+] Removing CLI symlink /usr/bin/plcc"
rm -f /usr/bin/plcc

echo "[+] Removing mutable data ..."
PRIVATELINE_TMP="/etc/opt/privateline-connect"
rm -rf $PRIVATELINE_TMP

echo "[+] Removing logs ..."
PRIVATELINE_LOG="/var/log/privateline"
rm -rf $PRIVATELINE_LOG

# ======== If we're uninstalling a full package with UI, run its logic after the base logic ========

if [ ${DPKG_MAINTSCRIPT_PACKAGE} != privateline-connect-full ]; then
	exit $?
fi

echo "[+] Running UI removal logic ..."

UI_APP=/opt/privateline-connect/ui/bin/privateline-connect-ui

UI_APP_USER_DIR="/home/${USER}/.config/privateline-connect-ui"
UI_APP_USER_DIR_OLD="/home/${USER}/.config/privateline-connect-ui" # (old productName='privateline-connect-ui')

AUTOSTART_FILE="/home/${USER}/.config/autostart/privateline-connect-ui.desktop"

DESKTOP_FILE_DIR=/usr/share/applications
DESKTOP_FILE=/usr/share/applications/privateline-connect-ui.desktop

# STOPPING APPLICATION (same functionality implemented also in 'before-install.sh')
echo "[+] Checking for 'privateline-connect-ui' running processes ..."
ps aux | grep ${UI_APP} | grep -v grep  > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "[!] Detected: privateLINE app is running"

  # We should be careful here: WE SHOULD NOT KILL THIS SCRIPT :)
  # (which also can have 'privateline-connect-ui' in process description)
  silent kill -TERM $(ps aux | grep ${UI_APP} | grep -v grep | awk '{print $2}')
  silent sleep 2
  silent kill -KILL $(ps aux | grep ${UI_APP} | grep -v grep | awk '{print $2}')
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
