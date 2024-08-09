#!/bin/sh

echo "[*] After install (<%= version %> : <%= pkg %> : $1)"

# update permissions for .desktop file and icon
DESKTOP_SRC_FILE=/usr/share/applications/privateline-connect-ui.desktop
ICON_SRC_FILE=/usr/share/icons/hicolor/scalable/apps/privateline-connect.svg
sudo chmod 755 $DESKTOP_SRC_FILE
sudo chmod 644 $ICON_SRC_FILE

# set permissions to allow non-root user to run privateline-connect-ui
sudo find /opt/privateline-connect/ui/bin -type d -exec chmod 755 "{}" \;
sudo chmod -R a+r /opt/privateline-connect/ui/bin

# create link to .desktop file
#APPS_DIR=/usr/share/applications
#DESKTOP_APPS_FILE=$APPS_DIR/privateline-connect-ui.desktop
#if [ -d "$APPS_DIR" ]; then
#    echo "[ ] Installing .desktop file..."
#    ln -fs $DESKTOP_SRC_FILE $DESKTOP_APPS_FILE || echo "[!] Failed to create link to .desktop file: '$DESKTOP_SRC_FILE' -> '$DESKTOP_APPS_FILE'"
#else
#    echo "[!] Unable to install .desktop file. Folder '$APPS_DIR' not exists"
#fi

# electron app requires 'chrome-sandbox' to be setuid root in some systems
sudo chmod 4755 /opt/privateline-connect/ui/bin/chrome-sandbox || echo "[!] Failed to 'chmod' for '/opt/privateline-connect/ui/bin/chrome-sandbox'"
