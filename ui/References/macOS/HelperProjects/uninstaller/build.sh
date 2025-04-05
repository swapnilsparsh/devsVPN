#!/bin/bash

#save current dir
_BASE_DIR="$( pwd )"
_SCRIPT=`basename "$0"`
#enter the script folder
cd "$(dirname "$0")"
_SCRIPT_DIR="$( pwd )"

# check result of last executed command
function CheckLastResult
{
  if ! [ $? -eq 0 ]; then #check result of last command
    if [ -n "$1" ]; then
      echo $1
    else
      echo "FAILED"
    fi
    exit 1
  fi
}

# The Apple DevID certificate which will be used to sign privateLINE-Connect Agent (Daemon) binary
# The helper will check privateLINE-Connect Agent signature with this value
_SIGN_CERT="" # E.g. "WXXXXXXXXN". Specific value can be passed by command-line argument: -c <APPLE_DEVID_SERT>
while getopts ":c:" opt; do
  case $opt in
    c) _SIGN_CERT="$OPTARG"
    ;;
  esac
done

if [ -z "${_SIGN_CERT}" ]; then
  echo "Usage:"
  echo "    $0 -c <APPLE_DEVID_CERTIFICATE>"
  echo "    Example: $0 -c WXXXXXXXXN"
  exit 1
fi

if [ ! -f "../helper/net.privateline-connect.client.Helper" ]; then
  echo " File not exists '../helper/net.privateline-connect.client.Helper'. Please, compile helper project first."
  exit 1
fi

rm -fr bin
CheckLastResult

echo "[ ] *** Compiling privateLINE-Connect Installer / Uninstaller ***"

echo "[+] privateLINE-Connect Installer: updating certificate info in .plist ..."
echo "    Apple DevID certificate: '${_SIGN_CERT}'"
plutil -replace SMPrivilegedExecutables -xml \
        "<dict> \
      		<key>net.privateline-connect.client.Helper</key> \
      		<string>identifier net.privateline-connect.client.Helper and certificate leaf[subject.OU] = ${_SIGN_CERT}</string> \
      	</dict>" "privateLINE-Connect Installer-Info.plist" || CheckLastResult
plutil -replace SMPrivilegedExecutables -xml \
        "<dict> \
          <key>net.privateline-connect.client.Helper</key> \
          <string>identifier net.privateline-connect.client.Helper and certificate leaf[subject.OU] = ${_SIGN_CERT}</string> \
        </dict>" "privateLINE-Connect Uninstaller-Info.plist" || CheckLastResult

echo "[+] privateLINE-Connect Installer: make ..."
make
CheckLastResult

echo "[+] privateLINE-Connect Installer: privateLINE-Connect Installer.app ..."
mkdir -p "bin/privateLINE-Connect Installer.app/Contents/Library/LaunchServices" || CheckLastResult
mkdir -p "bin/privateLINE-Connect Installer.app/Contents/MacOS" || CheckLastResult
cp "../helper/net.privateline-connect.client.Helper" "bin/privateLINE-Connect Installer.app/Contents/Library/LaunchServices" || CheckLastResult
cp "bin/privateLINE-Connect Installer" "bin/privateLINE-Connect Installer.app/Contents/MacOS" || CheckLastResult
cp "etc/install.sh" "bin/privateLINE-Connect Installer.app/Contents/MacOS" || CheckLastResult
cp "privateLINE-Connect Installer-Info.plist" "bin/privateLINE-Connect Installer.app/Contents/Info.plist" || CheckLastResult

echo "[+] privateLINE-Connect Installer: privateLINE-Connect Uninstaller.app ..."
mkdir -p "bin/privateLINE-Connect Uninstaller.app/Contents/MacOS" || CheckLastResult
cp "bin/privateLINE-Connect Uninstaller" "bin/privateLINE-Connect Uninstaller.app/Contents/MacOS" || CheckLastResult
cp "privateLINE-Connect Uninstaller-Info.plist" "bin/privateLINE-Connect Uninstaller.app/Contents/Info.plist" || CheckLastResult

echo "[ ] privateLINE-Connect Installer: Done"
echo "    ${_SCRIPT_DIR}/bin/privateLINE-Connect Installer.app"
echo "    ${_SCRIPT_DIR}/bin/privateLINE-Connect Uninstaller.app"

cd ${_BASE_DIR}
