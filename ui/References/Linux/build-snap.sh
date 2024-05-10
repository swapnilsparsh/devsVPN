#!/bin/bash

# check result of last executed command
CheckLastResult()
{
  if ! [ $? -eq 0 ]
  then #check result of last command
    if [ -n "$1" ]
    then
      echo $1
    else
      echo "FAILED"
    fi
    exit 1
  fi
}

cd "$(dirname "$0")"
SCRIPT_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
OUT_DIR="$SCRIPT_DIR/_out_bin"
PROJECT_ROOT=$( realpath "$SCRIPT_DIR/../../.." )
IVPN_DESKTOP_UI2_SOURCES="$PROJECT_ROOT/ui"

# ---------------------------------------------------------
VERSION=""
# reading version info from arguments
while getopts ":v:" opt; do
  case $opt in
    v) VERSION="$OPTARG"
    ;;
  esac
done

if [ -z "$VERSION" ]
then
  echo "Usage:"
  echo "      $0 -v <version>"
  echo "    It is possible to use additional arguments which will be passed directly to snapcraft tool"
  echo "      Example: $0 -v <version> --use-lxd"
  echo "    Note: Using Multipass leads to the consumption of an enormous amount of HDD space! Using LXD is recommended!"
  echo "    Note: Building the LXD image may FAIL sometimes due to connectivity issues. In such cases, try running: 'sudo iptables -P FORWARD ACCEPT'."
  exit 1
fi

if [[ $@ != *"--use-lxd"* ]]; then
  echo -e "You have not specified '--use-lxd'.\nUsing Multipass leads to the consumption of an enormous amount of HDD space!\nDo you really want to continue (by using Multipass)? (y/n)"
  read -p "" CONTINUE
  if [ "$CONTINUE" != "y" ]; then
    exit 1
  fi
fi

# exclude first two argunments (-v X.X.X) from $@
shift
shift

# check correct versions
echo "[i] (UI) package.json version: "
cat "${IVPN_DESKTOP_UI2_SOURCES}/package.json" | grep \"version\" | grep \"${VERSION}\"
CheckLastResult "ERROR: Please set correct version in file '${IVPN_DESKTOP_UI2_SOURCES}/package.json'"

echo "[i] (snap) snapcraft.yaml version: "
cat "${PROJECT_ROOT}/snap/snapcraft.yaml" | grep version: | grep \"${VERSION}\"
CheckLastResult "ERROR: Please set correct version in file '${PROJECT_ROOT}/snap/snapcraft.yaml'"

echo

# goto 'desktop-app' project root
echo "Entering project root folder: ${PROJECT_ROOT}"
cd ${PROJECT_ROOT}
CheckLastResult

# removing previous compilation results (to avoid including them into snap build VM)
echo "[+] REMOVING: rm -fr $SCRIPT_DIR/_out_bin/*"
rm -fr $SCRIPT_DIR/_out_bin/*
echo "[+] REMOVING: rm -fr $SCRIPT_DIR/_tmp/*"
rm -fr $SCRIPT_DIR/_tmp/*
echo "[+] REMOVING: rm -fr $PROJECT_ROOT/cli/References/Linux/_out_bin/*"
rm -fr $PROJECT_ROOT/cli/References/Linux/_out_bin/*
echo "[+] REMOVING: rm -fr $PROJECT_ROOT/cli/References/Linux/_tmp/*"
rm -fr $PROJECT_ROOT/cli/References/Linux/_tmp/*

# build snap package
echo "[+] Building Snap v${VERSION} ( snapcraft $@ )..."
snapcraft $@
CheckLastResult
echo "**************************************"
echo "[ ] *** Snap package build SUCCESS! ***"

echo "[+] Moving compiled packages to '$OUT_DIR'..."
mkdir -p $OUT_DIR
mv -f *.snap $OUT_DIR
CheckLastResult
echo "**************************************"
echo [ ] SUCCESS!
echo
cat << EOF
[NOTES]

 To install the package, use command:
    $ snap install <snap_file> --dangerous
        (argument '--dangerous' is needed because package was not provideded by SnapStore)
    Example:
        $ snap install ivpn_${VERSION}_amd64.snap --dangerous
 Steps required after install of manually! build snap:
    (not required when installing from SnapStore, since the SnapStore enabled auto-connection
    of required interfaces)
    1) Manual connection of the required interfaces:
        $ sudo snap connect ivpn:network-control
        $ sudo snap connect ivpn:firewall-control
    2) Restart daemon:
        $ sudo snap restart ivpn.daemon

 To release/deploy package to SnapStore (only for IVPN developers!):
    $ snapcraft upload --release=<risk_level> <snap_file>
        * where <risk_level> could be: edge/beta/candidate/stable
        * https://snapcraft.io/docs/releasing-your-app
    Example:
        $ snapcraft upload --release=beta ivpn_${VERSION}_amd64.snap
EOF
