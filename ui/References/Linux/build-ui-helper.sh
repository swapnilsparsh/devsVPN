#!/bin/bash

# Usage example:
#
#	Release build (slow):
#   	build-packages.sh -v 0.0.1
#	Debug build (fast):
#   	build-debug -v 0.0.1
#

# To be able to build DEB/RPM packages, the 'fpm' tool shall be installed
# (https://fpm.readthedocs.io/en/latest/installing.html)

# Useful commands (Ubuntu):
#
# To view *.deb package content:
#     dpkg -c privateline_1.0_amd64.deb
# List of installet packets:
#     dpkg --list [<mask>]
# Install package:
#     apt-get install <pkg-name>
# Remove packet:
#     dpkg --remove <packetname>
# Remove (2):
#     apt-get remove privateline
#     apt-get purge curl
#     apt-get autoremove
# Remove repository (https://www.ostechnix.com/how-to-delete-a-repository-and-gpg-key-in-ubuntu/):
#     add-apt-repository -r ppa:wireguard/wireguard
#     apt update
# List of services:
#     systemctl --type=service
# Start service:
#     systemctl start privateline-connect-svc
# Remove BROKEN package (which is unable to uninstall by normal ways)
#     sudo mv /var/lib/dpkg/info/privateline.* /tmp/
#     sudo dpkg --remove --force-remove-reinstreq privateline


#declare BUILD_TYPE DEB_COMPRESSION_ARGS RPM_COMPRESSION_ARGS

#if [[ $0 =~ .*build-debug ]]; then
#	echo -e "[\033[1;93mDEBUG BUILD\033[0m]"
#	echo -e "No package compression for debug build. Building DEB, but not RPM.\n"
#	BUILD_TYPE=debug
#	DEB_COMPRESSION_ARGS="--deb-compression none"
#	RPM_COMPRESSION_ARGS="--rpm-compression none"
#else
#	echo -e "[\033[1;93mRELEASE BUILD\033[0m]"
#	echo -e "High package compression (slow) for release build. Building DEB, but not RPM.\n"
#	BUILD_TYPE=release
#	DEB_COMPRESSION_ARGS="--deb-compression xz"
#	RPM_COMPRESSION_ARGS="--rpm-compression xz --rpm-compression-level 9"
#fi

cd "$(dirname "$0")"

# check result of last executed command
CheckLastResult()
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

ARCH="$( node -e 'console.log(process.arch)' )"
SCRIPT_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
OUT_DIR="$SCRIPT_DIR/_out_bin"
APP_UNPACKED_DIR="$SCRIPT_DIR/../../dist/linux-unpacked"
APP_UNPACKED_DIR_ARCH="$SCRIPT_DIR/../../dist/linux-${ARCH}-unpacked"
APP_BIN_DIR="$SCRIPT_DIR/../../dist/bin"
PRIVATELINE_DESKTOP_UI2_SOURCES="$SCRIPT_DIR/../../"

# ---------------------------------------------------------
# version info variables
VERSION=""
DATE="$(date "+%Y-%m-%d")"
COMMIT="$(git rev-list -1 HEAD)"

# reading version info from arguments
while getopts ":v:" opt; do
  case $opt in
    v) VERSION="$OPTARG"
    ;;
  esac
done

if [ -z "$VERSION" ]
then
  # Version was not provided by argument.
  # Intialize $VERSION by the data from of command: '../../package.json'
  VERSION="$(awk -F: '/"version"/ { gsub(/[" ,\n\r]/, "", $2); print $2 }' ../../package.json)"
  if [ -n "$VERSION" ]
  then
    echo "[ ] You are going to compile PrivateLine Connect UI v${VERSION} (commit:${COMMIT})"
#    read -p "Press enter to continue" yn
  else
    echo "Usage:"
    echo "    $0 -v <version>"
    exit 1
  fi
fi

#echo "Architecture: $ARCH"
echo "======================================================"
echo "======= Building privateLINE Connect UI binary ======="
echo "======================================================"

if [ -d $APP_UNPACKED_DIR ]; then
  echo "[+] Removing: $APP_UNPACKED_DIR"
  rm -fr "$APP_UNPACKED_DIR"
fi
if [ -d $APP_UNPACKED_DIR_ARCH ]; then
  echo "[+] Removing: $APP_UNPACKED_DIR_ARCH"
  rm -fr "$APP_UNPACKED_DIR_ARCH"
fi

if [ -d $APP_BIN_DIR ]; then
  echo "[+] Removing: $APP_BIN_DIR"
  rm -fr "$APP_BIN_DIR"
fi

cat "$PRIVATELINE_DESKTOP_UI2_SOURCES/package.json" | grep \"version\" | grep \"$VERSION\"
CheckLastResult "ERROR: Please set correct version in file '${PRIVATELINE_DESKTOP_UI2_SOURCES}package.json'"

echo "*** Installing NPM molules ... ***"
cd $PRIVATELINE_DESKTOP_UI2_SOURCES
CheckLastResult
npm install
CheckLastResult
cd $SCRIPT_DIR
CheckLastResult

echo "*** Building Electron app ... ***"
$SCRIPT_DIR/compile-ui.sh
CheckLastResult

if [ -d $APP_UNPACKED_DIR_ARCH ]; then
    # for non-standard architecture we must use the architecture-dependend path
    echo "Info: Non 'default' architecture!"
    APP_UNPACKED_DIR=$APP_UNPACKED_DIR_ARCH
fi
if [ -d $APP_UNPACKED_DIR ]; then
    echo "[ ] Exist: $APP_UNPACKED_DIR"
else
  echo "[!] Folder not exists: '$APP_UNPACKED_DIR'"
  echo "    Build PrivateLine Connect UI project (do not forget to set correct version for it in 'package.json')"
  exit 1
fi
if [ -f "$APP_UNPACKED_DIR/privateline-connect-ui" ]; then
    echo "[ ] Exist: $APP_UNPACKED_DIR/privateline-connect-ui"
else
  echo "[!] File not exists: '$APP_UNPACKED_DIR/privateline-connect-ui'"
  echo "    Build PrivateLine Connect UI project (do not forget to set correct version for it in 'package.json')"
  exit 1
fi

echo "[ ] Renaming: '$APP_UNPACKED_DIR' -> '$APP_BIN_DIR'"
mv $APP_UNPACKED_DIR $APP_BIN_DIR
CheckLastResult

# Vlad: refactoring for this build script to be called by CLI build scripts
#echo "DEB/RPM packages build skipped"
exit $?

if [ ! -z "$SNAPCRAFT_BUILD_ENVIRONMENT" ]; then
    echo "! SNAPCRAFT_BUILD_ENVIRONMENT detected !"
    echo "! DEB/RPM packages build skipped !"
    exit 0
fi

echo "======================================================"
echo "============== Building packages ====================="
echo "======================================================"

set -e

TMPDIR="$SCRIPT_DIR/_tmp"
if [ -d "$TMPDIR" ]; then rm -Rf $TMPDIR; fi
mkdir -p $TMPDIR

CreatePackage()
{
  PKG_TYPE=$1
  EXTRA_ARGS=$2

  cd $TMPDIR

  # Scripts order is different for different types of packages
  # DEB Install:
  #   (On Install)      (On Upgrade)
  #                     before_remove
  #   before_install    before_upgrade\before_install
  #                     after_remove
  #   after_install     after_upgrade\after_install
  #
  # DEB remove
  #   before_remove
  #   after_remove
  #
  # RPM Install:
  #   (On Install)      (On Upgrade)
  #   before_install    before_upgrade\before_install
  #   after_install     after_upgrade\after_install
  #                     before_remove
  #                     after_remove
  #
  # RPM remove
  #   before_remove
  #   after_remove
  #
  # NOTE! 'remove' scripts is using from old version!
  #
  # EXAMPLES:
  #
  # DEB
  # (Useful link: https://wiki.debian.org/MaintainerScripts)
  #
  # DEB (apt) Install3.3.30:
  #   [*] Before install (3.3.30 : deb : install)
  #   [*] After install (3.3.30 : deb : configure)
  # DEB (apt) Upgrade 3.3.20->3.3.30:
  #   [*] Before remove (3.3.20 : deb : upgrade)
  #   [*] Before install (3.3.30 : deb : upgrade)
  #   [*] After remove (3.3.20 : deb : upgrade)
  #   [*] After install (3.3.30 : deb : configure)
  # DEB (apt) Remove:
  #   [*] Before remove (3.3.20 : deb : remove)
  #   [*] After remove (3.3.20 : deb : remove)
  #
  # RPM
  # (Useful link: https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/)
  #   When scriptlets are called, they will be supplied with an argument.
  #   This argument, accessed via $1 (for shell scripts) is the number of packages of this name
  #   which will be left on the system when the action completes.
  #
  # RPM (dnf) install:
  #   [*] Before install (3.3.30 : rpm : 1)
  #   [*] After install (3.3.30 : rpm : 1)
  # RPM (dnf) upgrade:
  #   [*] Before install (3.3.30 : rpm : 2)
  #   [*] After install (3.3.30 : rpm : 2)
  #   [*] Before remove (3.3.20 : rpm : 1)
  #   [*] After remove (3.3.20 : rpm : 1)
  # RPM (dnf) remove:
  #   [*] Before remove (3.3.30 : rpm : 0)
  #   [*] After remove (3.3.30 : rpm : 0)

  fpm -d privateline $EXTRA_ARGS \
    --rpm-rpmbuild-define "_build_id_links none" \
    --deb-no-default-config-files -s dir -t $PKG_TYPE -n privateline-connect-ui -v $VERSION --url https://www.privateline.io --license "GNU GPL3" \
    --template-scripts --template-value pkg=$PKG_TYPE --template-value version=$VERSION \
    --vendor "privateLINE LLC" --maintainer "privateLINE LLC" \
    --description "$(printf "UI client for privateLINE service (https://www.privateline.io)\nGraphical interface v$VERSION.")" \
    --before-install "$SCRIPT_DIR/package_scripts/before-install.sh" \
    --after-install "$SCRIPT_DIR/package_scripts/after-install.sh" \
    --before-remove "$SCRIPT_DIR/package_scripts/before-remove.sh" \
    --after-remove "$SCRIPT_DIR/package_scripts/after-remove.sh" \
    $SCRIPT_DIR/ui/privateline-connect-ui.desktop=/usr/share/applications/privateline-connect-ui.desktop \
    $SCRIPT_DIR/ui/privateline-connect.svg=/usr/share/icons/hicolor/scalable/apps/privateline-connect.svg \
    $APP_BIN_DIR=/opt/privateline-connect/ui/
}

if [ ! -z "$GITHUB_ACTIONS" ]; 
then
  echo "! GITHUB_ACTIONS detected ! It is just a build test."
  echo "! Packages creation (DEB/RPM) skipped !"
  exit 0
fi

echo '---------------------------'
echo -e "DEB package...\t(compression settings: '${DEB_COMPRESSION_ARGS}')"
# to add dependency from another packet add extra arg "-d", example: "-d obfsproxy"
CreatePackage "deb" "${DEB_COMPRESSION_ARGS}"

echo '---------------------------'
#if [[ "${BUILD_TYPE}" == "release" ]]; then
#	echo -e "RPM package...\t(compression settings: '${RPM_COMPRESSION_ARGS}')"
#	CreatePackage "rpm" "${RPM_COMPRESSION_ARGS}"
#else
	echo -e "RPM package...\t\033[0;93mTODO:\033[0m Disabled .rpm compile for now, until we start shipping .rpm - this cuts Linux build time in half"
#fi

echo '---------------------------'
echo "Copying compiled packages to '$OUT_DIR'..."
mkdir -p $OUT_DIR
yes | cp -f $TMPDIR/*.* $OUT_DIR

set +e
