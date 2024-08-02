#!/bin/bash

# Usage example:
#
#	Release build (slow):
#   build-packages.sh -v 0.0.1
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
declare BUILD_TYPE DEB_COMPRESSION_ARGS RPM_COMPRESSION_ARGS

if [[ $0 =~ .*build-debug ]]; then
	echo -e "[\033[1;93mDEBUG BUILD\033[0m]"
	echo -e "No package compression for debug build. Building DEB, but not RPM.\n"
	BUILD_TYPE=debug
	DEB_COMPRESSION_ARGS="--deb-compression none"
	RPM_COMPRESSION_ARGS="--rpm-compression none"
else
	echo -e "[\033[1;93mRELEASE BUILD\033[0m]"
	echo -e "High package compression (slow) for release build. Building DEB, but not RPM.\n"
	BUILD_TYPE=release
	DEB_COMPRESSION_ARGS="--deb-compression xz"
	RPM_COMPRESSION_ARGS="--rpm-compression xz --rpm-compression-level 9"
fi

cd "$(dirname "$0")"

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

ARCH="$( node -e 'console.log(process.arch)' )"
SCRIPT_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
OUT_DIR="$SCRIPT_DIR/_out_bin"

DAEMON_REPO_ABS_PATH=$("./../config/daemon_repo_local_path_abs.sh")
CheckLastResult "Failed to determine location of PRIVATELINE Daemon sources. Plase check 'config/daemon_repo_local_path.txt'"

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
  # Intialize $VERSION by the data from of command: '../../../ui/package.json'
  VERSION="$(awk -F: '/"version"/ { gsub(/[" ,\n\r]/, "", $2); print $2 }' ../../../ui/package.json)"
  if [ -n "$VERSION" ]
  then
    echo "[ ] You are going to compile PRIVATELINE Daemon & CLI 'v${VERSION}' (commit:${COMMIT})"
    read -p "Press enter to continue" yn
  else    
    echo "Usage:"
    echo "    $0 -v <version>"
    exit 1
  fi
fi

echo "Architecture: $ARCH"
echo '---------------------------'
echo "Building privateLINE Connect Daemon ($DAEMON_REPO_ABS_PATH)...";
echo '---------------------------'
$DAEMON_REPO_ABS_PATH/References/Linux/scripts/build-all.sh -v $VERSION
CheckLastResult "ERROR building privateLINE Connect Daemon"

echo '---------------------------'
echo "Building privateLINE Connect CLI ...";
echo '---------------------------'
$SCRIPT_DIR/compile-cli.sh -v $VERSION
CheckLastResult "ERROR building privateLINE Connect CLI"

echo "======================================================"
echo "============== Building packages ====================="
echo "======================================================"

set -e

TMPDIR="$SCRIPT_DIR/_tmp"
TMPDIRSRVC="$TMPDIR/srvc"
if [ -d "$TMPDIR" ]; then rm -Rf $TMPDIR; fi
mkdir -p $TMPDIR
mkdir -p $TMPDIRSRVC

cd $TMPDIRSRVC

echo "Preparing service..."
fpm -v $VERSION -n privateline-connect-svc -s pleaserun -t dir --deb-no-default-config-files /usr/bin/privateline-connect-svc

OBFSPXY_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/obfs4proxy_inst/obfs4proxy
WG_QUICK_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/wireguard-tools_inst/wg-quick
WG_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/wireguard-tools_inst/wg
DNSCRYPT_PROXY_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/dnscryptproxy_inst/dnscrypt-proxy
V2RAY_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/v2ray_inst/v2ray
KEM_HELPER_BIN=$DAEMON_REPO_ABS_PATH/References/Linux/_deps/kem-helper/kem-helper-bin/kem-helper

#if [ "$(find ${DNSCRYPT_PROXY_BIN} -perm 755)" != "${DNSCRYPT_PROXY_BIN}" ] || [ "$(find ${OBFSPXY_BIN} -perm 755)" != "${OBFSPXY_BIN}" ] || [ "$(find ${WG_QUICK_BIN} -perm 755)" != "${WG_QUICK_BIN}" ] || [ "$(find ${WG_BIN} -perm 755)" != "${WG_BIN}" ]
#then
#  echo ----------------------------------------------------------
#  echo "Going to change access mode to 755 for binaries:"
#  echo "  - ${OBFSPXY_BIN}"
#  echo "  - ${WG_QUICK_BIN}"
#  echo "  - ${WG_BIN}"
#  echo "  - ${DNSCRYPT_PROXY_BIN}"
#  echo "(you may be asked for credentials for 'sudo')"
#  sudo chmod 755 ${OBFSPXY_BIN}
#  sudo chmod 755 ${WG_QUICK_BIN}
#  sudo chmod 755 ${WG_BIN}
#  sudo chmod 755 ${DNSCRYPT_PROXY_BIN}
#
#  if [ "$(find ${DNSCRYPT_PROXY_BIN} -perm 755)" != "${DNSCRYPT_PROXY_BIN}" ] || [ "$(find ${OBFSPXY_BIN} -perm 755)" != "${OBFSPXY_BIN}" ] || [ "$(find ${WG_QUICK_BIN} -perm 755)" != "${WG_QUICK_BIN}" ] || [ "$(find ${WG_BIN} -perm 755)" != "${WG_BIN}" ]
#  then
#    echo "Error: Failed to change file permissions!"
#    exit 1
#  fi
#  echo ----------------------------------------------------------
#fi

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

  fpm -d openvpn -d iptables -d resolvconf $EXTRA_ARGS \
    --rpm-rpmbuild-define "_build_id_links none" \
    --deb-no-default-config-files -s dir -t $PKG_TYPE -n privateline -v $VERSION --url https://www.privateline.io --license "GNU GPL3" \
    --template-scripts --template-value pkg=$PKG_TYPE --template-value version=$VERSION \
    --vendor "privateLINE LLC" --maintainer "privateLINE LLC" \
    --description "$(printf "Client for privateLINE service (https://www.privateline.io)\nCommand line interface v$VERSION. Try 'privateline-connect-cli' from command line.")" \
    --before-install "$SCRIPT_DIR/package_scripts/before-install.sh" \
    --after-install "$SCRIPT_DIR/package_scripts/after-install.sh" \
    --before-remove "$SCRIPT_DIR/package_scripts/before-remove.sh" \
    --after-remove "$SCRIPT_DIR/package_scripts/after-remove.sh" \
    $DAEMON_REPO_ABS_PATH/References/Linux/etc=/opt/privateline-connect/ \
    $DAEMON_REPO_ABS_PATH/References/common/etc=/opt/privateline-connect/ \
    $DAEMON_REPO_ABS_PATH/References/Linux/scripts/_out_bin/privateline-connect-svc=/usr/bin/ \
    $OUT_DIR/privateline-connect-cli=/usr/bin/ \
    $OUT_DIR/privateline-connect-cli.bash-completion=/opt/privateline-connect/etc/privateline-connect-cli.bash-completion \
    $WG_QUICK_BIN=/opt/privateline-connect/wireguard-tools/wg-quick \
    $WG_BIN=/opt/privateline-connect/wireguard-tools/wg \
    $TMPDIRSRVC/privateline-connect-svc.dir/usr/share/pleaserun/=/usr/share/pleaserun
#    ${KEM_HELPER_BIN}=/opt/privateline-connect/kem/kem-helper \
#    ${DNSCRYPT_PROXY_BIN}=/opt/privateline-connect/dnscrypt-proxy/dnscrypt-proxy \
#    $OBFSPXY_BIN=/opt/privateline-connect/obfsproxy/obfs4proxy \
#    $V2RAY_BIN=/opt/privateline-connect/v2ray/v2ray 
# TODO FIXME: Vlad - disabled bundling kem-helper, dnscrypt-proxy, obfsproxy, v2ray for now
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
