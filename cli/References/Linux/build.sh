#!/bin/bash

# Usage example:
#
# FIXME: Vlad - update
#	Release build (slow compilation):
#   build-packages.sh -v 0.0.1
#	Testing build (fast compilation):
#   build-debug -v 0.0.1
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

cd "$(dirname "$0")"

print_usage_exit() {
  # FIXME: Vlad - flesh out
	>&2 echo "ERROR: cannot call $0 directly, must call it through one of symlinks"
	exit 1
}

# check result of last executed command
CheckLastResult() {
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

DAEMON_REPO_ABS_PATH=$("./../config/daemon_repo_local_path_abs.sh")
CheckLastResult "Failed to determine location of privateLINE Daemon sources. Please check 'config/daemon_repo_local_path.txt'"

UI_REPO_ABS_PATH=$("./../config/ui_repo_local_path_abs.sh")
CheckLastResult "Failed to determine location of privateLINE UI sources. Please check 'config/ui_repo_local_path.txt'"

# ---------------------------------------------------------

# PKGNAME can be:
#	privateline-connect-console     // this includes daemon+CLI
#	privateline-connect-full        // this includes daemon+CLI+UI

declare PKGNAME= PKGTYPE= CONFLICTS PKG_MESSAGE PKG_DESCRIPTION DEB_COMPRESSION_ARGS= RPM_COMPRESSION_ARGS=

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

VALID_ARGS=$(getopt -o vcfdrtr --long version,console,full,deb,rpm,test,release -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1;
fi

eval set -- "$VALID_ARGS"
while [ : ]; do
  case "$1" in
    -a | --alpha)
        echo "Processing 'alpha' option"
        shift
        ;;
    -b | --beta)
        echo "Processing 'beta' option"
        shift
        ;;
    -g | --gamma)
        echo "Processing 'gamma' option. Input argument is '$2'"
        shift 2
        ;;
    -d | --delta)
        echo "Processing 'delta' option. Input argument is '$2'"
        shift 2
        ;;
    --) shift; 
        break 
        ;;
  esac
done

if [ -z "$VERSION" ]; then
  # Version was not provided by argument.
  # Intialize $VERSION by the data from of command: '../../../ui/package.json'
  VERSION="$(awk -F: '/"version"/ { gsub(/[" ,\n\r]/, "", $2); print $2 }' ../../../ui/package.json)"
  if [ -n "$VERSION" ]
  then
    echo "[ ] You are going to compile PRIVATELINE Daemon & CLI 'v${VERSION}' (commit:${COMMIT})"
#    read -p "Press enter to continue" yn
  else
    echo "Usage:"
    echo "    $0 -v <version>"
    exit 1
  fi
fi

if [[ $0 =~ .*build-console\..* ]]; then
	PKGNAME=privateline-connect-console
	CONFLICTS=privateline-connect-full
	PKG_MESSAGE="Package '$PKGNAME' will include daemon+CLI."
elif [[ $0 =~ .*build-full\..* ]]; then
	PKGNAME=privateline-connect-full
	CONFLICTS=privateline-connect-console
	PKG_MESSAGE="Package '$PKGNAME' will include daemon+CLI+UI."
else
	print_error_exit
fi

if [[ $0 =~ .*\.quick-build ]]; then
	echo -e "[\033[1;93mQUICK BUILD\033[0m - \033[1;95m$PKGNAME\033[0m]"
	echo ${PKG_MESSAGE}
	echo -e "Quick build for testing - no package compression.\n"
	DEB_COMPRESSION_ARGS="--deb-compression none"
	RPM_COMPRESSION_ARGS="--rpm-compression none"
elif [[ $0 =~ .*\.release-build ]]; then
	echo -e "[\033[1;32mRELEASE BUILD\033[0m - \033[1;95m$PKGNAME\033[0m]"
	echo ${PKG_MESSAGE}
	echo -e "Release build - maximum package compression.\n"
	DEB_COMPRESSION_ARGS="--deb-compression xz"
	RPM_COMPRESSION_ARGS="--rpm-compression xz --rpm-compression-level 9"
else
	print_error_exit
fi

# Set VERSION in the package description
if [ $PKGNAME == privateline-connect-console ]; then
	PKG_DESCRIPTION="$(printf "Client v$VERSION for privateLINE service (https://www.privateline.io)\nThis package includes daemon and command line interface. Try 'plcc' from command line.")"
else
	PKG_DESCRIPTION="$(printf "Client v$VERSION for privateLINE service (https://www.privateline.io)\nThis package includes daemon, command line interface, and graphical user interface. Try 'plcc' from command line.")"
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

if [ $PKGNAME == privateline-connect-full ]; then
	echo '---------------------------'
	echo "Building privateLINE Connect UI ($UI_REPO_ABS_PATH)...";
	echo '---------------------------'
	$UI_REPO_ABS_PATH/References/Linux/build.sh -v $VERSION
	CheckLastResult "ERROR building privateLINE Connect UI"
fi

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

  EXTRA_INPUTS=
  if [ $PKGNAME == privateline-connect-full ]; then
  	EXTRA_INPUTS="$UI_REPO_ABS_PATH/References/Linux/ui/privateline-connect-ui.desktop=/usr/share/applications/privateline-connect-ui.desktop \
				  $UI_REPO_ABS_PATH/References/Linux/ui/privateline-connect.svg=/usr/share/icons/hicolor/scalable/apps/privateline-connect.svg \
				  $UI_REPO_ABS_PATH/dist/bin=/opt/privateline-connect/ui/"
  fi

  fpm -d openvpn -d iptables -d "resolvconf | systemd-resolved | openresolv" $EXTRA_ARGS \
    --conflicts $CONFLICTS \
    --rpm-rpmbuild-define "_build_id_links none" \
    --deb-no-default-config-files -s dir -t $PKG_TYPE -n $PKGNAME -v $VERSION --url https://www.privateline.io --license "GNU GPL3" \
    --template-scripts --template-value pkg=$PKG_TYPE --template-value version=$VERSION \
    --vendor "privateLINE LLC" --maintainer "privateLINE LLC" \
    --description "${PKG_DESCRIPTION}" \
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
    $TMPDIRSRVC/privateline-connect-svc.dir/usr/share/pleaserun/=/usr/share/pleaserun \
    ${EXTRA_INPUTS}

#    ${KEM_HELPER_BIN}=/opt/privateline-connect/kem/kem-helper \
#    ${DNSCRYPT_PROXY_BIN}=/opt/privateline-connect/dnscrypt-proxy/dnscrypt-proxy \
#    $OBFSPXY_BIN=/opt/privateline-connect/obfsproxy/obfs4proxy \
#    $V2RAY_BIN=/opt/privateline-connect/v2ray/v2ray
# TODO FIXME: Vlad - disabled bundling kem-helper, dnscrypt-proxy, obfsproxy, v2ray for now
}

if [ ! -z "$GITHUB_ACTIONS" ]; then
  echo "! GITHUB_ACTIONS detected ! It is just a build test."
  echo "! Packages creation (DEB/RPM) skipped !"
  exit 0
fi

echo '---------------------------'
echo -e "DEB package...\t(compression settings: '${DEB_COMPRESSION_ARGS}')"
# to add dependency from another packet add extra arg "-d", example: "-d obfsproxy"
CreatePackage "deb" "${DEB_COMPRESSION_ARGS}"

echo '---------------------------'
#echo -e "RPM package...\t(compression settings: '${RPM_COMPRESSION_ARGS}')"
#CreatePackage "rpm" "${RPM_COMPRESSION_ARGS}"
echo -e "RPM package...\t\033[0;93mTODO:\033[0m Disabled .rpm compile for now, until we start shipping .rpm - this cuts Linux build time in half"

echo '---------------------------'
echo "Moving compiled packages to '$OUT_DIR'..."
mkdir -p $OUT_DIR
find $TMPDIR -type f ! -empty -name "*.deb" -exec mv -f "{}" $OUT_DIR \;
find $TMPDIR -type f ! -empty -name "*.rpm" -exec mv -f "{}" $OUT_DIR \;

set +e
