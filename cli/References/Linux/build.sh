#!/bin/bash

# Usage example:
#
#  To create a testing build (fast compilation) of a console-only package (daemon+CLI) in DEB format:
#     build.sh --console --deb --test
#  To create a release build (slow compilation) of a full package (daemon+CLI+UI) in RPM format:
#     build.sh --full --rpm --release
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

print_usage_exit() {
	echo -e "\nUsage: $0 < --console | --full > < --deb | --rpm > < --test | --release > [-v,--version VER]"
  echo -e "\t--console\t\tBuild a console-only package containing daemon+CLI"
  echo -e "\t--full\t\t\tBuild a full package containing daemon+CLI+UI"
  echo -e "\t--deb\t\t\tBuild a DEB package"
  echo -e "\t--rpm\t\t\tBuild an RPM package"
  echo -e "\t--test\t\t\tBuild a package for testing - no package compression, fast compilation"
  echo -e "\t--release\t\tBuild a release package - max package compression, slow compilation"
  echo -e "\t-v, --version\t\tSpecify version"
  echo -e "\nExamples:\n"
  echo -e "\tTo create a testing build of a console-only package in DEB format:"
  echo -e "\t\tyes | $0 --console --deb --test\n"
  echo -e "\tTo create a release build of a full package in RPM format:"
  echo -e "\t\t$0 --full --rpm --release"
  exit $1
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

cd "$(dirname "$0")"
ARCH="$( node -e 'console.log(process.arch)' )"
SCRIPT_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
OUT_DIR="$SCRIPT_DIR/_out_bin"

DAEMON_REPO_ABS_PATH=$("./../config/daemon_repo_local_path_abs.sh")
CheckLastResult "Failed to determine location of privateLINE Daemon sources. Please check 'config/daemon_repo_local_path.txt'"

UI_REPO_ABS_PATH=$("./../config/ui_repo_local_path_abs.sh")
CheckLastResult "Failed to determine location of privateLINE UI sources. Please check 'config/ui_repo_local_path.txt'"

# ---------------------------------------------------------

# PKG_NAME can be:
#	privateline-connect-console     // this includes daemon+CLI
#	privateline-connect-full        // this includes daemon+CLI+UI

declare PKG_NAME= PKG_TYPE= CONFLICTS PKG_MESSAGE_SUFFIX PKG_DESCRIPTION PKG_COMPRESSION_ARGS= BUILD_FLAVOR BUILD_FLAVOR_DESCR PKGFILE=

# version info variables
VERSION=""
DATE="$(date "+%Y-%m-%d")"
COMMIT="$(git rev-list -1 HEAD)"

VALID_ARGS=$(getopt -o hv: --long help,console,full,deb,rpm,test,release,version: -- "$@")
if [[ $? -ne 0 ]]; then
    print_usage_exit 1;
fi

eval set -- "$VALID_ARGS"
while [ : ]; do
  case "$1" in
    --console)
        [[ ! -z $PKG_NAME ]]              && { >&2 echo "ERROR: PKG_NAME already set to '${PKG_NAME}'"; print_usage_exit 1; }
        PKG_NAME=privateline-connect-console
        CONFLICTS=privateline-connect-full
        PKG_MESSAGE_SUFFIX="daemon+CLI"
        shift
        ;;
    --full)
        [[ ! -z $PKG_NAME ]]              && { >&2 echo "ERROR: PKG_NAME already set to '${PKG_NAME}'"; print_usage_exit 1; }
        PKG_NAME=privateline-connect-full
        CONFLICTS=privateline-connect-console
        PKG_MESSAGE_SUFFIX="daemon+CLI+UI"
        shift
        ;;
    --deb | --rpm)
        [[ ! -z $PKG_TYPE ]]              && { >&2 echo "ERROR: PKG_TYPE already set to '${PKG_TYPE}'"; print_usage_exit 1; }
        [[ "$1" =~ ([[:alpha:]]+) ]]      || print_usage_exit 1
        PKG_TYPE=${BASH_REMATCH[1]}
        shift
        ;;
    --test)
        [[ ! -z $PKG_COMPRESSION_ARGS ]]  && { >&2 echo "ERROR: PKG_COMPRESSION_ARGS already set to '${PKG_COMPRESSION_ARGS}'"; print_usage_exit 1; }
        PKG_COMPRESSION_ARGS="--deb-compression none --rpm-compression none"
        BUILD_FLAVOR="\033[1;93mTESTING BUILD\033[0m"
        BUILD_FLAVOR_DESCR="Quick build for testing - no package compression.\n"
        shift
        ;;
    --release)
        [[ ! -z $PKG_COMPRESSION_ARGS ]]  && { >&2 echo "ERROR: PKG_COMPRESSION_ARGS already set to '${PKG_COMPRESSION_ARGS}'"; print_usage_exit 1; }
        PKG_COMPRESSION_ARGS="--deb-compression xz --rpm-compression xz --rpm-compression-level 9"
        BUILD_FLAVOR="\033[1;32mRELEASE BUILD\033[0m"
        BUILD_FLAVOR_DESCR="Release build - maximum package compression.\n"
        shift
        ;;
    -v | --version)
        VERSION="$2"
        shift 2
        ;;
    -h | --help)
        print_usage_exit 0
        ;;
    --) shift;
        break
        ;;
  esac
done

[[ -z $PKG_NAME ]]                        && { >&2 echo "ERROR: you must include '--console' or '--full' argument"; print_usage_exit 1; }
[[ -z $PKG_TYPE ]]                        && { >&2 echo "ERROR: you must include '--deb' or '--rpm' argument"; print_usage_exit 1; }
[[ -z $PKG_COMPRESSION_ARGS ]]            && { >&2 echo "ERROR: you must include '--test' or '--release' argument"; print_usage_exit 1; }

if [ -z "$VERSION" ]; then
  # Version was not provided by argument.
  # Intialize $VERSION by the data from of command: '../../../ui/package.json'
  VERSION="$(awk -F: '/"version"/ { gsub(/[" ,\n\r]/, "", $2); print $2 }' ../../../ui/package.json)"
  [ -n "$VERSION" ] || { echo >&2 "ERROR parsing version"; exit 1; }
fi

echo "[ ] You are going to compile PRIVATELINE Daemon & CLI 'v${VERSION}' (commit:${COMMIT})"
echo -e "[${BUILD_FLAVOR} - \033[1;95m${PKG_NAME}\033[0m - ${PKG_TYPE^^} - $ARCH]"
echo "Package '$PKG_NAME' will include ${PKG_MESSAGE_SUFFIX}."
echo -e ${BUILD_FLAVOR_DESCR}
echo "Architecture: $ARCH"

# Set VERSION in the package description
if [ $PKG_NAME == privateline-connect-console ]; then
	PKG_DESCRIPTION="$(printf "Client v$VERSION for privateLINE service (https://www.privateline.io)\nThis package includes daemon and command line interface. Try 'plcc' from command line.")"
else
	PKG_DESCRIPTION="$(printf "Client v$VERSION for privateLINE service (https://www.privateline.io)\nThis package includes daemon, command line interface, and graphical user interface. Try 'plcc' from command line.")"
fi

# ---------------------------------------------------------

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

if [ $PKG_NAME == privateline-connect-full ]; then
	echo '---------------------------'
	echo "Building privateLINE Connect UI ($UI_REPO_ABS_PATH)...";
	echo '---------------------------'
	$UI_REPO_ABS_PATH/References/Linux/build-ui-helper.sh -v $VERSION
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
  EXTRA_ARGS=$1

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
  if [ $PKG_NAME == privateline-connect-full ]; then
  	EXTRA_INPUTS="$UI_REPO_ABS_PATH/References/Linux/ui/privateline-connect-ui.desktop=/usr/share/applications/privateline-connect-ui.desktop \
				  $UI_REPO_ABS_PATH/References/Linux/ui/privateline-connect.svg=/usr/share/icons/hicolor/scalable/apps/privateline-connect.svg \
				  $UI_REPO_ABS_PATH/dist/bin=/opt/privateline-connect/ui/"
  fi

  declare RESOLVCONF_DEP
  if [[ ${PKG_TYPE} == deb ]]; then
  	RESOLVCONF_DEP="resolvconf | systemd-resolved | openresolv"
  elif [[ ${PKG_TYPE} == rpm ]]; then
  	RESOLVCONF_DEP=/usr/sbin/resolvconf
  fi

  DEBUG_ARGS=
#  DEBUG_ARGS="--log debug --debug"

  FPMOUT=$(fpm ${DEBUG_ARGS} -d openvpn -d iptables -d "${RESOLVCONF_DEP}" $EXTRA_ARGS \
    --conflicts $CONFLICTS ${PKG_COMPRESSION_ARGS} \
    --rpm-rpmbuild-define "_build_id_links none" \
    --deb-no-default-config-files -s dir -t $PKG_TYPE -n $PKG_NAME -v $VERSION --url https://www.privateline.io --license "GNU GPL3" \
    --template-scripts --template-value pkg=$PKG_TYPE --template-value version=$VERSION \
    --vendor "privateLINE LLC" --maintainer "privateLINE LLC" \
    --description "${PKG_DESCRIPTION}" \
    --before-install "$SCRIPT_DIR/package_scripts/before-install.sh" \
    --after-install "$SCRIPT_DIR/package_scripts/after-install.sh" \
    --before-remove "$SCRIPT_DIR/package_scripts/before-remove.sh" \
    --after-remove "$SCRIPT_DIR/package_scripts/after-remove.sh" \
    --rpm-rpmbuild-define "PKG_NAME ${PKG_NAME}" \
    $DAEMON_REPO_ABS_PATH/References/Linux/etc=/opt/privateline-connect/ \
    $DAEMON_REPO_ABS_PATH/References/common/etc=/opt/privateline-connect/ \
    $DAEMON_REPO_ABS_PATH/References/Linux/scripts/_out_bin/privateline-connect-svc=/usr/bin/ \
    $OUT_DIR/privateline-connect-cli=/usr/bin/ \
    $OUT_DIR/privateline-connect-cli.bash-completion=/opt/privateline-connect/etc/privateline-connect-cli.bash-completion \
    $WG_QUICK_BIN=/opt/privateline-connect/wireguard-tools/wg-quick \
    $WG_BIN=/opt/privateline-connect/wireguard-tools/wg \
    $TMPDIRSRVC/privateline-connect-svc.dir/usr/share/pleaserun/=/usr/share/pleaserun \
    ${EXTRA_INPUTS})

#    ${KEM_HELPER_BIN}=/opt/privateline-connect/kem/kem-helper \
#    ${DNSCRYPT_PROXY_BIN}=/opt/privateline-connect/dnscrypt-proxy/dnscrypt-proxy \
#    $OBFSPXY_BIN=/opt/privateline-connect/obfsproxy/obfs4proxy \
#    $V2RAY_BIN=/opt/privateline-connect/v2ray/v2ray
# TODO FIXME: Vlad - disabled bundling kem-helper, dnscrypt-proxy, obfsproxy, v2ray for now

	# Parse fpm output like {:timestamp=>"2024-08-08T18:19:49.509475-0500", :message=>"Created package", :path=>"privateline-connect-console_1.3_amd64.deb"}
    FPMOUT=${FPMOUT//[\{]/\(}
    FPMOUT=${FPMOUT//[\}]/\)}
	FPMOUT=${FPMOUT//:[[:digit:]]}
	FPMOUT=${FPMOUT//:/\[\"}
    FPMOUT=${FPMOUT//=>/\"\]=}
    FPMOUT=${FPMOUT//,/ }
    declare -A FPMOUTMAP=$FPMOUT
    echo "${FPMOUTMAP[message]} '${FPMOUTMAP[path]}'"
    PKGFILE=${FPMOUTMAP[path]}
}

if [ ! -z "$GITHUB_ACTIONS" ]; then
  echo "! GITHUB_ACTIONS detected ! It is just a build test."
  echo "! Packages creation (DEB/RPM) skipped !"
  exit 0
fi

echo '---------------------------'
echo -e "${PKG_TYPE^^} package...\t(package compression settings: '${PKG_COMPRESSION_ARGS}')"
# to add dependency from another packet add extra arg "-d", example: "-d obfsproxy"
CreatePackage

echo '---------------------------'
echo "Moving compiled package '$PKGFILE' to '$OUT_DIR'..."
mkdir -p $OUT_DIR
#find $TMPDIR -type f ! -empty -name "*.${PKG_TYPE}" -exec mv -f "{}" ${OUT_DIR} \;
mv -f $TMPDIR/$PKGFILE ${OUT_DIR}

set +e
