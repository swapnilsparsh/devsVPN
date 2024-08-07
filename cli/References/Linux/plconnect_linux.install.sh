#! /bin/bash

[[ $EUID -eq 0 ]]											|| { >&2 echo "ERROR: must run $0 as root"; exit 1; }

WORKDIR=$(dirname $(realpath $0))

dpkg -i $WORKDIR/../../../*/References/Linux/_out_bin/*.deb	|| { RET=$?; >&2 echo "ERROR $RET installing packages"; exit $RET; }
systemctl daemon-reload