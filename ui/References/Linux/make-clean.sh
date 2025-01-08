#! /bin/bash

# Copyright (c) 2024 privateLINE, LLC.

OURDIR=$(dirname $(realpath $0))
cd "$OURDIR/../../../"			|| { RET=$?; >&2 echo "ERROR $RET cd"; exit $RET; }

rm -rf cli/References/Linux/{_out_bin,_tmp}

# don't delete compiled binaries under daemon/References/Linux/_deps/*_inst - they don't take much space
#rm -rf daemon/References/Linux/_deps/*_inst
rm -rf daemon/References/Linux/_deps/*_build
rm -rf daemon/References/Linux/_deps/kem-helper/liboqs

rm -rf daemon/References/Linux/scripts/_out_bin

rm -rf ui/{dist,node_modules,out}
rm -rf ui/References/Linux/{_out_bin,_tmp}
