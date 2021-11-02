#!/usr/bin/env bash

set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. $script_dir/setup.sh

# Check that cmake is available
if ! which cmake > /dev/null; then
    echo "Error: Building requires cmake to be installed"
    exit 1
fi

build_dir=${TOP_LEVEL}/build_te
rm -fr $build_dir
mkdir $build_dir
pushd $build_dir > /dev/null
cmake ${TOP_LEVEL} -DBUILD_TESTS=TRUE

# Extra parameters for this can be given on the command line e.g. VERBOSE=1
# Note that -j 1 will override the -j `nproc --all` if sequential build is required
make -j `nproc --all` $@
ctest -V
if which valgrind > /dev/null; then
    ctest -T memcheck
fi

popd > /dev/null
