#!/usr/bin/env bash

set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$script_dir/build.sh

examples=`find $script_dir/* -maxdepth 0 -type d -not -path "*build_*" -not -path "*run_*" -not -path "*fragment_*"`
for example in $examples; do
    example_name=`basename $example`
    build_dir=$script_dir/build_$example_name

    executable=`find $build_dir -name "*.riscv" -o -name "*.pk"`
    nresults=`echo $executable | tr " " "\n" | wc -l`
    if [ $nresults -gt 1 ]; then
        >&2 echo "Found multiple results for executable for test $example_name:"
        >&2 echo "$executable"
        exit 1
    fi

    # Use itype3_debug so that full addresses are used if debugging is needed
    $script_dir/../../scripts/ci/run_regression.sh --tidy --verbose --debug -t itype3_debug --fixed run_$example_name $executable

    echo "Completed run of $example_name"
done
