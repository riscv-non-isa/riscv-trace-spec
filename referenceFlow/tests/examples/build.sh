#!/usr/bin/env bash

set -e

if ! which riscv64-unknown-elf-gcc > /dev/null; then
    if [ ! -x /opt/riscv/bin/riscv64-unknown-elf-gcc ]; then
        echo "Error: Unable to find RISCV gcc compiler"
        exit 1
    fi
fi

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

examples=`find $script_dir/* -maxdepth 0 -type d -not -path "*build_*" -not -path "*run_*" -not -path "*fragment_*"`
for example in $examples; do
    example_name=`basename $example`
    build_dir=$script_dir/build_$example_name
    rm -fr $build_dir
    mkdir $build_dir
    pushd $build_dir > /dev/null
    cmake ../$example_name
    make

    trace_file=../$example_name/$example_name.spike_pc_trace
    if [ -e $trace_file ]; then
        echo "Copy trace file for $example_name"
        cp $trace_file .
    fi
    popd > /dev/null

    echo "Completed build of $example_name"
done
