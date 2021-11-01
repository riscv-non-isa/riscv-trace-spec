#!/usr/bin/env bash
if which spike > /dev/null 2>&1; then
    echo "Using `which spike`"
    spike $@
else
    BINDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
    echo "Using $BINDIR/spike"
    $BINDIR/spike $@
fi
