# Attempt to find the top level for building and running
# If in a fixed place within a git repository then we could use something like this
#if git rev-parse --git-dir > /dev/null 2>&1; then
#    export TOP_LEVEL=`(cd ${script_dir}; git rev-parse --show-toplevel)`
#
# however, if put inside a deeper hierarchy this would break. So try to find the
# "top level" by locating a file that must be present.
if [ -e $script_dir/../bin/spike.sh ]; then
    export TOP_LEVEL="$( echo $script_dir | rev | cut -d'/' -f2- | rev )"
elif [ -e $script_dir/../../bin/spike.sh ]; then
    export TOP_LEVEL="$( echo $script_dir | rev | cut -d'/' -f3- | rev )"
else
    echo "Error: unable to determine the top level directory"
    exit 1
fi
