# Define the tests to be excluded
exclude_list=(pk test_mix06_max30k_liv11)
# These fail when using call stack, not clear whether this is a bug with the harness,
# a bug with the algorithm or whether this example code is just not amenable to using the call stack?
exclude_list+=(xrle hello_world new_hw embench-qrduino embench-crc32 embench-cubic br_j_asm_test)

declare -A SCF
SCF[iaddress_lsb_p]=1
SCF[itype_width_p]=4

declare -A UCF
UCF[resync-max]=1
UCF[implicit-return]=true
UCF[full-address]=false
