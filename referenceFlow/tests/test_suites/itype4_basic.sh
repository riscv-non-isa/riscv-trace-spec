# Define the tests to be excluded
exclude_list=(pk test_mix06_max30k_liv11)

declare -A SCF
SCF[iaddress_lsb_p]=1
SCF[itype_width_p]=4

declare -A UCF
UCF[resync-max]=0
UCF[implicit-return]=false
UCF[full-address]=false
