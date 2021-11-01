# Define the tests to be excluded
exclude_list=(pk test_mix06_max30k_liv11)

declare -A SCF
SCF[iaddress_lsb_p]=0
SCF[itype_width_p]=3

declare -A UCF
UCF[resync-max]=1
UCF[implicit-return]=false
UCF[full-address]=true
