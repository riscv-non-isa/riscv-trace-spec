# Define the tests to be excluded
exclude_list=(pk test_mix06_max30k_liv11)

# Set to non zero some sizes that are not used in the processing but will test the te_inst
# raw handling. e.g. return_stack_size_p
declare -A SCF
SCF[iaddress_lsb_p]=1
SCF[itype_width_p]=4
SCF[return_stack_size_p]=7
SCF[call_counter_size_p]=0
SCF[notime_p]=0
SCF[sijump_p]=1

declare -A UCF
UCF[resync-max]=16
UCF[implicit-return]=false
UCF[full-address]=false
