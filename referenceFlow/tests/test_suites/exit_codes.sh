# Added expected exit codes here for the various phases of particular tests.
# If not present the assumption is the expected exit code is 0 i.e. success
# Array index value is test_name.phase_name (phase names are given in run_regression.sh)
# e.g. exit_codes[br_j_asm.i_spike]=156
declare -A exit_codes
exit_codes[test_discon_branch_exception.d_spike]=141 # Non zero because spike doesn't terminate
exit_codes[xrle.d_spike]=141 # Non zero because spike doesn't terminate
exit_codes[ecall_exception.i_spike]=255 # Non zero because spike doesn't terminate cleanly
