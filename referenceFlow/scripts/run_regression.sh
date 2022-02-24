#!/usr/bin/env bash

#############################################################################
# Error handling ############################################################

function error_report_on() {
    trap 'error_report ${LINENO} $?' ERR
}

function error_report_off() {
    trap - ERR
}

# Catch lots of errors
function errors_on() {
    stty -echoctl # hide ^C
    trap cleanup EXIT
    trap interrupt SIGINT
    error_report_on

    set -o pipefail
    set -o errtrace
    set -o nounset
    set -o errexit
}

function errors_off() {
    error_report_off

    set +o pipefail
    set +o errtrace
    set +o nounset
    set +o errexit
}

function cleanup() {
    errors_off
    if [ "${#pids[@]}" != "0" ]; then
        echo "Cleanup any running processes"
        # Kill all children of this process
        pkill --parent $$
    fi

    popd > /dev/null 2>&1

    if [ "$regression_dir" != "" ]; then
        echo "Results stored in $regression_dir"
    fi
}

function interrupt() {
    echo "Handling SIGINT"
    exit 0
}

function error_report() {
  local parent_lineno="$1"
  exit_code="$2"
  echo "Error on or near line ${parent_lineno}; exiting with status ${exit_code}"

  exit "${exit_code}"
}

function assert() {
    if [ ! $@ ]; then
        echo "Error: test $@ failed"
        exit 1
    fi
}

# End of Error handling #####################################################
#############################################################################

#############################################################################
# Parallel test handling ####################################################

function add_test() {
    local test_name=$1
    shift
    local limit=0
    # Decide whether the next argument is a command or a limit
    if [[ $1 =~ ^-?[0-9]+$ ]]; then
        limit=$1
        shift
    fi
    local test_cmd=$@
    if [ $VERBOSE -eq 1 ]; then
        if [ "$limit" == "0" ]; then
            echo "Test=$test_name \"$test_cmd\""
        else
            echo "Test=$test_name (output limit=$limit lines) \"$test_cmd\""
        fi
    fi

    expected_exit_code=0
    # Check if an expected error code has been set
    if [[ -v exit_codes[$test_name] ]]; then
        expected_exit_code=${exit_codes[$test_name]}
    fi

    error_report_off
    if [ "$limit" == "0" ]; then
        { $test_cmd 2>&1 | ${GZIP} > $test_name.test_log${GZ}; test ${PIPESTATUS[0]} -eq $expected_exit_code; } &
    else
        { $test_cmd 2>&1 | head -n $limit | ${GZIP} > $test_name.test_log${GZ}; test ${PIPESTATUS[0]} -eq $expected_exit_code; } &
    fi
    error_report_on
    pid=$!
    pids+=( "$pid" )
    test_pids[$pid]=$test_name
    echo "------- Added test ${test_pids[$pid]} PID=$pid -------"
}

function wait_for_tests_to_complete() {
    local phase="Phase $phase:"
    exit_code=0
    for pid in "${pids[@]}"; do
        expected_exit_code=0
        # Check if an expected error code has been set
        if [[ -v exit_codes[${test_pids[$pid]}] ]]; then
            expected_exit_code=${exit_codes[${test_pids[$pid]}]}
        fi
        if [ $expected_exit_code -ne 0 ]; then
            echo "Waiting for test ${test_pids[$pid]} PID=$pid expected exit=$expected_exit_code"
        else
            echo "Waiting for test ${test_pids[$pid]} PID=$pid"
        fi
        errors_off
        wait "$pid"
        rc=$?
        errors_on
        if [ "$rc" == "$expected_exit_code" ]; then
            echo "^^^^^^^ ${test_pids[$pid]} PASSED ^^^^^^^"
        else
            echo "vvvvvvv ${test_pids[$pid]} FAILED expected exit=$expected_exit_code got $rc vvvvvvv"
            log_length=`${GZCAT} ${test_pids[$pid]}.test_log${GZ} | wc -l | cut -d " " -f 1`
            if [ $log_length -lt 20 ]; then
                ${GZCAT} ${test_pids[$pid]}.test_log${GZ}
            else
                ${GZCAT} ${test_pids[$pid]}.test_log${GZ} | head
                ${GZCAT} ${test_pids[$pid]}.test_log${GZ} | tail
            fi
            echo "vvvvvvv End of log ${test_pids[$pid]} FAILED vvvvv"
            (( exit_code |= $rc ))
        fi
    done
    if [ "$exit_code" == "0" ]; then
        echo "${phase}All tested PASSED"
    else
        echo "*******${phase}All tests completed but some FAILED (Result $exit_code)*******"
    fi

    # Clear lists so more tests can be added
    pids=()
    test_pids=()

    return "$exit_code"
}

# End of Parallel test handling #############################################
#############################################################################

function set_riscv_toolchain () {
    export RISCV_TOOLCHAIN=${RISCV_TOOLCHAIN:-/opt/riscv/}
    if [ ! -d ${RISCV_TOOLCHAIN} ]; then
        export RISCV_TOOLCHAIN=${TOP_LEVEL}
    fi
    if [ -x $RISCV_TOOLCHAIN/bin/riscv64-unknown-elf-objdump ]; then
        has_objdump=1
    else
        echo "Warning:Unable to locate riscv64-unknown-elf-objdump in order to test the decoder"
        has_objdump=0
    fi
    echo "Setting RISCV_TOOLCHAIN to $RISCV_TOOLCHAIN"

    # Look for proxy kernels
    if [ -f $RISCV_TOOLCHAIN/bin/pk ]; then
        proxy_kernel=$RISCV_TOOLCHAIN/bin/pk
    elif [ -f $test_input_dir/pk.$elf_ext ]; then
        proxy_kernel=$test_input_dir/pk.$elf_ext
    fi

    if [ "$proxy_kernel" == "" ]; then
        echo "Warning:No proxy kernels found"
    else
        echo "Setting Proxy Kernel to be $proxy_kernel"
    fi

    # Spike requires the dtc, check it's available
    if ! which dtc > /dev/null; then
        echo "Error: spike requires dtc (device-tree-compiler) to be installed"
        exit 1
    fi
}

function check_executable() {
    local executable=$1
    if [ ! -x $executable ];then
        >&2 echo "Executable $executable not found"
        exit 1
    fi
}

function get_test_name() {
    local test_path=$1
    echo `basename -s .$elf_ext $test_path | xargs basename -s .$pk_ext`
}

function get_pk() {
    local test_path=$1
    ext=${test_path##*.}
    if [ "$ext" == "pk" ]; then
        echo $proxy_kernel
    else
        echo ""
    fi
}

function get_isa_type() {
    local test_path=$1
    file_type=`file -L $test_path`
    if echo $file_type | grep "ELF 32-bit" > /dev/null 2>&1; then
        echo $rv32_isa
    elif echo $file_type | grep "ELF 64-bit" > /dev/null 2>&1; then
        echo $rv64_isa
    else
        echo "Unknown ISA: file type $file_type"
    fi
}

function create_scf () {
    local scf_name=$1; shift

    cp $template_static_config $scf_name

    for key in "${!SCF[@]}"; do
        # Key words must be at the start of the line
        key_string="^$key *=.*$"
        rc=0
        grep "$key_string" $scf_name > /dev/null || rc=$?
        if [ "$rc" != "0" ]; then
            >&2 echo "Key \"$key\" not found in SCF file $scf_name"
            exit 1
        fi
        sed -i "s#$key_string#$key=${SCF[$key]}#" $scf_name
    done
}

function create_ucf () {
    local phase=$1; shift
    local test_name=$1; shift
    local test_dir=$1; shift

    UCF[file-stem]=$test_dir/${test_name}.$phase
    local ucf_name=$test_dir/${test_name}.$phase.ucf
    cp $template_user_config $ucf_name

    for key in "${!UCF[@]}"; do
        # Key words must be at the start of the line
        key_string="^$key *=.*$"
        rc=0
        grep "$key_string" $ucf_name > /dev/null || rc=$?
        if [ "$rc" != "0" ]; then
            >&2 echo "Key \"$key\" not found in UCF file $ucf_name"
            exit 1
        fi
        sed -i "s#$key_string#$key=${UCF[$key]}#" $ucf_name

    done

    if [ "$phase" == "encoder" ]; then
        if [ "${UCF[object-files]}" != "" ]; then
            >&2 echo "Object files incorrectly provided to phase $phase in create_ucf()"
            exit 1
        fi
    elif [ "$phase" == "decoder" ]; then
        if [ "${UCF[object-files]}" == "" ]; then
            >&2 echo "Object files not provided to phase $phase in create_ucf()"
            exit 1
        fi
    else
        >&2 echo "Unknown phase $phase in create_ucf()"
        exit 1
    fi
    echo $ucf_name
}

function check_raw() {
    local test_path=$1
    local test_name=$2
    local suite_dir=$3
    local scf=$4

    $TOP_LEVEL/scripts/te_inst_deserialiser.py ${DEBUG} -u $suite_dir/$test_name.encoder.ucf -c $scf $suite_dir/$test_name.$i_encoder_raw_ext
    diff $suite_dir/$test_name.$i_encoder_ext $suite_dir/$test_name.te_inst_csv
}

function check_i_output() {
    local test_path=$1
    local test_name=$2
    local suite_dir=$3

    test_expected=$spike_dir/$test_name.$i_spike_ext
    # The list of pc transitions will be in <test_name>.decoder.trace
    test_pc_trace=$suite_dir/$test_name.decoder.trace
    assert -e $test_expected
    assert -e $test_pc_trace
    $TOP_LEVEL/scripts/compare_pc_trace.py $test_expected $test_pc_trace
}

function check_d_output() {
    local test_path=$1
    local test_name=$2
    local suite_dir=$3

    test_expected=$spike_dir/$test_name.$d_spike_ext
    # The output data trace will be in <test_name>.decoder.trace
    test_data_trace=$suite_dir/$test_name.decoder.trace
    test_encoder_ucf=$suite_dir/$test_name.encoder.ucf
    assert -e $test_expected
    assert -e $test_data_trace
    assert -e $test_encoder_ucf
    $TOP_LEVEL/scripts/compare_data_trace.py $test_expected $test_data_trace $test_encoder_ucf
}

function record_statistics() {
    local trace_type=$1
    local test_name=$2
    local stats_file=$3
    local suite_dir=$4

    if [ "$trace_type" == "inst" ]; then
        spike_ext=$i_spike_ext
        encoder_ext=$i_encoder_ext
        encoder_raw_ext=$i_encoder_raw_ext
    else
        spike_ext=$d_spike_ext
        encoder_ext=$d_encoder_ext
        encoder_raw_ext=$d_encoder_raw_ext
    fi

    if [ "$#" == "5" ]; then
        # Final total results
        local ntests=$5
        nentries=$((stats_total[1]/ntests))
        npackets=$((stats_total[2]/ntests))
        payload_bytes=$((stats_total[3]/ntests))
        # Interesting way of doing floating point calculations using printf
        bits_per_inst=`printf %.3f "$((10**3 * stats_total[3] * 8/stats_total[1]))e-3"`
    else
        # Normal recording of a single test
        nentries=`wc -l $spike_dir/$test_name.$spike_ext | cut -d " " -f 1`
        nentries=$((nentries - 1))
        # Only produce statistics for trace tests run where the number
        # of entries exceed the threshold. This removes any strange small tests which
        # will not have meaningful statistics
        if [ $nentries -lt $STATS_THRESHOLD ]; then
            return
        fi

        stats_total[1]=$((stats_total[1]+nentries))
        npackets=`wc -l $suite_dir/$test_name.$encoder_ext | cut -d " " -f 1`
        npackets=$((npackets - 1))
        stats_total[2]=$((stats_total[2]+npackets))
        if [ -e $suite_dir/$test_name.$encoder_raw_ext ]; then
            # Includes header byte per packet
            raw_bytes=`stat -c "%s" $suite_dir/$test_name.$encoder_raw_ext`
            payload_bytes=$((raw_bytes - npackets))
        else
            >&2 echo "Warning: payload size unavailable"
            payload_bytes=0
        fi
        stats_total[3]=$((stats_total[3]+payload_bytes))
        # Interesting way of doing floating point calculations using printf
        bits_per_inst=`printf %.3f "$((10**3 * payload_bytes * 8/nentries))e-3"`
    fi

    printf "%${stats_width[0]}s" $test_name >> $stats_file
    printf "%${stats_width[1]}d" $nentries >> $stats_file
    printf "%${stats_width[2]}d" $npackets >> $stats_file
    printf "%${stats_width[3]}d" $payload_bytes >> $stats_file
    printf "%${stats_width[4]}f" $bits_per_inst >> $stats_file
    printf "\n" >> $stats_file

    nstats_files=$((nstats_files + 1))
}


function run_instruction_suite() {
    local test_suite=$1
    suite_dir=$regression_dir/$test_suite
    mkdir $suite_dir
    pushd $suite_dir > /dev/null

    printf "\n    >>>>>>>Running INSTRUCTION test suite $test_suite in $suite_dir<<<<<<<\n\n"
    suite_path=$suite_base_dir/$test_suite.sh
    if [ ! -e $suite_path ]; then
        echo "Error: Unable to load test suite $suite_path"
        exit 1
    fi

    declare -a exclude_list=()
    declare -a test_list=()
    unset SCF
    unset UCF
    . $suite_path

    if [ "${#exclude_list[@]}" == "0" ]; then
        echo "Warning: The exclude list is empty, this is probably not right"
    fi

    for test_path in ${alltests[@]}; do
        test_name=$(get_test_name $test_path)
        if echo "${exclude_list[@]}" | fgrep --word-regexp "$test_name" > /dev/null; then
            echo "*******Excluded test $test_name*******"
        else
            test_list+=($test_path)
        fi
    done

    if [ "${#test_list[@]}" == "0" ]; then
        usage "$TESTS does not match any non excluded tests"
    fi

    template_static_config=$TOP_LEVEL/tests/config_files/i_template.scf
    template_user_config=$TOP_LEVEL/tests/config_files/i_template.ucf
    assert -e $template_static_config
    assert -e $template_user_config

    # Only a single SCF for each word size because it represents the hardware
    static_config_64=$suite_dir/hardware_64.scf
    SCF[iaddress_width_p]=64
    create_scf $static_config_64
    static_config_32=$suite_dir/hardware_32.scf
    SCF[iaddress_width_p]=32
    create_scf $static_config_32

    # Run spike to produce INSTRUCTION TRACE
    # This only needs to be done once for each of the test files and they can then be used by
    # each test suite
    phase="i_spike"
    spike_dir=$regression_dir/spike
    mkdir -p $spike_dir
    pushd $spike_dir > /dev/null
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        test_dir=`dirname $test_path`
        i_spike_output=$test_name.$i_spike_ext
        # Nasty special cases can't be easily run automatically with spike and so
        # the instruction trace file is provided
        if [ -e $test_dir/$i_spike_output ]; then
            echo "NOT RUNNING SPIKE, using the preset trace $test_dir/$i_spike_output"
            cp $test_dir/$i_spike_output .
        fi
        # Find out whether input is 32-bit or 64-bit. For a pk test, determine the type of pk
        pk=$(get_pk $test_path)
        if [ "$pk" == "" ]; then
            isa_type=$(get_isa_type $test_path)
        else
            isa_type=$(get_isa_type $pk)
        fi
        if [[ -v test_isa[$test_name] ]]; then
            if [ "${test_isa[$test_name]}" != "$isa_type" ]; then
                echo "Inconsistent ISA type for test $test_name"
                exit 1
            fi
        fi
        test_isa[$test_name]=$isa_type

        # When the file already exists don't need to run spike
        if [ -e $i_spike_output ]; then
            continue
        fi

        # Don't use the provided memory map for pk tests as it breaks the test
        args=
        if [ "$pk" == "" ]; then
            args=${SPIKE_MEM_MAP}
        fi
        add_test ${test_name}.$phase ${EXECUTER} ${SPIKE} ${args} ${SPIKE_INST_OPTION} $i_spike_output --isa=$isa_type $pk $test_path
    done

    wait_for_tests_to_complete $phase
    popd > /dev/null

    # Run post-iss
    phase="post-iss"
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        if [ "$(get_isa_type $test_path)" == "$rv32_isa" ]; then
            static_config=$static_config_32
        else
            static_config=$static_config_64
        fi
        add_test ${test_name}.$phase ${EXECUTER} ${POSTISS} -c $static_config -i $spike_dir/$test_name.$i_spike_ext
    done

    wait_for_tests_to_complete $phase

    # Run encoder
    phase="encoder"
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        test_input=$suite_dir/$test_name.$postiss_ext
        assert -f $test_input
        UCF[object-files]=
        user_config=$(create_ucf $phase $test_name $suite_dir)
        if [ "$(get_isa_type $test_path)" == "$rv32_isa" ]; then
            static_config=$static_config_32
        else
            static_config=$static_config_64
        fi
        if [ "$USE_OLD_ENCODER" == "1" ];then
            add_test ${test_name}.$phase ${EXECUTER} ${I_ENCODER} ${ANNOTATE} ${DEBUG} -u $user_config -c $static_config -i $test_input
        else
            add_test ${test_name}.$phase ${COVERAGE_RUN} ${I_ENCODER} ${ANNOTATE} ${DEBUG} -u $user_config -c $static_config
        fi
    done

    wait_for_tests_to_complete $phase

    # Run check of te_inst raw output (can only do this with the new encoder)
    if [ "$USE_OLD_ENCODER" == "0" ];then
        phase="check-raw"
        for test_path in "${test_list[@]}"; do
            test_name=$(get_test_name $test_path)
            if [ "$(get_isa_type $test_path)" == "$rv32_isa" ]; then
                static_config=$static_config_32
            else
                static_config=$static_config_64
            fi
            add_test ${test_name}.$phase check_raw $test_path $test_name $suite_dir $static_config
        done

        wait_for_tests_to_complete $phase
    fi

    if [ "$has_objdump" == "1" ]; then
        # Run decoder
        phase="decoder"
        for test_path in "${test_list[@]}"; do
            test_name=$(get_test_name $test_path)
            test_input=$suite_dir/$test_name.$i_encoder_ext
            test_input_raw=$suite_dir/$test_name.$i_encoder_raw_ext
            assert -f $test_input
            assert -f $test_input_raw
            test_src_dir=`dirname $test_path`
            if [ -f ${test_src_dir}/$test_name.$elf_ext ]; then
                UCF[object-files]=${test_src_dir}/$test_name.$elf_ext
            else
                UCF[object-files]="$proxy_kernel ${test_src_dir}/$test_name.$pk_ext"
            fi
            if [[ ! -v test_isa[$test_name] ]]; then
                echo "ISA type not set for test $test_name"
                exit 1
            fi
            if [ "${test_isa[$test_name]}" == "$rv32_isa" ]; then
                UCF[use-rv32-isa]="true"
                static_config=$static_config_32
            else
                UCF[use-rv32-isa]="false"
                static_config=$static_config_64
            fi
            user_config=$(create_ucf $phase $test_name $suite_dir)
            if [ "$USE_CSV" == "1" ]; then
                add_test ${test_name}.$phase ${COVERAGE_RUN} ${I_DECODER} ${DEBUG} -u $user_config -c $static_config -i $test_input
            else
                add_test ${test_name}.$phase ${COVERAGE_RUN} ${I_DECODER} ${DEBUG} -u $user_config -c $static_config -i $test_input_raw
            fi
        done

        wait_for_tests_to_complete $phase

        # Run check of trace output
        phase="check"
        for test_path in "${test_list[@]}"; do
            test_name=$(get_test_name $test_path)
            add_test ${test_name}.$phase check_i_output $test_path $test_name $suite_dir
        done

        wait_for_tests_to_complete $phase

        stats_file=$suite_dir/encoder_i_statistics.log
        declare -a stats_width=(30 16 16 16 16)
        declare -a stats_total=(0 0 0 0 0)
        declare -a header=("Test" "Instructions" "Packets" "Payload(bytes)" "Bits/instr")
        nstats_files=0
        total_width=0
        for i in "${!stats_width[@]}"; do
            printf "%${stats_width[$i]}s" ${header[$i]} >> $stats_file
            total_width=$((total_width+${stats_width[$i]}))
        done
        printf "\n" >> $stats_file
        echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
        for test_path in "${test_list[@]}"; do
            test_name=$(get_test_name $test_path)
            record_statistics inst $test_name $stats_file $suite_dir
        done

        if [ $nstats_files -eq 0 ]; then
            rm $stats_file
        else
            echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
            record_statistics inst "Average" $stats_file $suite_dir $nstats_files
            echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
            echo "-------Created statistics in $stats_file -------"

            cat $stats_file
        fi
    else
        echo "Unable to run decoder as RISCV toolchain is not available"
    fi

    popd > /dev/null
}

function run_data_suite() {
    local test_suite=$1
    suite_dir=$regression_dir/$test_suite
    mkdir $suite_dir
    pushd $suite_dir > /dev/null

    printf "\n    >>>>>>>Running DATA test suite $test_suite in $suite_dir<<<<<<<\n\n"
    suite_path=$suite_base_dir/$test_suite.sh
    if [ ! -e $suite_path ]; then
        echo "Error: Unable to load data test suite $suite_path"
        exit 1
    fi

    declare -a exclude_list=()
    declare -a test_list=()
    unset SCF
    unset UCF
    . $suite_path

    if [ "${#exclude_list[@]}" == "0" ]; then
        echo "Warning: The exclude list is empty, this is probably not right"
    fi

    for test_path in ${alltests[@]}; do
        test_name=$(get_test_name $test_path)
        if echo "${exclude_list[@]}" | fgrep --word-regexp "$test_name" > /dev/null; then
            echo "*******Excluded test $test_name*******"
        else
            test_list+=($test_path)
        fi
    done

    if [ "${#test_list[@]}" == "0" ]; then
        usage "$TESTS does not match any non excluded tests"
    fi

    template_static_config=$TOP_LEVEL/tests/config_files/d_template.scf
    template_user_config=$TOP_LEVEL/tests/config_files/d_template.ucf
    assert -e $template_static_config
    assert -e $template_user_config

    # Only a single SCF for each word size because it represents the hardware
    static_config_64=$suite_dir/hardware_64.scf
    SCF[daddress_width_p]=64
    SCF[data_width_p]=64
    create_scf $static_config_64
    static_config_32=$suite_dir/hardware_32.scf
    SCF[daddress_width_p]=32
    SCF[data_width_p]=32
    create_scf $static_config_32

    # Run spike to produce DATA TRACE
    # This only needs to be done once for each of the test files and they can then be used by
    # each test suite
    phase="d_spike"
    spike_dir=$regression_dir/spike
    mkdir -p $spike_dir
    pushd $spike_dir > /dev/null
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        test_dir=`dirname $test_path`
        d_spike_output=$test_name.$d_spike_ext
        i_spike_output=$test_name.$i_spike_ext
        # Nasty special cases can't be easily run automatically with spike and so
        # the instruction trace file is provided. For data trace use the length of this file to
        # limit the running of the data trace using the method of running head to limit the
        # number of output lines in order to stop the running of spike - otherwise spike does
        # not exit for some of these executables.
        # Note that this is only approximately the right thing to do as the instruction trace
        # doesn't necessarily start at the beginning of the spike execution.
        # Hopefully this is ok for testing the data trace, otherwise much more complication is
        # needed to make sure that the data trace relates to the instruction trace.
        # Limit = 0 means run to completion
        data_trace_limit=0
        if [ -e $test_dir/$i_spike_output ]; then
            data_trace_limit=`wc -l $test_dir/$i_spike_output | cut -d " " -f 1`
        fi
        # Find out whether input is 32-bit or 64-bit. For a pk test, determine the type of pk
        pk=$(get_pk $test_path)
        if [ "$pk" == "" ]; then
            isa_type=$(get_isa_type $test_path)
        else
            isa_type=$(get_isa_type $pk)
        fi
        if [[ -v test_isa[$test_name] ]]; then
            if [ "${test_isa[$test_name]}" != "$isa_type" ]; then
                echo "Inconsistent ISA type for test $test_name"
                exit 1
            fi
        fi
        test_isa[$test_name]=$isa_type

        # When the file already exists don't need to run spike
        if [ -e $d_spike_output ]; then
            continue
        fi

        # Don't use the provided memory map for pk tests as it breaks the test
        args=
        if [ "$pk" == "" ]; then
            args=${SPIKE_MEM_MAP}
        fi
        add_test ${test_name}.$phase $data_trace_limit ${EXECUTER} ${SPIKE} -l ${args} --data-trace $d_spike_output --isa=$isa_type $pk $test_path
    done

    wait_for_tests_to_complete $phase
    popd > /dev/null

    # Run encoder
    phase="encoder"
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        test_input=$spike_dir/$test_name.$d_spike_ext
        assert -f $test_input
        UCF[object-files]=
        user_config=$(create_ucf $phase $test_name $suite_dir)
        if [ "$(get_isa_type $test_path)" == "$rv32_isa" ]; then
            static_config=$static_config_32
        else
            static_config=$static_config_64
        fi
        add_test ${test_name}.$phase ${COVERAGE_RUN} ${D_ENCODER} ${DEBUG} -u $user_config -c $static_config
    done

    wait_for_tests_to_complete $phase

    # Run decoder
    phase="decoder"
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        test_input=$suite_dir/$test_name.$d_encoder_ext
        test_input_raw=$suite_dir/$test_name.$d_encoder_raw_ext
        assert -f $test_input
        assert -f $test_input_raw
        if [ "$(get_isa_type $test_path)" == "$rv32_isa" ]; then
            static_config=$static_config_32
        else
            static_config=$static_config_64
        fi
        if [ "$USE_CSV" == "1" ]; then
            add_test ${test_name}.$phase ${COVERAGE_RUN} ${D_DECODER} ${DEBUG} -c $static_config -i $test_input
        else
            add_test ${test_name}.$phase ${COVERAGE_RUN} ${D_DECODER} ${DEBUG} -c $static_config -i $test_input_raw
        fi
    done

    wait_for_tests_to_complete $phase

    # Run check of trace output
    phase="check"
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        add_test ${test_name}.$phase check_d_output $test_path $test_name $suite_dir
    done

    wait_for_tests_to_complete $phase

    # Produce statistics for all of the data trace tests run
    stats_file=$suite_dir/encoder_d_statistics.log
    declare -a stats_width=(30 16 16 16 16)
    declare -a stats_total=(0 0 0 0 0)
    declare -a header=("Test" "Entries" "Packets" "Payload(bytes)" "Bits/entry")
    nstats_files=0
    total_width=0
    for i in "${!stats_width[@]}"; do
        printf "%${stats_width[$i]}s" ${header[$i]} >> $stats_file
        total_width=$((total_width+${stats_width[$i]}))
    done
    printf "\n" >> $stats_file
    echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
    for test_path in "${test_list[@]}"; do
        test_name=$(get_test_name $test_path)
        record_statistics data $test_name $stats_file $suite_dir
    done

    if [ $nstats_files -eq 0 ]; then
        rm $stats_file
    else
        echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
        record_statistics data "Average" $stats_file $suite_dir $nstats_files
        echo `head -c $total_width < /dev/zero | tr '\0' '-'` >> $stats_file
        echo "-------Created statistics in $stats_file -------"

        cat $stats_file
    fi

    popd > /dev/null
}

#############################################################################
# Main script ###############################################################

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. $script_dir/setup.sh

exit_code=0
errors_on

usage() {
    echo "Usage: $0 [<test name>] [-t|--test-suite <test_suite>] [--fixed regression_dir] [--tidy] [-d|--debug] [--annotate] [-v|--verbose] [--valgrind] [--valgrind-leak] [--valgrind-track]" 1>&2
    msg=${1:-}
    if [ ! -z "${msg}" ]; then
        echo "  Error:$1"
    fi
    exit 1
 }

declare -a test_suites=()
function add_test_suite() {
    local test_suite=$1
    if echo "${test_suites[@]}" | fgrep --word-regexp "$test_suite"; then
        echo "Warning: test suite $test already added"
    else
        test_suites+=($test_suite)
    fi
}

EXECUTER=
REG_DIR="auto"
declare -a TESTS=()
TIDY=0
ANNOTATE=
DEBUG=
VERBOSE=0
COVERAGE=0
USE_OLD_ENCODER=0
USE_OLD_DECODER=0
GZIP="gzip --stdout"
GZCAT="zcat"
GZ=".gz"
STATS_THRESHOLD=1000
nstats_files=0
USE_CSV=0
while [[ "$#" > 0 ]]; do
    case $1 in
        -h | --help) usage; exit 0; shift;;
        --fixed) if [ "$#" -le 1 ]; then usage "--fixed dir required";
                 fi; shift; REG_DIR=$1; shift;;
        --tidy) TIDY=1; shift;;
        -t | --test-suite) if [ "$#" -le 1 ]; then usage "--test-suite suite required";
                           fi; shift; add_test_suite $1; shift;;
        --annotate) ANNOTATE="--annotate"; shift;;
        -d | --debug) DEBUG="--debug"; shift;;
        -v | --verbose) VERBOSE=1; shift;;
        # Add --leak-check=full for full check, this is very, very slow!
        --valgrind) EXECUTER='valgrind --error-exitcode=1'; shift;;
        --valgrind-leak) EXECUTER='valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1'; shift;;
        --valgrind-track) EXECUTER='valgrind --track-origins=yes --error-exitcode=1'; shift;;
        --old-encoder) USE_OLD_ENCODER=1; shift;;
        --old-decoder) USE_OLD_DECODER=1; shift;;
        --threshold)  if [ "$#" -le 1 ]; then usage "--threshold count";
                      fi; shift; STATS_THRESHOLD=$1; shift;;
        --use-csv) USE_CSV=1; shift;;
        --coverage) COVERAGE=1; shift;;
        -* | --*) usage "Unknown option $1";;
        *) TESTS+=($1); shift;;
    esac;
done

COVERAGE_ERASE=
COVERAGE_RUN=""
COVERAGE_COMBINE=
COVERAGE_HTML=
COVERAGE_REPORT=
if [ "$COVERAGE" == "1" ]; then
    coverage_cmd=
    if which python3-coverage > /dev/null; then
        coverage_cmd="python3-coverage"
    else
        if which coverage > /dev/null; then
            coverage_cmd="coverage"
        else
            echo "Failed to find python coverage command"
            exit 1
        fi
    fi
    if [ ${coverage_cmd} != "" ]; then
        echo "Running with coverage"
        COVERAGE_ERASE="${coverage_cmd} erase"
        COVERAGE_RUN="${coverage_cmd} run --parallel-mode"
        COVERAGE_COMBINE="${coverage_cmd} combine"
        COVERAGE_HTML="${coverage_cmd} html"
        COVERAGE_REPORT="${coverage_cmd} report"
    else
        echo "Running without coverage"
    fi
fi

if [ "${#test_suites[@]}" == "0" ]; then
    add_test_suite itype3_basic
    echo ">>>>>>>Using the default test suite ${test_suites[@]}<<<<<<<"
fi

test_input_dir=$TOP_LEVEL/tests/test_files/
if [ ! -d $test_input_dir ]; then
    echo "Unable to find test input directory $test_input_dir"
    exit 1
fi

# Read the script defining expected exit codes
suite_base_dir=$TOP_LEVEL/tests/test_suites/
. $suite_base_dir/exit_codes.sh

elf_ext="riscv"
pk_ext="pk"
i_spike_ext="spike_pc_trace"
d_spike_ext="spike_data_trace"
postiss_ext="encoder_input"
i_encoder_ext="te_inst"
i_encoder_raw_ext="te_inst_raw"
d_encoder_ext="te_data"
d_encoder_raw_ext="te_data_raw"

# Find the test pathnames from the names provided on the command line
declare -a alltests=()
if [ "${#TESTS[@]}" == "0" ]; then
    alltests+=(`find $test_input_dir -name "*.$elf_ext" -o -name "*.$pk_ext"`)
else
    for testname in ${TESTS[@]}; do
        # If the test name has an extension of .riscv or .pk then it is assumed to be full path
        # and so will not be searched for in the test_input_dir.
        ext=${testname##*.}
        if [ "$ext" == "riscv" ] || [ "$ext" == "pk" ]; then
            alltests+=(`realpath $testname`)
        else
            if [ "${#TESTS[@]}" == "1" ]; then
                alltests+=(`find $test_input_dir -name "*$testname*.$elf_ext" -o -name "$testname*.$pk_ext"`)
            else
                alltests+=(`find $test_input_dir -name "$testname.$elf_ext" -o -name "$testname.$pk_ext"`)
            fi
        fi
    done
fi

if [ "${#alltests[@]}" == "0" ]; then
    echo "No tests match \"${TESTS[@]}\""
    exit 1
fi

rv32_isa="RV32IMAFDC"
rv64_isa="RV64IMAFDC"
declare -A test_isa=()

has_objdump=0
proxy_kernel=
set_riscv_toolchain
SPIKE=$TOP_LEVEL/bin/spike.sh
SPIKE_MEM_MAP="-m0x20010000:0x40000,0x80000000:0x400000"

if ( ${SPIKE} -h 3>&1 1>&2- 2>&3- ) | grep "ust-trace" > /dev/null; then
    SPIKE_INST_OPTION="--ust-trace"
else
    SPIKE_INST_OPTION="--inst-trace"
fi

D_ENCODER=$TOP_LEVEL/scripts/data_encoder_model.py
check_executable $D_ENCODER
echo "Using data encoder $D_ENCODER"
D_DECODER=$TOP_LEVEL/scripts/data_decoder_model.py
check_executable $D_DECODER
echo "Using data decoder $D_DECODER"

POSTISS=$TOP_LEVEL/build_te/post-iss/post-iss
check_executable $POSTISS
if [ "$USE_OLD_ENCODER" == "1" ];then
    I_ENCODER=$TOP_LEVEL/build_te/riscv-encoder/riscv-encoder
else
    I_ENCODER=$TOP_LEVEL/scripts/encoder_model.py
fi
check_executable $I_ENCODER
echo "Using instruction encoder $I_ENCODER"
if [ "$USE_OLD_DECODER" == "1" ];then
    I_DECODER=$TOP_LEVEL/build_te/riscv-decoder/riscv-decoder
else
    I_DECODER=$TOP_LEVEL/scripts/decoder_model.py
fi
check_executable $I_DECODER
echo "Using instruction decoder $I_DECODER"

if [ "$USE_CSV" == "1" ]; then
    echo "Using CSV communications encoder ----> decoder"
fi

if [ "$TIDY" == "1" ]; then
    echo "Tidying previous runs"
    rm -fr `pwd`/regression_*
fi

if [ "$REG_DIR" == "auto" ]; then
    if [ "$COVERAGE" == "1" ]; then
        regression_dir=`pwd`/regression_coverage
        rm -fr $regression_dir
    else
        regression_dir=`pwd`/regression_`date +"%Y%m%d_%H%M%S"`
    fi
else
    if [ "${REG_DIR:0:1}" == "/" ]; then
        regression_dir=$REG_DIR
    else
        regression_dir=`pwd`/$REG_DIR
    fi
    if [ -d $regression_dir ]; then
        rm -fr $regression_dir
    fi
fi
mkdir $regression_dir
echo "<<<<<<< Running tests in $regression_dir >>>>>>>"

for test_suite in "${test_suites[@]}"; do
    if echo $test_suite | grep "^dtype" > /dev/null 2>&1; then
        run_data_suite $test_suite
    elif echo $test_suite | grep "^itype" > /dev/null 2>&1; then
        run_instruction_suite $test_suite
    else
        echo "Error unknown test suite type $test_suite"
        exit 1
    fi
done

if [ "$COVERAGE" == "1" ]; then
    cd $regression_dir

    i_suites=`find . -maxdepth 1 -type d -name "itype*" `
    if [ "$i_suites" != "" ]; then
        mkdir i_coverage
        for i_suite in $i_suites; do
            find $i_suite -name ".coverage*" -exec cp {} i_coverage \;
        done
        pushd i_coverage > /dev/null
        # Coverage must be combined as we are using parallel mode because the tests are run in
        # parallel
        $COVERAGE_COMBINE
        $COVERAGE_REPORT
        $COVERAGE_HTML
        popd >> /dev/null
        tar zcf instruction_coverage.tgz i_coverage
    fi

    d_suites=`find . -maxdepth 1 -type d -name "dtype*" `
    if [ "$d_suites" != "" ]; then
        mkdir d_coverage
        for d_suite in $d_suites; do
            find $d_suite -name ".coverage*" -exec cp {} d_coverage \;
        done
        pushd d_coverage > /dev/null
        # Coverage must be combined as we are using parallel mode because the tests are run in
        # parallel
        $COVERAGE_COMBINE
        $COVERAGE_REPORT
        $COVERAGE_HTML
        popd >> /dev/null
        tar zcf data_coverage.tgz d_coverage
    fi
fi
