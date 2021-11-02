cmake_minimum_required(VERSION 2.6)
project(riscv-disassembler)

set(SOURCE_FILES
    src/riscv-disas.c
    )

# target
add_library(riscv-disassembler STATIC ${SOURCE_FILES})

#target_compile_options(riscv-disassembler PRIVATE -std=gnu99)

target_compile_options(riscv-disassembler PRIVATE -O2)
target_compile_options(riscv-disassembler PRIVATE -fdiagnostics-show-option)
target_include_directories( riscv-disassembler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

if (BUILD_TESTS)
    # Disregard coverage option on unit tests
    string(REPLACE "--coverage" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REPLACE "--coverage" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

    # test-disas execautable
    project(test-disas)
    add_executable(test-disas src/test-disas.c)
    target_link_libraries(test-disas riscv-disassembler)

    # test-encode execautable
    project(test-encode)
    add_executable(test-encode src/test-encode.c)
    target_link_libraries(test-encode riscv-disassembler)
endif(BUILD_TESTS)

