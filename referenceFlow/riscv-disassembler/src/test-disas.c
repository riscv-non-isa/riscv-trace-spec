#include <stdio.h>

#include "riscv-disas.h"

void print_insn(int64_t pc, int64_t inst)
{
    char buf[128] = { 0 };
    disasm_inst(buf, sizeof(buf), rv64, pc, inst);
    printf("0x%" PRIx64 ":  %s\n", pc, buf);
}

static uint64_t inst_arr[] = {
    0x0,
    0x1,
    0xd,
    0x401,
    0x404,
    0x405,
    0xf1402573,
    0x597,
    0x204002b7,
    0x13,
};

int main()
{
	uint64_t pc = 0x10078;
	for (size_t i = 0; i < sizeof(inst_arr) / sizeof(inst_arr[0]); i++) {
		uint64_t inst = inst_arr[i];
		print_insn(pc, inst);
		pc += inst_length(inst);
	}
}
