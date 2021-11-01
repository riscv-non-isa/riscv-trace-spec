#include "riscv-disas.h"

enum {
    OPC_ADD = 0x33,
    OPC_ADDI = 0x13,
    OPC_ADDIW = 0x1b,
    OPC_ADDW = 0x3b,
    OPC_AND = 0x7033,
    OPC_ANDI = 0x7013,
    OPC_AUIPC = 0x17,
    OPC_BEQ = 0x63,
    OPC_BGE = 0x5063,
    OPC_BGEU = 0x7063,
    OPC_BLT = 0x4063,
    OPC_BLTU = 0x6063,
    OPC_BNE = 0x1063,
    OPC_DIV = 0x2004033,
    OPC_DIVU = 0x2005033,
    OPC_DIVUW = 0x200503b,
    OPC_DIVW = 0x200403b,
    OPC_JAL = 0x6f,
    OPC_JALR = 0x67,
    OPC_LB = 0x3,
    OPC_LBU = 0x4003,
    OPC_LD = 0x3003,
    OPC_LH = 0x1003,
    OPC_LHU = 0x5003,
    OPC_LUI = 0x37,
    OPC_LW = 0x2003,
    OPC_LWU = 0x6003,
    OPC_MUL = 0x2000033,
    OPC_MULH = 0x2001033,
    OPC_MULHSU = 0x2002033,
    OPC_MULHU = 0x2003033,
    OPC_MULW = 0x200003b,
    OPC_OR = 0x6033,
    OPC_ORI = 0x6013,
    OPC_REM = 0x2006033,
    OPC_REMU = 0x2007033,
    OPC_REMUW = 0x200703b,
    OPC_REMW = 0x200603b,
    OPC_SB = 0x23,
    OPC_SD = 0x3023,
    OPC_SH = 0x1023,
    OPC_SLL = 0x1033,
    OPC_SLLI = 0x1013,
    OPC_SLLIW = 0x101b,
    OPC_SLLW = 0x103b,
    OPC_SLT = 0x2033,
    OPC_SLTI = 0x2013,
    OPC_SLTIU = 0x3013,
    OPC_SLTU = 0x3033,
    OPC_SRA = 0x40005033,
    OPC_SRAI = 0x40005013,
    OPC_SRAIW = 0x4000501b,
    OPC_SRAW = 0x4000503b,
    OPC_SRL = 0x5033,
    OPC_SRLI = 0x5013,
    OPC_SRLIW = 0x501b,
    OPC_SRLW = 0x503b,
    OPC_SUB = 0x40000033,
    OPC_SUBW = 0x4000003b,
    OPC_SW = 0x2023,
    OPC_XOR = 0x4033,
    OPC_XORI = 0x4013,
};

uint32_t encode_sbimm12(uint32_t imm)
{
    return ((imm << 19) >> 31) << 31 |
        ((imm << 21) >> 26) << 25 |
        ((imm << 27) >> 28) << 8 |
        ((imm << 20) >> 31) << 7;
}

uint32_t encode_r_jimm20(uint32_t rd, uint32_t imm)
{
    return (rd & 0x1f) << 7 |
        ((imm << 11) >> 31) << 31 |
        ((imm << 21) >> 22) << 21 |
        ((imm << 20) >> 31) << 20 |
        ((imm << 12) >> 24) << 12;
}

uint32_t encode_rr_simm12(uint32_t rd, uint32_t rs1, uint32_t imm)
{
    return (rd & 0x1f) << 7 |
        (rs1 & 0x1f) << 15 |
        (imm & 0xfff) << 20;
}

void print_inst(uint64_t pc, uint32_t inst)
{
    char buf[80] = { 0 };
    disasm_inst(buf, sizeof(buf), rv64, pc, inst);
    printf("%016" PRIx64 ":  %s\n", pc, buf);
}

int main()
{
    print_inst(0x10000, OPC_BEQ | encode_sbimm12(-454));
    print_inst(0x10004, OPC_BEQ | encode_sbimm12(-232));
    print_inst(0x10008, OPC_BEQ | encode_sbimm12(232));
    print_inst(0x1000c, OPC_BEQ | encode_sbimm12(454));
    print_inst(0x10010, OPC_ADDI | encode_rr_simm12(8, 9, 0));
    print_inst(0x10014, OPC_JAL | encode_r_jimm20(0, -4));
    print_inst(0x10018, OPC_JAL | encode_r_jimm20(1, -12));
}
