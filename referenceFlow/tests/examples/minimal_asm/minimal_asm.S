/* https://github.com/riscv/riscv-isa-sim/issues/256 */
.section .text
.global _start

_start:
        la      t1, tohost
        li      t2, 1
        sw      t2, 0(t1)      // Write a 1 to tohost to exit spike

.section .tohost, "aw", @progbits
.globl tohost
.align 4
tohost: .dword 0
.globl fromhost
.align 4
fromhost: .dword 0
