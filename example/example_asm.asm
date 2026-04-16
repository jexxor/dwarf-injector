; Example DWARF expression ASM
; Predicate: input[0:32] == "DWARF_VM_IS_THE_REAL_GIGACHAD_!!"
; Input pointer is available in r12, so load64 <off> means *(u64*)(r12 + off).

load64 0
const 0x4d565f4652415744
xor

load64 8
const 0x5f4548545f53495f
xor
or

load64 16
const 0x4749475f4c414552
xor
or

load64 24
const 0x21215f4441484341
xor
or

const 0
eq

