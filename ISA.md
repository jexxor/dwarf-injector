# DWARF-INJECTOR ASM ISA

This file documents the plain ASM input format consumed by [patcher.py](patcher.py).

## Scope

- This ISA describes a subset of DWARF expression opcodes.
- It is intended for boolean predicates evaluated by the unwinder.
- The expression result is used as the recovered value for register rbx.

## Syntax

- One instruction per line.
- Mnemonics are case-insensitive.
- Operands are separated by spaces or commas.
- Integer literals use Python-style parsing:
  - Decimal: 42
  - Hex: 0x2a
  - Negative: -7
- Comments are supported with ;, //, or #.
- Label declarations ending with : are accepted as no-ops for readability.
  - Labels are not resolved in branches in this PoC.

## Stack Model

- The expression VM is stack-based.
- Most binary operations pop two values and push one result.
- Comparison operators push 1 for true, 0 for false.

## Instruction Set

### Literal / memory

- const IMM
  - Push signed/unsigned constant using DW_OP_consts or DW_OP_constu.
- constu IMM
  - Push non-negative constant (ULEB128).
- consts IMM
  - Push signed constant (SLEB128).
- lit N
  - Push literal in range 0..31.
- lit0 ... lit31
  - Push small literal.
- addr IMM
  - Push an absolute 64-bit address value.
- breg12 OFF
  - Push address r12 + OFF (SLEB128 offset).
- load64 OFF
  - Expand to breg12 OFF + deref_size 8.
- deref
  - Dereference default-sized address from top of stack.
- deref_size N
  - Dereference N bytes (N in 0..255).

### Arithmetic / bitwise / compare

- add, sub, mul, div, mod
- and, or, xor
- shl, shr, shra
- abs, neg, not
- eq, ne, lt, le, gt, ge

### Stack ops

- dup, drop, over, swap, rot, pick N

### Control / misc

- plus_uconst IMM
- bra REL16
- skip REL16
  - REL16 is a signed 16-bit relative jump in bytes.
  - Label resolution is not implemented in this PoC.
- call_frame_cfa
- stack_value
- nop
- byte IMM
  - Append raw byte (0..255) directly to expression stream.

## Minimal Example

See [example/example_asm.asm](example/example_asm.asm) for a full predicate. A tiny expression that always returns true:

```asm
lit1
```

A tiny expression that always returns false:

```asm
lit0
```

## Notes

- r12 is expected to hold the input pointer at unwind time.
- Keep expressions compact to avoid unnecessary stub padding.
- This is research tooling and intentionally minimal.
