# dwarf-injector (DWARF unwinder logic injection)

## Proof-of-concept warning

This repository is a proof of concept for research and CTF-style experimentation.

- It relies on implementation details of Itanium EH unwinding on x86-64.
- Behavior may differ across compilers, linkers, unwinders, optimization levels, and ABIs.
- Incorrect DWARF expressions can crash the process during unwind.
- Do not use this approach in production systems.

## What it does

The toolchain injects a DWARF expression into a function FDE in `.eh_frame`.
During exception unwinding, the unwinder evaluates that expression and writes the computed value into `rbx` (via `DW_CFA_val_expression`).

The sample program in [example/example.cpp](example/example.cpp) treats non-zero `rbx` as success.

## Current workflow (ASM-first)

1. Write expression logic in plain ASM syntax in [example/example_asm.asm](example/example_asm.asm).
2. Point the patcher to a source file `X.cpp` via `--source X.cpp`.
3. The script:
	- assembles the ASM into DWARF expression bytes,
	- computes nearest stub size (with alignment policy),
	- preprocesses `X.cpp` and writes `X.preprocessed.cpp`,
	- auto-injects stub macro and unwind stub usage when missing,
	- compiles `X.preprocessed.cpp`,
	- patches `.eh_frame` in the built binary.

No manual marker/cfi boilerplate or long NOP chain editing is required in C++ source.

## Quick start

Requirements:

- Python 3
- g++
- pyelftools (`pip install pyelftools`)

## Tested environment

The current implementation was validated on the following baseline:

- OS: Arch Linux (rolling), x86-64
- Kernel: Linux 6.19.11-arch1-1
- Compiler: g++ (GCC) 15.2.1 (20260209)

Default build flags used by the patcher:

```bash
g++ -O0 -fno-omit-frame-pointer -g -std=c++20
```

Run:

```bash
python3 patcher.py --source ./example/example.cpp
```

Example using a custom source file:

```bash
python3 patcher.py --source ./your_target.cpp
```

Then test:

```bash
./example/example_patched
```

## CLI

Common options:

- `--expr-asm`: path to ASM expression file (default `./example/example_asm.asm`)
- `--source`: C++ source, e.g. `X.cpp` (default `./example/example.cpp`)
- `--preprocessed`: generated source path (default `X.preprocessed.cpp`)
- `--input`: intermediate binary path (default `X`)
- `--output`: patched binary path (default `X_patched`)
- `--build-cmd`: custom build command template with `{source}`, `{preprocessed}`, and `{binary}` placeholders
- `--trigger-function`: unwind trigger function name for auto-injection (default `SecretUnwindTrigger`)
- `--stub-align`: stub size alignment (default `1`, meaning exact fit)
- `--max-padding`: safety limit for NOP padding (default `8`)
- `--stub-index`: choose which matching stub to patch if multiple are present

## ASM ISA documentation

Instruction set and syntax are documented in [ISA.md](ISA.md).

## Repository layout

- [example/example.cpp](example/example.cpp): user-facing target source with minimal manual prep
- [patcher.py](patcher.py): ASM assembler + source preprocess + build + binary patch pipeline
- [example/example_asm.asm](example/example_asm.asm): example boolean expression in plain ASM
