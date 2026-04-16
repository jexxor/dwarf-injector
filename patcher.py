#!/usr/bin/env python3
import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess

from elftools.elf.elffile import ELFFile

PROJECT_NAME = "dwarf-injector"
PRIMARY_STUB_BEGIN_MARKER = "// DWARF_INJECTOR_STUB_BEGIN"
PRIMARY_STUB_END_MARKER = "// DWARF_INJECTOR_STUB_END"
LEGACY_STUB_BEGIN_MARKER = "// DWARFER_STUB_BEGIN"
LEGACY_STUB_END_MARKER = "// DWARFER_STUB_END"
STUB_MARKER_PAIRS = (
    (PRIMARY_STUB_BEGIN_MARKER, PRIMARY_STUB_END_MARKER),
    (LEGACY_STUB_BEGIN_MARKER, LEGACY_STUB_END_MARKER),
)
DEFAULT_TRIGGER_FUNCTION = "SecretUnwindTrigger"
STUB_MACRO_NAME = "DWARF_BOOL_STUB"

DW_CFA_VAL_EXPRESSION = 0x16
DWARF_REG_RBX = 0x03
NOP = 0x96
DEFAULT_BUILD_CMD = "g++ -O0 -fno-omit-frame-pointer -g -std=c++20 {preprocessed} -o {binary}"

NOARG_OPS = {
    "add": 0x22,
    "sub": 0x1C,
    "mul": 0x1E,
    "div": 0x1B,
    "mod": 0x1D,
    "and": 0x1A,
    "or": 0x21,
    "xor": 0x27,
    "shl": 0x24,
    "shr": 0x25,
    "shra": 0x26,
    "eq": 0x29,
    "ne": 0x2E,
    "lt": 0x2D,
    "le": 0x2C,
    "gt": 0x2B,
    "ge": 0x2A,
    "abs": 0x19,
    "neg": 0x1F,
    "not": 0x20,
    "dup": 0x12,
    "drop": 0x13,
    "over": 0x14,
    "swap": 0x16,
    "rot": 0x17,
    "deref": 0x06,
    "call_frame_cfa": 0x9C,
    "stack_value": 0x9F,
    "nop": NOP,
}

U8_ARG_OPS = {
    "pick": 0x15,
    "deref_size": 0x94,
}

ULEB_ARG_OPS = {
    "constu": 0x10,
    "plus_uconst": 0x23,
}

SLEB_ARG_OPS = {
    "consts": 0x11,
    "breg12": 0x7C,
}

BRANCH_OPS = {
    "bra": 0x28,
    "skip": 0x2F,
}

LIT_MNEMONIC_RE = re.compile(r"^lit([0-9]|[12][0-9]|3[01])$")


def encode_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 cannot encode negative values")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def encode_sleb128(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        if (value == 0 and sign_bit == 0) or (value == -1 and sign_bit != 0):
            more = False
        else:
            byte |= 0x80
        out.append(byte & 0xFF)
    return bytes(out)


def parse_int(token: str, asm_path: str, line_no: int) -> int:
    try:
        return int(token, 0)
    except ValueError as exc:
        raise ValueError(f"{asm_path}:{line_no}: invalid immediate '{token}'") from exc


def emit_const(code: bytearray, value: int) -> None:
    if value < -(1 << 63) or value > ((1 << 64) - 1):
        raise ValueError(f"Constant out of range for 64-bit target: {value}")

    if value >= 0:
        code.append(0x10)  # DW_OP_constu
        code.extend(encode_uleb128(value))
    else:
        code.append(0x11)  # DW_OP_consts
        code.extend(encode_sleb128(value))


def strip_comment(line: str) -> str:
    for marker in (";", "//", "#"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def expect_arg_count(mnemonic: str, args: list[str], expected: int, asm_path: str, line_no: int) -> None:
    if len(args) != expected:
        raise ValueError(
            f"{asm_path}:{line_no}: {mnemonic} expects {expected} operand(s), got {len(args)}"
        )


def assemble_asm_file(asm_path: str) -> bytes:
    with open(asm_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    code = bytearray()

    for line_no, raw in enumerate(lines, start=1):
        line = strip_comment(raw)
        if not line:
            continue

        if line.endswith(":"):
            # Labels are accepted as no-ops for readability, but not resolved for branches.
            continue

        normalized = line.replace(",", " ")
        parts = normalized.split()
        mnemonic = parts[0].lower()
        args = parts[1:]

        lit_match = LIT_MNEMONIC_RE.match(mnemonic)
        if lit_match:
            expect_arg_count(mnemonic, args, 0, asm_path, line_no)
            code.append(0x30 + int(lit_match.group(1)))
            continue

        if mnemonic in NOARG_OPS:
            expect_arg_count(mnemonic, args, 0, asm_path, line_no)
            code.append(NOARG_OPS[mnemonic])
            continue

        if mnemonic in U8_ARG_OPS:
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < 0 or value > 0xFF:
                raise ValueError(f"{asm_path}:{line_no}: {mnemonic} operand must fit u8")
            code.extend((U8_ARG_OPS[mnemonic], value))
            continue

        if mnemonic in ULEB_ARG_OPS:
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < 0:
                raise ValueError(f"{asm_path}:{line_no}: {mnemonic} operand must be non-negative")
            code.append(ULEB_ARG_OPS[mnemonic])
            code.extend(encode_uleb128(value))
            continue

        if mnemonic in SLEB_ARG_OPS:
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            code.append(SLEB_ARG_OPS[mnemonic])
            code.extend(encode_sleb128(value))
            continue

        if mnemonic in BRANCH_OPS:
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < -32768 or value > 32767:
                raise ValueError(f"{asm_path}:{line_no}: {mnemonic} operand must fit int16")
            code.append(BRANCH_OPS[mnemonic])
            code.extend(struct.pack("<h", value))
            continue

        if mnemonic == "const":
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            emit_const(code, parse_int(args[0], asm_path, line_no))
            continue

        if mnemonic == "lit":
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < 0 or value > 31:
                raise ValueError(f"{asm_path}:{line_no}: lit operand must be in range 0..31")
            code.append(0x30 + value)
            continue

        if mnemonic == "addr":
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{asm_path}:{line_no}: addr operand must fit u64")
            code.append(0x03)  # DW_OP_addr
            code.extend(value.to_bytes(8, "little"))
            continue

        if mnemonic == "load64":
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            code.append(0x7C)  # DW_OP_breg12
            code.extend(encode_sleb128(value))
            code.extend((0x94, 0x08))  # DW_OP_deref_size 8
            continue

        if mnemonic == "byte":
            expect_arg_count(mnemonic, args, 1, asm_path, line_no)
            value = parse_int(args[0], asm_path, line_no)
            if value < 0 or value > 0xFF:
                raise ValueError(f"{asm_path}:{line_no}: byte operand must fit u8")
            code.append(value)
            continue

        raise ValueError(f"{asm_path}:{line_no}: unsupported instruction '{mnemonic}'")

    if not code:
        raise ValueError(f"{asm_path}: assembled payload is empty")

    return bytes(code)


def choose_stub_size(payload_len: int, align: int) -> int:
    if payload_len <= 0:
        raise ValueError("Payload length must be positive")
    if align <= 0:
        raise ValueError("--stub-align must be >= 1")
    return ((payload_len + align - 1) // align) * align


def build_placeholder_bytes(length: int) -> bytes:
    seed = f"{PROJECT_NAME}:placeholder:{length}".encode("ascii")
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.blake2s(seed + counter.to_bytes(4, "little")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def build_val_expression_cfi(expr_bytes: bytes) -> bytes:
    cfi = bytearray((DW_CFA_VAL_EXPRESSION,))
    cfi.extend(encode_uleb128(DWARF_REG_RBX))
    cfi.extend(encode_uleb128(len(expr_bytes)))
    cfi.extend(expr_bytes)
    return bytes(cfi)


def cfi_escape_text(cfi_bytes: bytes) -> str:
    raw = ", ".join(f"0x{byte:02x}" for byte in cfi_bytes)
    return f".cfi_escape {raw}"


def upsert_stub_macro(source: str, cfi_text: str) -> str:
    generated_body = (
        "// Auto-generated by dwarf-injector. Do not edit by hand.\n"
        f'#define {STUB_MACRO_NAME} "{cfi_text}"'
    )
    generated_block = (
        f"{PRIMARY_STUB_BEGIN_MARKER}\n"
        f"{generated_body}\n"
        f"{PRIMARY_STUB_END_MARKER}\n"
    )

    for begin_marker, end_marker in STUB_MARKER_PAIRS:
        pattern = re.compile(
            rf"({re.escape(begin_marker)}\n)(.*?)(\n{re.escape(end_marker)})",
            re.DOTALL,
        )
        matches = list(pattern.finditer(source))
        if len(matches) > 1:
            raise RuntimeError(
                "Found multiple stub marker blocks. "
                f"Keep only one of {begin_marker} ... {end_marker}."
            )
        if len(matches) == 1:
            return pattern.sub(lambda m: m.group(1) + generated_body + m.group(3), source, count=1)

    macro_pattern = re.compile(rf"(?m)^[ \t]*#define[ \t]+{re.escape(STUB_MACRO_NAME)}[^\n]*$")
    macro_matches = list(macro_pattern.finditer(source))
    macro_line = f'#define {STUB_MACRO_NAME} "{cfi_text}"'

    if len(macro_matches) > 1:
        raise RuntimeError(f"Found multiple #{STUB_MACRO_NAME} definitions. Keep only one.")
    if len(macro_matches) == 1:
        return macro_pattern.sub(macro_line, source, count=1)

    include_matches = list(re.finditer(r"(?m)^[ \t]*#include[^\n]*\n", source))
    if include_matches:
        insert_pos = include_matches[-1].end()
        gap_prefix = "" if source[:insert_pos].endswith("\n\n") else "\n"
        return source[:insert_pos] + gap_prefix + generated_block + source[insert_pos:]

    return generated_block + "\n" + source


def find_function_body_bounds(source: str, function_name: str) -> tuple[int, int] | None:
    pattern = re.compile(rf"{re.escape(function_name)}\s*\([^)]*\)\s*\{{", re.MULTILINE)
    match = pattern.search(source)
    if not match:
        return None

    open_brace = match.end() - 1
    depth = 0
    for idx in range(open_brace, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_brace + 1, idx

    raise RuntimeError(f"Could not find closing brace for function '{function_name}'")


def ensure_trigger_stub_usage(source: str, trigger_function: str) -> str:
    bounds = find_function_body_bounds(source, trigger_function)
    if bounds is None:
        raise RuntimeError(
            f"Trigger function '{trigger_function}' not found. "
            "Use --trigger-function or add this function to source."
        )

    body_start, body_end = bounds
    body = source[body_start:body_end]

    missing_statements = []
    if '.cfi_same_value r12' not in body:
        missing_statements.append('asm volatile(".cfi_same_value r12");')
    if STUB_MACRO_NAME not in body:
        missing_statements.append(f"asm volatile({STUB_MACRO_NAME});")

    if not missing_statements:
        return source

    throw_match = re.search(r"(?m)^[ \t]*throw\b[^\n;]*;", body)
    if throw_match:
        insertion_pos = body_start + throw_match.start()
        indent = re.match(r"^[ \t]*", throw_match.group(0)).group(0)
    else:
        insertion_pos = body_end
        indent = "    "

    injected = "".join(f"{indent}{statement}\n" for statement in missing_statements)
    return source[:insertion_pos] + injected + source[insertion_pos:]


def preprocess_source(
    source_path: str,
    preprocessed_path: str,
    placeholder_cfi: bytes,
    trigger_function: str,
) -> None:
    with open(source_path, "r", encoding="utf-8") as f:
        source = f.read()

    updated = upsert_stub_macro(source, cfi_escape_text(placeholder_cfi))
    updated = ensure_trigger_stub_usage(updated, trigger_function)

    preprocessed_dir = os.path.dirname(preprocessed_path)
    if preprocessed_dir:
        os.makedirs(preprocessed_dir, exist_ok=True)

    with open(preprocessed_path, "w", encoding="utf-8") as f:
        f.write(updated)


def build_binary(
    source_path: str,
    preprocessed_path: str,
    binary_path: str,
    build_cmd_template: str,
) -> None:
    rendered = build_cmd_template.format(
        source=shlex.quote(source_path),
        preprocessed=shlex.quote(preprocessed_path),
        binary=shlex.quote(binary_path),
    )
    cmd = shlex.split(rendered)
    subprocess.run(cmd, check=True)


def default_preprocessed_path(source_path: str) -> str:
    source = Path(source_path)
    if source.suffix:
        return str(source.with_name(f"{source.stem}.preprocessed{source.suffix}"))
    return str(source.with_name(f"{source.name}.preprocessed.cpp"))


def default_binary_path(source_path: str) -> str:
    source = Path(source_path)
    if source.suffix:
        return str(source.with_suffix(""))
    return str(source)


def locate_blob(data: bytearray, elf: ELFFile, blob: bytes, stub_index: int) -> tuple[int, int]:
    eh_frame = elf.get_section_by_name(".eh_frame")
    if eh_frame is None:
        raise RuntimeError(".eh_frame section not found")

    sec_start = eh_frame.header["sh_offset"]
    sec_end = sec_start + eh_frame.header["sh_size"]

    matches = []
    scan = sec_start
    while True:
        idx = data.find(blob, scan, sec_end)
        if idx == -1:
            break
        matches.append(idx)
        scan = idx + 1

    if not matches:
        raise RuntimeError("Could not find generated stub marker in .eh_frame")

    if stub_index < 0 or stub_index >= len(matches):
        raise RuntimeError(f"stub-index {stub_index} out of range (found {len(matches)} stubs)")

    return matches[stub_index], len(matches)


def patch_binary(
    input_path: str,
    output_path: str,
    placeholder_cfi: bytes,
    patched_cfi: bytes,
    stub_index: int,
) -> tuple[int, int]:
    if len(placeholder_cfi) != len(patched_cfi):
        raise RuntimeError("Placeholder and patched CFI blobs must have the same size")

    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    elf = ELFFile(io.BytesIO(data))
    patch_at, total_stubs = locate_blob(data, elf, placeholder_cfi, stub_index)
    data[patch_at : patch_at + len(placeholder_cfi)] = patched_cfi

    with open(output_path, "wb") as f:
        f.write(data)

    os.chmod(output_path, os.stat(input_path).st_mode & 0o777)
    return patch_at, total_stubs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble a plain ASM DWARF expression, preprocess source stub size, "
            "build ELF, and patch .eh_frame"
        )
    )

    parser.add_argument(
        "--source",
        default="./example/example.cpp",
        help="Path to C++ source (manual stub markers are optional)",
    )
    parser.add_argument(
        "--preprocessed",
        default=None,
        help="Path for generated preprocessed source (default: X.preprocessed.cpp next to --source)",
    )
    parser.add_argument(
        "--expr-asm",
        default="./example/example_asm.asm",
        help="Path to plain ASM expression file",
    )
    parser.add_argument(
        "--trigger-function",
        default=DEFAULT_TRIGGER_FUNCTION,
        help="Function name where throw/unwind happens (default: SecretUnwindTrigger)",
    )
    parser.add_argument(
        "--input",
        "--binary",
        dest="input_binary",
        default=None,
        help="Path to intermediate binary built from preprocessed source (default: X)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to patched binary (default: <binary>_patched)",
    )
    parser.add_argument(
        "--build-cmd",
        default=DEFAULT_BUILD_CMD,
        help="Build command template. Use {source}, {preprocessed}, and {binary} placeholders.",
    )

    parser.add_argument(
        "--stub-align",
        type=int,
        default=1,
        help="Round stub size to this alignment (default 1 = exact payload size)",
    )
    parser.add_argument(
        "--max-padding",
        type=int,
        default=8,
        help="Fail if alignment would require more than this many NOP padding bytes",
    )
    parser.add_argument(
        "--stub-index",
        type=int,
        default=0,
        help="Which matching stub blob to patch if multiple are present",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    source_path = args.source
    preprocessed_path = args.preprocessed or default_preprocessed_path(source_path)
    input_binary = args.input_binary or default_binary_path(source_path)
    output_binary = args.output or f"{input_binary}_patched"

    payload = assemble_asm_file(args.expr_asm)
    stub_size = choose_stub_size(len(payload), args.stub_align)
    padding = stub_size - len(payload)

    if padding > args.max_padding:
        raise RuntimeError(
            f"Refusing to emit long NOP chain: padding={padding}, limit={args.max_padding}. "
            "Use --stub-align 1 or increase --max-padding explicitly."
        )

    placeholder_expr = build_placeholder_bytes(stub_size)
    patched_expr = payload + bytes((NOP,)) * padding

    placeholder_cfi = build_val_expression_cfi(placeholder_expr)
    patched_cfi = build_val_expression_cfi(patched_expr)

    preprocess_source(source_path, preprocessed_path, placeholder_cfi, args.trigger_function)
    build_binary(source_path, preprocessed_path, input_binary, args.build_cmd)

    patch_at, total_stubs = patch_binary(
        input_binary,
        output_binary,
        placeholder_cfi,
        patched_cfi,
        args.stub_index,
    )

    print(f"[+] Expression source: {args.expr_asm}")
    print(f"[+] Payload size: {len(payload)} bytes")
    print(f"[+] Stub size: {stub_size} bytes (align={args.stub_align}, padding={padding})")
    print(f"[+] Source: {source_path}")
    print(f"[+] Trigger function: {args.trigger_function}")
    print(f"[+] Wrote preprocessed source: {preprocessed_path}")
    print(f"[+] Built intermediate binary: {input_binary}")
    print(f"[+] Patched {input_binary} -> {output_binary}")
    print(f"[+] Stub index: {args.stub_index}/{total_stubs - 1}, file offset: 0x{patch_at:x}")


if __name__ == "__main__":
    main()
