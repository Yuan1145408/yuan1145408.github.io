import sys
import os
from typing import Tuple

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def get_text_section(pe: "pefile.PE") -> Tuple[int, int]:
    for sec in pe.sections:
        name = sec.Name.decode(errors='ignore').strip('\x00')
        if name == '.text':
            return sec.PointerToRawData, sec.SizeOfRawData
    # fallback: use entry point section
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for sec in pe.sections:
        start = sec.VirtualAddress
        end = start + sec.Misc_VirtualSize
        if start <= ep_rva < end:
            return sec.PointerToRawData, sec.SizeOfRawData
    raise RuntimeError('Could not locate code section')


def main():
    if len(sys.argv) < 2:
        print('Usage: python disasm_exe.py <exe> [max_insns] [--out <file>]')
        sys.exit(1)
    path = sys.argv[1]
    max_insns = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 300
    out_path = None
    if len(sys.argv) >= 4 and sys.argv[3] == '--out' and len(sys.argv) >= 5:
        out_path = sys.argv[4]
    pe = pefile.PE(path)
    is64 = pe.FILE_HEADER.Machine == 0x8664
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = True

    # Use memory-mapped image to avoid zero RAW sizes
    mem = pe.get_memory_mapped_image()

    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base = pe.OPTIONAL_HEADER.ImageBase
    # Locate section containing EP, define maximum bytes to disassemble within that section
    max_bytes = 0x3000
    sec_name = None
    for sec in pe.sections:
        start = sec.VirtualAddress
        end = start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
        if start <= ep_rva < end:
            sec_name = sec.Name.decode(errors='ignore').strip('\x00')
            max_bytes = min(max_bytes, end - ep_rva)
            break
    ep_off_in_mem = pe.get_offset_from_rva(ep_rva)
    code = mem[ep_off_in_mem:ep_off_in_mem + max_bytes]

    lines = []
    lines.append(f"EntryPoint RVA: 0x{ep_rva:x}")
    lines.append(f"ImageBase: 0x{base:x}")
    if sec_name:
        lines.append(f"EP in section: {sec_name}")
    else:
        lines.append("EP section not identified")
    lines.append("\nDisassembly:")
    count = 0
    for insn in md.disasm(code, base + ep_rva):
        lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        count += 1
        if count >= max_insns:
            break
    output = "\n".join(lines)
    print(output)
    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"\nSaved disassembly to: {out_path}")


if __name__ == '__main__':
    main()