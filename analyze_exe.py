import sys
import os
import re
from typing import List

try:
    import pefile
except ImportError:
    print("pefile not installed")
    sys.exit(1)


def is_dotnet(pe: "pefile.PE") -> bool:
    # Check for COM descriptor (CLI) directory presence
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
    try:
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        return dir_entry.VirtualAddress != 0 and dir_entry.Size != 0
    except Exception:
        return False


def get_imports(pe: "pefile.PE") -> List[str]:
    imports = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                for imp in entry.imports:
                    name = ''
                    if imp.name:
                        name = imp.name.decode(errors='ignore') if isinstance(imp.name, bytes) else str(imp.name)
                    else:
                        name = f"ord({imp.ordinal})" if hasattr(imp, 'ordinal') else ''
                    imports.append(f"{dll_name}!{name}")
    except Exception:
        pass
    return imports


def get_exports(pe: "pefile.PE") -> List[str]:
    exports = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = ''
                if sym.name:
                    name = sym.name.decode(errors='ignore') if isinstance(sym.name, bytes) else str(sym.name)
                exports.append(name or f"ord({sym.ordinal})")
    except Exception:
        pass
    return exports


def extract_ascii_strings(data: bytes, min_len: int = 6) -> List[str]:
    pattern = rb"[ -~]{%d,}" % min_len
    strings = re.findall(pattern, data)
    return [s.decode(errors='ignore') for s in strings]


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_exe.py <path_to_exe> [--out <report.txt>]")
        sys.exit(1)

    path = sys.argv[1]
    out_path = None
    if len(sys.argv) >= 4 and sys.argv[2] == '--out':
        out_path = sys.argv[3]
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(1)

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()

    lines: List[str] = []
    lines.append(f"File: {path}")
    lines.append(f"Machine: 0x{pe.FILE_HEADER.Machine:04x}")
    lines.append(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    sections = [sec.Name.decode(errors='ignore').strip('\u0000') for sec in pe.sections]
    lines.append(f"Sections: {sections}")
    lines.append("Section details:")
    for sec in pe.sections:
        name = sec.Name.decode(errors='ignore').strip('\x00')
        lines.append(
            f"  {name}: RVA=0x{sec.VirtualAddress:x}, VSZ=0x{sec.Misc_VirtualSize:x}, RAW=0x{sec.PointerToRawData:x}, RSZ=0x{sec.SizeOfRawData:x}"
        )

    dotnet = is_dotnet(pe)
    lines.append(f"Is .NET: {dotnet}")
    zero_raw_sections = [sec.Name.decode(errors='ignore').strip('\x00') for sec in pe.sections if sec.SizeOfRawData == 0]
    if zero_raw_sections:
        lines.append(f"Possible packed (sections with zero raw size): {zero_raw_sections}")

    imports = get_imports(pe)
    if imports:
        lines.append("Imports (top 50):")
        for i, imp in enumerate(imports[:50], 1):
            lines.append(f"  {i:02d}. {imp}")
    else:
        lines.append("No import table or failed to parse imports.")

    exports = get_exports(pe)
    if exports:
        lines.append("Exports:")
        for e in exports:
            lines.append(f"  {e}")
    else:
        lines.append("No exports or failed to parse exports.")

    # Extract strings from raw file
    with open(path, 'rb') as f:
        data = f.read()
    strings = extract_ascii_strings(data, min_len=7)
    lines.append("\nStrings (top 100):")
    for s in strings[:100]:
        lines.append(f"  {s}")

    output = "\n".join(lines)
    print(output)
    if out_path:
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\nSaved report to: {out_path}")
        except Exception as e:
            print(f"Failed to save report: {e}")


if __name__ == '__main__':
    main()