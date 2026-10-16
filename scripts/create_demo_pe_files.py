from pathlib import Path

def create_version_dll():
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x80).to_bytes(4, "little")
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos_full = (bytes(dos) + dos_stub).ljust(0x80, b"\x00")

    pe_sig = b"PE\x00\x00"
    machine = 0x014C
    sections_count = 2
    opt_size = 0xE0
    characteristics = 0x0002 | 0x2000  # EXECUTABLE | DLL

    file_header = bytearray(20)
    file_header[0:2] = machine.to_bytes(2, "little")
    file_header[2:4] = sections_count.to_bytes(2, "little")
    file_header[4:8] = (1700000000).to_bytes(4, "little")
    file_header[16:18] = opt_size.to_bytes(2, "little")
    file_header[18:20] = characteristics.to_bytes(2, "little")

    opt_header = bytearray(opt_size)
    opt_header[0:2] = (0x010B).to_bytes(2, "little")
    opt_header[16:20] = (0x1000).to_bytes(4, "little")
    opt_header[28:32] = (0x00400000).to_bytes(4, "little")
    opt_header[32:36] = (0x1000).to_bytes(4, "little")
    opt_header[36:40] = (0x0200).to_bytes(4, "little")
    opt_header[56:60] = (0x4000).to_bytes(4, "little")
    opt_header[60:64] = (0x0400).to_bytes(4, "little")
    opt_header[68:70] = (2).to_bytes(2, "little")
    opt_header[70:72] = (0x0000).to_bytes(2, "little")  # No ASLR, No DEP
    opt_header[92:96] = (16).to_bytes(4, "little")

    # Data Directories:
    # 0 = Export Directory (RVA 0x2000, Size 0x200)
    opt_header[96:100] = (0x2000).to_bytes(4, "little")
    opt_header[100:104] = (0x200).to_bytes(4, "little")

    # 9 = TLS Directory (RVA 0x2200, Size 0x18)
    opt_header[168:172] = (0x2200).to_bytes(4, "little")
    opt_header[172:176] = (0x18).to_bytes(4, "little")

    # Section 1 (.text)
    sec1 = bytearray(40)
    sec1[0:8] = b".text\x00\x00\x00"
    sec1[8:12] = (0x0400).to_bytes(4, "little")
    sec1[12:16] = (0x1000).to_bytes(4, "little")
    sec1[16:20] = (0x0400).to_bytes(4, "little")
    sec1[20:24] = (0x0400).to_bytes(4, "little")
    sec1[36:40] = (0x60000020).to_bytes(4, "little")

    # Section 2 (.rdata)
    sec2 = bytearray(40)
    sec2[0:8] = b".rdata\x00\x00"
    sec2[8:12] = (0x0400).to_bytes(4, "little")
    sec2[12:16] = (0x2000).to_bytes(4, "little")
    sec2[16:20] = (0x0400).to_bytes(4, "little")
    sec2[20:24] = (0x0800).to_bytes(4, "little")
    sec2[36:40] = (0x40000040).to_bytes(4, "little")

    headers = (dos_full + pe_sig + bytes(file_header) + bytes(opt_header) + bytes(sec1) + bytes(sec2)).ljust(0x400, b"\x00")

    sec1_data = (
        b"\x90\x90\xcc" +
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00" +
        b"strcpy\x00sprintf\x00gets\x00" +
        b"mscoree.dll\x00_CorDllMain\x00" +
        b"v4.0.30319\x00.NETFramework,Version=v4.8\x00" +
        b"Assembly.Load\x00Process.Start\x00WebClient\x00Confuser.Core\x00" +
        b"cmd.exe /c start powershell.exe -ExecutionPolicy Bypass\x00"
    ).ljust(0x400, b"\x90")

    sec2_bytes = bytearray(0x400)
    # Export directory
    sec2_bytes[12:16] = (0x2080).to_bytes(4, "little") # Name RVA
    sec2_bytes[16:20] = (1).to_bytes(4, "little")      # Base
    sec2_bytes[20:24] = (2).to_bytes(4, "little")      # NumberOfFunctions
    sec2_bytes[24:28] = (2).to_bytes(4, "little")      # NumberOfNames
    sec2_bytes[28:32] = (0x2028).to_bytes(4, "little") # AddressOfFunctions
    sec2_bytes[32:36] = (0x2030).to_bytes(4, "little") # AddressOfNames
    sec2_bytes[36:40] = (0x2038).to_bytes(4, "little") # AddressOfNameOrdinals

    sec2_bytes[0x28:0x2C] = (0x20A0).to_bytes(4, "little") # Forwarded
    sec2_bytes[0x2C:0x30] = (0x1000).to_bytes(4, "little") # Normal

    sec2_bytes[0x30:0x34] = (0x20C0).to_bytes(4, "little") # Name 0
    sec2_bytes[0x34:0x38] = (0x20E0).to_bytes(4, "little") # Name 1

    sec2_bytes[0x38:0x3A] = (0).to_bytes(2, "little")
    sec2_bytes[0x3A:0x3C] = (1).to_bytes(2, "little")

    sec2_bytes[0x80:0x8C] = b"version.dll\x00"
    sec2_bytes[0xA0:0xC0] = b"VERSION_ORIG.GetFileVersionInfoA\x00".ljust(32, b"\x00")
    sec2_bytes[0xC0:0xD4] = b"GetFileVersionInfoA\x00"
    sec2_bytes[0xE0:0xEB] = b"CustomInit\x00"

    # TLS Directory at 0x200 (RVA 0x2200):
    sec2_bytes[0x200:0x204] = (0x00402200).to_bytes(4, "little")
    sec2_bytes[0x204:0x208] = (0x00402210).to_bytes(4, "little")
    sec2_bytes[0x208:0x20C] = (0x00402214).to_bytes(4, "little")
    sec2_bytes[0x20C:0x210] = (0x00402220).to_bytes(4, "little") # AddressOfCallBacks

    sec2_bytes[0x220:0x224] = (0x00401010).to_bytes(4, "little") # Callback 1
    sec2_bytes[0x224:0x228] = (0x00401050).to_bytes(4, "little") # Callback 2
    sec2_bytes[0x228:0x22C] = (0).to_bytes(4, "little")

    # Add high-entropy overlay payload at the end
    overlay_data = bytes([((x * 41 + 17) % 256) for x in range(512)])

    pe_dll_data = headers + sec1_data + bytes(sec2_bytes) + overlay_data
    out_path = Path("test-files/demo_showcase/version.dll")
    out_path.write_bytes(pe_dll_data)
    print("Saved test-files/demo_showcase/version.dll, size:", len(pe_dll_data))

if __name__ == "__main__":
    create_version_dll()
