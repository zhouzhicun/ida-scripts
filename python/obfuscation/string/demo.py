
import ida_bytes
import flare_emu

# jd: int8x16_t *sub_7EE8()
print("\n\n-----------------------------\n\n")

def emu_run_decrypt(func_addr, str_addr, str_len):

    emu_helper = flare_emu.EmuHelper()
    emu_helper.emulateRange(func_addr, registers={"arg1": str_addr, "arg2": str_len})
    result = emu_helper.getRegVal('X0')

    str = emu_helper.getEmuString(result).decode("UTF-8")
    plain_text_bytes = emu_helper.getEmuBytes(result, str_len)

    ida_bytes.patch_bytes(str_addr, bytes(plain_text_bytes))
    ida_bytes.patch_byte(str_addr + str_len, 0)
    
    print(f"result = {hex(result)} str = {str}, bytes = {plain_text_bytes}")


emu_run_decrypt(0xA6B0, 0x42610 + 8 * 0, 4)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 1, 21)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 7, 4)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 8, 22)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 14, 9)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 17, 47)

emu_run_decrypt(0xA6B0, 0x42610 + 8 * 29, 10)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 32, 47)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 44, 5)
emu_run_decrypt(0xA6B0, 0x42610 + 8 * 46, 27)



