

import idc
import idaapi
import ida_bytes
import pyperclip

import zzPluginBase.utils as utils
import zzPluginBase.keycap as keycap

################################### 选择代码块 #############################################

#获取寄存器名字
def get_regName(addr):
    disasm = idc.GetDisasm(addr)
    print("asm => " + disasm)
    disasm = disasm.upper()
    parts = disasm.split()
    isBXX = parts[0] == 'B' or parts[0] == 'BR' or parts[0] == "BLR" or parts[0] == "BL" 
    if (isBXX) and len(parts) > 1:
        return parts[1]
    else:
        return ""


#检查选择代码是否有效
def check_code():

    invalid = (0, 0, 0, "")

    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if start == idaapi.BADADDR or end == idaapi.BADADDR:
        print("No code selected.")
        return invalid

    last = end - 4
    regName = get_regName(last)
    if len(regName) < 1:
        print("not BR reg, please check~")
        return invalid
    
    return (1, start, last, regName)



#patch指令: nop掉前面N-1条指令， patch最后一条将BR Xn patch为 B 0xXXXX;  并添加注释
def patch_code(startInsnAddr, endInsnAddr, targetAddr):
    
    disasm = idc.GetDisasm(endInsnAddr)

    #1.NOP掉前面N-1条指令
    nopInsnCount = int((endInsnAddr - startInsnAddr) / 4)
    nopCodeBytes = keycap.generate_code("nop", 0)
    ida_bytes.patch_bytes(startInsnAddr, bytes(nopCodeBytes) * nopInsnCount)

    #1.patch最后一条指令
    code = f"B {hex(targetAddr)}"
    codeBytes =  keycap.generate_code(code, endInsnAddr)
    ida_bytes.patch_bytes(endInsnAddr, bytes(codeBytes))
    print("patch code => " +  hex(endInsnAddr) + " : " + code)

    #2.添加注释
    idaapi.set_cmt(endInsnAddr, disasm, 0)


    

