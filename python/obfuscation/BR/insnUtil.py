
from capstone import *
from keystone import *


ZZ_ARCH_ARM = 0
ZZ_ARCH_ARM64 = 1

class OBFInsnUtil:

    def __init__(self, arch=ZZ_ARCH_ARM64):
        self.init_keystone(arch)
        self.init_capstone(arch)

    ############## disasm #############
        
    #生成汇编代码
    # 使用： for i in disasm(hexstr, addr): print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    def disasm(self, hexstr, addr):
        code_bytes = bytes.fromhex(hexstr)
        return self.disasm(code_bytes, addr)
    
    def disasm(self, code_bytes, addr):
        return self.cs.disasm(code_bytes, addr)

        
    #生成汇编代码
    # 使用： for (address, size, mnemonic, op_str) in disasm_lite(hexstr, addr):
    def disasm_lite(self, hexstr, addr):
        code_bytes = bytes.fromhex(hexstr)
        return self.disasm_lite(code_bytes, addr)
    
    def disasm_lite(self, code_bytes, addr):
        return self.cs.disasm_lite(code_bytes, addr)
    

    ############## asm ################

    #生成机器码, 默认返回byte数组, 如果要返回bytes， 则第三个参数传True
    # 使用：encoding, count = generate_code(asm_str, addr)
    def asm(self, asm_str, addr, as_bytes = False):
        return self.ks.asm(asm_str, addr, as_bytes)   



######################################## init ###################################################


    def init_keystone(self, arch):
        if arch == ZZ_ARCH_ARM64:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        else:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
    

    def init_capstone(self, arch):
        if arch == ZZ_ARCH_ARM64:
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        self.cs.detail = True        # 设置为详细反汇编模式
        self.cs.skipdata = True      # 设置反汇编跳过数据

