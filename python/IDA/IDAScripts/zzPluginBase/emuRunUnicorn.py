
from unicorn import *
from unicorn.arm64_const import *



REG_NAME_ARM64 = {
    "x0": UC_ARM64_REG_X0,
    "x1": UC_ARM64_REG_X1,
    "x2": UC_ARM64_REG_X2,
    "x3": UC_ARM64_REG_X3,
    "x4": UC_ARM64_REG_X4,
    "x5": UC_ARM64_REG_X5,
    "x6": UC_ARM64_REG_X6,
    "x7": UC_ARM64_REG_X7,
    "x8": UC_ARM64_REG_X8,
    "x9": UC_ARM64_REG_X9,
    "x10": UC_ARM64_REG_X10,
    "x11": UC_ARM64_REG_X11,
    "x12": UC_ARM64_REG_X12,
    "x13": UC_ARM64_REG_X13,
    "x14": UC_ARM64_REG_X14,
    "x15": UC_ARM64_REG_X15,
    "x16": UC_ARM64_REG_X16,
    "x17": UC_ARM64_REG_X17,
    "x18": UC_ARM64_REG_X18,
    "x19": UC_ARM64_REG_X19,
    "x20": UC_ARM64_REG_X20,
    "x21": UC_ARM64_REG_X21,
    "x22": UC_ARM64_REG_X22,
    "x23": UC_ARM64_REG_X23,
    "x24": UC_ARM64_REG_X24,
    "x25": UC_ARM64_REG_X25,
    "x26": UC_ARM64_REG_X26,
    "x27": UC_ARM64_REG_X27,
    "x28": UC_ARM64_REG_X28,
    "x29": UC_ARM64_REG_X29,
    "x30": UC_ARM64_REG_X30,
}

def unicornRun(startAddr, codeHex, regName):
    print("==========================================================")
    ARM_CODE = bytes.fromhex(codeHex)
    endAddr = startAddr + len(ARM_CODE) - 4
    print(f"unicorn run start => ( {hex(startAddr)}, {hex(endAddr)} )")
    
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    # 设置内存映射, 大小为100M
    mu.mem_map(0x1000000, 100 * 1024 * 1024) 
    mu.mem_write(startAddr, ARM_CODE)
    mu.emu_start(startAddr, endAddr)

    regName = regName.lower()
    result = mu.reg_read(REG_NAME_ARM64.get(regName))
    print(f"unicorn run end => {regName} = {hex(result)} )")
    return result

