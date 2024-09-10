
import flare_emu



################ 注意：作为插件执行，容易卡死；不建议作为插件使用；作为脚本执行卡死概率小很多  #######################

'''
flare_emu模块模拟执行指令，返回指定寄存器的值
@param startAddr: 起始地址
@param endAddr: 结束地址
@param regName: 寄存器名
'''

def emu_run_code(startAddr, endAddr, regName):

    print("==========================================================")
    print(f"flare_emu run start => ( {hex(startAddr)}, {hex(endAddr)} )")

    emu_helper = flare_emu.EmuHelper()
    emu_helper.emulateRange(startAddr, endAddr, skipCalls=False)
    result = emu_helper.getRegVal(regName)

    print(f"flare_emu run end => {regName} = {hex(result)} )")

    return result





