
'''
针对 Armariris(孤挺花) OLLVM 字符串加密
脚本来源：白龙-字符串加密第四篇：https://www.yuque.com/lilac-2hqvv/hgwa9g/gzxl56

Armariris 字符串加密特征：
1.字符串解密函数都放在 .init_array中，
2.且函数名以 .datadiv_decode 开头。

脚本解密思路：
1.通过unicorn模拟执行 .datadiv_decodeXXX系列函数，
2.并hook memory write操作， 在hook操作中得到明文，然后进行patch。

'''



# IDA 相关模块
import ida_bytes
import idaapi
import idautils
import idc

# 导入 Unicorn 模块
from unicorn import *
from unicorn.arm_const import *

#import uTrace


def get_arm_code():
    binaryFileEnd = idc.get_inf_attr(idc.INF_MAX_EA)
    print(hex(binaryFileEnd))
    ARM_CODE = idaapi.get_bytes(0, binaryFileEnd)
    return ARM_CODE

def get_data_range():
    data_start = 0
    data_end = 0
    for seg in idautils.Segments():
        name = idc.get_segm_name(seg)
        if name == ".data":
            data_start = idc.get_segm_start(seg)
            data_end = idc.get_segm_end(seg)

    return data_start,  data_end



##################################################################################


def create_unicorn(ARM_CODE, ADDRESS, data_start, data_end):

    # 初始化模拟器
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # 将想要模拟执行的机器码写到我们刚分配的虚拟内存上
    mu.mem_map(ADDRESS, 16 * 1024 * 1024)
    mu.mem_write(ADDRESS, ARM_CODE)

    # 设置栈寄存器
    StackBase = ADDRESS + (15 * 1024 * 1024)
    mu.reg_write(UC_ARM_REG_SP, StackBase)
    
    # 设置函数返回地址
    mu.reg_write(UC_ARM_REG_LR, ADDRESS)


    # 添加指令追踪
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=1, end=0)
    # 添加内存写入监控
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)

    
    # 对读写的内存访问 Hook 回调
    def hook_mem_access(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            addr = address - ADDRESS
            if data_start < addr < data_end:
                ida_bytes.patch_byte(addr, value)

    # 指令追踪的回调，每条指令执行前都会进入此处逻辑
    def hook_code(uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address - ADDRESS, size))


    return mu



def find_datadiv_decode_funcs():
    func_list = []
    for addr in idautils.Functions():
        funcName = idaapi.get_ea_name(addr)
        if funcName.startswith(".datadiv_decode"):
            funcEnd = idc.get_func_attr(addr, idc.FUNCATTR_END)
            funcStart = addr

            #限制解密函数至少包含十条汇编，才做处理。
            if len(list(idautils.FuncItems(addr))) > 10:            
                # 如果是thumb模式，地址+1
                arm_or_thumb = idc.get_sreg(addr, "T")
                if arm_or_thumb:
                    funcStart = addr + 1

            func_list.append((funcName, funcStart, funcEnd))

######################################################################################

def decypt():

    ADDRESS = 0x1000000

    #1.
    arm_code = get_arm_code()
    data_start, data_end = get_data_range()
    mu = create_unicorn(arm_code, ADDRESS, data_start, data_end)

    #2.
    func_list = find_datadiv_decode_funcs()
    for (_, funcStart, funcEnd) in func_list:
        mu.emu_start(ADDRESS + funcStart, ADDRESS + funcEnd - 4)

    print("emulate over")



            

