from findBR import *
from patch import *





###################################################################################################

def print_func_addr(mnem, func_addr_dict):
    print(f"------------- cur func list [{mnem}] ---------------")
    for ins_addr, func_start in func_addr_dict.items():
        print(f"ins_addr = {ins_addr:#x}, func_start = {func_start:#x}")

def find_func(so_start_addr):
    br_func_addr_dict = find_BR_func(so_start_addr, "BR")
    blr_func_addr_dict = find_BR_func(so_start_addr, "BLR")
    print_func_addr('BR', br_func_addr_dict)
    print_func_addr('BLR', blr_func_addr_dict)

    result_func_set = set(br_func_addr_dict.values()) | set(blr_func_addr_dict.values())
    return result_func_set


def create_config():

    arch = ZZ_ARCH_ARM64
    
   #so库中start和stack_chk_fail的函数地址
    so_start_addr = 0x63550
    so_end_addr = 0x191150
    stack_chk_fail_func_addr = None #0x160D0

    #默认设置
    unicorn_mem_code =  (0x00000000, 100 * 0x1000 * 0x1000)      #代码：100M
    unicorn_mem_stack = (0x80000000, 8 * 0x1000 * 0x1000)       #栈：8M
    dead_code_ins_max_count = 1000                             #死代码最大指令条数

    trace_ins_path_table = []
    config = OBFConfig(arch, unicorn_mem_code, unicorn_mem_stack, so_start_addr, so_end_addr, stack_chk_fail_func_addr, dead_code_ins_max_count, trace_ins_path_table)
    return config


def main():

    is_patch = True
    exclude_func_table = []

    #初始化
    manager = init(create_config())

    #查找BR混淆的方法
    print('---------------- find all BR func -----------------')
    result_func_set = find_func(manager.config.so_start_addr)

    result_func_arr = sorted(result_func_set)
    for addr in result_func_arr:
        print(f'func_addr = {hex(addr)}')

    #开始deobfuscate, 过滤掉不需要被排除的方法（比如特定原因导致该函数无法模拟执行，则可添加到exclude_func_table表中）
    for func_addr in result_func_arr:
        if func_addr not in exclude_func_table:
            deobf(func_addr, is_patch)
        
main()