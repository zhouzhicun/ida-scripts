from patch import *


################################################ 执行脚本  ###################################################

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
    result_func_set = [0x1619C]  #需要deobfuscate的函数列表

    #初始化
    init(create_config())
    #开始deobfuscate
    for func_addr in sorted(result_func_set):
        deobf(func_addr, is_patch)

main()