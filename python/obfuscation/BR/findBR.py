import idc
import idaapi


#获取匹配的指令
def get_all_instructions(min_addr, pattern):

    result = []

    # 遍历每一条指令
    cur_address = min_addr
    end_address = idc.BADADDR
    
    while cur_address < end_address:
        if idc.is_code(idc.get_full_flags(cur_address)):
            # 获取指令的反汇编文本
            disasm = idc.generate_disasm_line(cur_address, 0)
            if disasm:
                if pattern == None:
                    result.append((cur_address, disasm))
                else:
                    if pattern in disasm:
                        result.append((cur_address, disasm))
        
        cur_address = idc.next_head(cur_address)

    return result




'''
开辟栈空间的常见 ARM64 指令包括：
SUB SP, SP, #<size>：减少 SP 寄存器的值以分配栈空间。
STP <reg1>, <reg2>, [SP, #-<size>]!：将寄存器的值存储到栈上并减少栈指针的值。
'''
def is_stack_allocation_instruction(address):

    op_str = idc.GetDisasm(address).lower()
    
    # 判断是否是 SUB 指令
    if "sub" in op_str and "sp," in op_str:
        return True
      
    # 判断是否是 STP 指令
    elif "stp" in op_str and "[sp,#" in op_str and "]!" in op_str:
        return True

    return False


def find_func_start(ins_addr):
    addr_end = 0
    while(ins_addr > addr_end):
        #判断当前地址是否为开辟栈空间指令，且该指令是该函数的第一条指令
        if is_stack_allocation_instruction(ins_addr):
            func = idaapi.get_func(ins_addr)
            if func and func.start_ea == ins_addr:
                return ins_addr
        ins_addr = idc.prev_head(ins_addr)
                
    return 0


def find_BR_func(min_addr, mnem):
    ins_info_list = get_all_instructions(min_addr, mnem)
    func_addr_dict = {}
    for addr, _ in ins_info_list:
        func_start = find_func_start(addr)
        func_addr_dict[addr] = func_start 
    return func_addr_dict


#查找对应的函数
# def find_BR_func(min_addr, mnem):

#     print(f"---------------------- {mnem} -----------------------")
#     ins_info_list = get_all_instructions(min_addr, mnem)
#     func_addr = []
#     for addr, _ in ins_info_list:
#         func_start = find_func_start(addr)
#         func_addr.append((addr, func_start))

#     for addr, func_start in func_addr:
#         print(f' {mnem} at {hex(addr)}, func_addr = {hex(func_start)}')

# find_BR_func(0x16190, 'BR')
# find_BR_func(0x16190, 'BLR')