import queue

import idc
import idaapi
import idautils

from capstone.arm64_const import *
from unicorn.arm64_const import *
from unicorn import *


from insnUtil import *
from unicornUtil import *
from commStruct import *





# 1. 将函数头放到队列中
# 2. 从队列中取出一个地址，开始执行
# 3. 执行时，将执行过的指令和上下文保存到指令栈中

# 4. 遇到了ret或者是bl .__stack_chk_fail 就停止
# 5. 遇到死循环代码就停止
# 6. 遇到 bl 或者 svc 指令就跳过，或者非法内存访问也跳过
# 8.
# 8. 遇到 b 或者 b.cond 指令就停止，并创建新路径。 
# 4. 判断是否到达了br/blr reg
# 5. 如果到达了br/blr reg，首先判断当前路径有没有条件标识(即cond_desc)，
#    1.有则创建跳转地址的新路径，并添加到br表中；
#    2.没有的话，则从指令栈中回溯指令，找到决定reg的条件指令，
#       2.1 如果没有找到条件指令，则认为是直接跳转，创建跳转地址的新路径，并添加到BR/BLR表中；  
#       2.2 如果有找到条件指令，并从该条件指令的下一条指令开始创建两条路径（分别对应条件的true和false分支）添加到队列中。



#条件映射表
ZZCondTable = {
    'EQ': 'NE',
    'NE': 'EQ',
    'CS': 'CC',
    'CC': 'CS',
    'MI': 'PL',
    'PL': 'MI',
    'VS': 'VC',
    'VC': 'VS',
    'HI': 'LS',
    'LS': 'HI',
    'GE': 'LT',
    'LT': 'GE',
    'GT': 'LE',
    'LE': 'GT',
    'AL': 'AL'
}

#转换条件码
def convert_cond_code(cond_code):
    cond_code = cond_code.upper()
    if cond_code == 'HS':
        return 'CS'
    elif cond_code == 'LO':
        return 'CC'
    else:
        return cond_code
  
manager = None


#################################### helper ####################################################

def get_offset_str(addr):
    global manager
    return hex(addr - manager.config.mem_code[0])

def find_cond(path, dest_reg_name):

    dest_reg_name = UnicornUtil.convert_reg64(dest_reg_name)
    reg_name_set = {dest_reg_name}

    target_cond_ins_info = None
    cmp_ins_count = 0   #回溯时中间cmp指令数
    cond_ins_count = 0  #回溯时中间条件指令数

    #开始回溯指令，查找条件指令
    for ins_info in path.ins_stack[::-1]:

        ins = ins_info.ins
        
        #获取该指令的操作数列表
        op_list = UnicornUtil.get_op_list(ins)
        if len(op_list) == 0:
            continue
        
        #判断第一个操作数是否为寄存器，不是则跳过
        op0 = op_list[0]
        if not UnicornUtil.is_reg_name(op0):
            continue

        op0 = UnicornUtil.convert_reg64(op0)
        ins_mnemonic = ins.mnemonic.lower()

        if ins_mnemonic == 'cmp':
            cmp_ins_count += 1
        elif UnicornUtil.is_condition(ins_mnemonic):
            cond_ins_count += 1

        #如果op0寄存器在集合中
        if op0 in reg_name_set:
            #如果当前指令是条件指令，则该指令就是目标条件指令
            
            if UnicornUtil.is_condition(ins_mnemonic):
                target_cond_ins_info = ins_info
                break
            else:
                for op in op_list[1:]:
                    if UnicornUtil.is_reg_name(op):
                        op = UnicornUtil.convert_reg64(op)
                        reg_name_set.add(op)

    #回溯完毕，如果找到对应的条件指令，则中间条件指令数需-1
    if target_cond_ins_info is not None:
        cond_ins_count -= 1

    return target_cond_ins_info, cmp_ins_count, cond_ins_count
    
#################################### unicorn hook ####################################################

def hook_unmapped_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print('error! access invalid mem, pc:%x type:%d addr:%x size:%x' % (pc, type, address, size))
    uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
    return True


def hook_code(uc, address, size, user_data):

    global manager

    #1.解析当前指令并打印
    code = manager.uc.mem_read(address, size)
    cur_ins = list(manager.ins_util.disasm(code, address))[0]
    cur_context = UnicornUtil.get_context(uc)
    ins_mnemonic = cur_ins.mnemonic.lower()
    ins_address = get_offset_str(address)
    ins_asm =  cur_ins.mnemonic + ' ' + cur_ins.op_str


    #添加当前指令
    cur_ins_info = ZZInsnInfo(address, cur_ins, cur_context)
    manager.cur_path.add_ins(cur_ins_info)


    #trace当前指令
    cur_path_start = manager.cur_path.start_addr
    if cur_path_start in manager.config.trace_ins_path_table:
        print('[+] tracing instruction => addr:%s size:%x, ins:%s, context:%s' % (ins_address, size, ins_asm, cur_context))

    

    ############################# 判断指令类型 ########################################

    #2.0.1 跳过bl、svc指令
    if ins_mnemonic == 'bl' or ins_mnemonic == 'svc':
        uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
        return


    #2.0.1 跳过非法内存访问：非栈或so本身内存访问
    config = manager.config
    if UnicornUtil.is_access_ilegel_memory(uc, cur_ins, config.mem_code, config.mem_stack):
        uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
        return



    #2.1 遇到ret直接停止
    if ins_mnemonic == 'ret':
        print("[+] encountered ret, stop")
        uc.emu_stop()
        return
    
    #2.2 遇到bl .__stack_chk_fail停止
    if UnicornUtil.is_call_stack_chk_fail(cur_ins, cur_context, manager.config.stack_chk_fail_func_addr):
        print("[+] encountered bl .__stack_chk_fail, stop")
        uc.emu_stop()
        return
    

    if 'udf' in ins_mnemonic:
        print("[+] encountered udf, stop")
        uc.emu_stop()
        return

    #3.3 简单死代码检测
    if UnicornUtil.is_simple_dead_code(cur_ins):
        print("[+] encountered dead code, stop")
        uc.emu_stop()
        return
    
    #3.4 太多指令
    if manager.is_dead_code():
        path = manager.cur_path
        start_addr, context, cond_desc, ins_count = path.start_addr, path.context, path.cond_desc, path.ins_count()
        path_desc = f'start_addr: {hex(start_addr)}, cur_addr: {hex(cur_ins.address)},  cond_desc: {cond_desc}, ins_count: {str(ins_count)}'
        print("[+] encountered too many instructions, stop; path_info = " + path_desc)
        uc.emu_stop()
        return
    

    #3.7 判断是否为b指令
    if ins_mnemonic == 'b':
        cond_true_path = ZZPathInfo(cur_ins.address, cur_ins.operands[0].imm, cur_context, None)
        add_path(manager.cur_path, cond_true_path)
        uc.emu_stop()
        return

    #3.8 判断是否为b.cond条件跳转指令   
    if ins_mnemonic.startswith('b.'):
        dest_addr = cur_ins.operands[0].imm
        next_addr = cur_ins.address + size
        cond_true_path = ZZPathInfo(cur_ins.address, dest_addr, cur_context, None)
        cond_false_path = ZZPathInfo(cur_ins.address, next_addr, cur_context, None)
        add_path(manager.cur_path, cond_true_path)
        add_path(manager.cur_path, cond_false_path)
        uc.emu_stop()
        return
    
    #cbz,或者 cbnz：CBNZ W0, loc_12FB90
    if ins_mnemonic.startswith('cb'):
        dest_addr = cur_ins.operands[1].imm
        next_addr = cur_ins.address + size
        cond_true_path = ZZPathInfo(cur_ins.address, dest_addr, cur_context, None)
        cond_false_path = ZZPathInfo(cur_ins.address, next_addr, cur_context, None)
        add_path(manager.cur_path, cond_true_path)
        add_path(manager.cur_path, cond_false_path)
        uc.emu_stop()
        return

    
    #3.9 判断是否为br跳转
    if ins_mnemonic == 'br':

        table = manager.br_table
        cond_desc = manager.cur_path.cond_desc
        br_reg_name, br_reg_value = UnicornUtil.parse_reg(cur_ins, cur_context, 0)
        dest_addr_str = f'{hex(br_reg_value)}'

        #1.判断是否存在cond_desc
        if cond_desc is not None:
            #1.1.保存跳转信息到BR表中
            cur_jump_info = f'{cond_desc}: {dest_addr_str}'
            if ins_address in table:
                table[ins_address] = table[ins_address] + " | " + cur_jump_info
            else:
               table[ins_address] = cur_jump_info 
            
            #1.2.新建跳转地址的路径
            path = ZZPathInfo(cur_ins.address, br_reg_value, cur_context, None)
            add_path(manager.cur_path, path)
            
            uc.emu_stop()
            return

        #2.回溯指令栈，找对应的条件指令
        cond_ins_info, cmp_count, cond_count = find_cond(manager.cur_path, br_reg_name)
        if cond_ins_info is None:
            #2.1没有条件指令, 记录到br表，并创建新path
            table[ins_address] = f'{dest_addr_str}'
            path = ZZPathInfo(cur_ins.address, br_reg_value, cur_context, None)
            add_path(manager.cur_path, path)

            uc.emu_stop()
            return
        else:
            #2.1有条件指令
            # 解析条件指令
            cond_ins, cond_context = cond_ins_info.ins, cond_ins_info.context
            cond_info = UnicornUtil.parse_cond_info(cond_ins, cond_context)
            cond, cond_dest_reg_name = cond_info.cond, cond_info.dest_reg_name
            true_value, false_value = cond_info.cond_true_value, cond_info.cond_false_value
            
            #创建两条分支路径：从条件指令开始创建两条子路径分支(对应条件的true, false分支).
            next_ins_addr = cond_ins.address + 4

            #其他描述
            cond_other_desc = ''
            if cmp_count > 0 or cond_count > 0:
                cond_other_desc = f"_{hex(cond_ins.address)}-{cmp_count}-{cond_count}"
            
            true_cond_desc = cond + '_true' + cond_other_desc
            true_cond_context = UnicornUtil.set_reg_value(cond_context, cond_dest_reg_name, true_value)
            true_path = ZZPathInfo(cond_ins.address, next_ins_addr, true_cond_context, true_cond_desc)
            false_cond_desc = cond + '_false' + cond_other_desc
            false_cond_context = UnicornUtil.set_reg_value(cond_context, cond_dest_reg_name, false_value)
            false_path = ZZPathInfo(cond_ins.address, next_ins_addr, false_cond_context, false_cond_desc)
            add_path(manager.cur_path, true_path)
            add_path(manager.cur_path, false_path)

            uc.emu_stop()
            return

     #3.10 判断是否为blr跳转
    if ins_mnemonic == 'blr':

        table = manager.blr_table
        cond_desc = manager.cur_path.cond_desc
        blr_reg_name, blr_reg_value = UnicornUtil.parse_reg(cur_ins, cur_context, 0)
        next_ins_addr = cur_ins.address + 4
        dest_addr_str = f'{hex(blr_reg_value)}'
        
        #判断是否存在cond_desc
        if cond_desc is not None:
            cur_jump_info = f'{cond_desc}: {dest_addr_str}'
            if ins_address in table:
                table[ins_address] = table[ins_address] + " | " + cur_jump_info
            else:
               table[ins_address] = cur_jump_info 
            
            path = ZZPathInfo(cur_ins.address, next_ins_addr, cur_context, None)
            add_path(manager.cur_path, path)

            uc.emu_stop()
            return

        #回溯指令栈，找对应的条件指令
        cond_ins_info, cmp_count, cond_count = find_cond(manager.cur_path, blr_reg_name)
        if cond_ins_info is None:
            #没有条件指令
            table[ins_address] = f'{dest_addr_str}'
            path = ZZPathInfo(cur_ins.address, next_ins_addr, cur_context, None)
            add_path(manager.cur_path, path)

            uc.emu_stop()
            return
        else:
            #有条件指令
            #解析条件指令，并从条件指令开始创建两条子路径分支(对应条件的true, false分支).
            cond_ins, cond_context = cond_ins_info.ins, cond_ins_info.context
            cond_info = UnicornUtil.parse_cond_info(cond_ins, cond_context)
            cond, cond_dest_reg_name = cond_info.cond, cond_info.dest_reg_name
            true_value, false_value = cond_info.cond_true_value, cond_info.cond_false_value

            #其他描述
            cond_other_desc = ''
            if cmp_count > 0 or cond_count > 0:
                cond_other_desc = f"_{hex(cond_ins.address)}-{cmp_count}-{cond_count}"
            
            true_cond_desc = cond + '_true' + cond_other_desc
            true_cond_context = UnicornUtil.set_reg_value(cond_context, cond_dest_reg_name, true_value)
            true_path = ZZPathInfo(cond_ins.address, next_ins_addr, true_cond_context, true_cond_desc)

            false_cond_desc = cond + '_false' + cond_other_desc
            false_cond_context = UnicornUtil.set_reg_value(cond_context, cond_dest_reg_name, false_value)
            false_path = ZZPathInfo(cond_ins.address, next_ins_addr, false_cond_context, false_cond_desc)

            add_path(manager.cur_path, true_path)
            add_path(manager.cur_path, false_path)

            uc.emu_stop()
            return   


def is_valid_addr(addr):
    if addr >= manager.config.so_start_addr and addr <= manager.config.so_end_addr:
        return True
    else:
        return False


def add_path(cur_path, target_path):
    global manager
    if not is_valid_addr(target_path.start_addr):
        #print(f'目标路径首地址不在so内, target_path = {target_path.path_desc()}')
        return

    # print('------------------ 添加路径 -------------------------')
    # print(f'当前路径：\n {cur_path.path_desc()}')
    # print(f'添加路径：\n {target_path.path_desc()}')
    manager.add_path(target_path)



#模拟执行指令流(指令路径), 返回分支路径数组
def emu_run_path(path):

    global manager

    start_addr, context, path_desc = path.start_addr, path.context, path.path_desc()
    #print(f'当前执行路径：\n {path_desc}')

    #重置path状态
    manager.set_cur_path(path)

    #准备context，并执行
    cur_pc = start_addr
    cur_context = context

    while True:
        try:
            #开始模拟执行，执行完毕后，执行break跳出循环
            UnicornUtil.set_context(manager.uc, cur_context)   
            manager.uc.emu_start(cur_pc, manager.config.mem_code[0] + manager.config.mem_code[1])  
            break
        except Exception as e:
            #碰到异常，判断指令地址是否在地址有效范围内，不是有效地址则退出循环；否则跳过当前指令，从下一条继续执行
            print(f"exception = {e}")
            last_ins = path.ins_stack[-1]
            if not is_valid_addr(last_ins.addr):
                break 
            
            #更新context和pc，继续运行~
            cur_pc = manager.uc.reg_read(UC_ARM64_REG_PC) + 4
            cur_context = last_ins.context  



############################################# 解析跳转信息，并patch #####################################################################


def patch(ins_mnem):
    
    global manager
    
    bad_table = {}
    jump_table = None
    ins_mnemonic = None
    if ins_mnem == 'br':
        jump_table = manager.br_table
        ins_mnemonic = 'B'
    elif ins_mnem == 'blr':
        jump_table = manager.blr_table
        ins_mnemonic = 'BL'
    else:
        print(f"invalid ins_mnem, ins_mnem = {ins_mnem}")
        return

    for addr_key in jump_table.keys():

        addr_val = int(addr_key, 16)

        #解析跳转信息
        #jmp_info = '0x16324' 或 'lt_true: 0x16324 | lt_false: 0x16418' 或 'lt_true_0-2: 0x16324 | lt_false_0-2: 0x16418'
        cur_jump_info_str = jump_table[addr_key]
        patch_ins_addr, code_size, asm_code = parse_jump_info(addr_val, ins_mnemonic, cur_jump_info_str)

        if asm_code is not None:

            #获取原汇编指令
            origin_code_bytes = idaapi.get_bytes(patch_ins_addr, code_size)
            origin_code_ins_arr = manager.ins_util.disasm_lite(origin_code_bytes, patch_ins_addr)
            comment = 'patch by zz: '
            for (_, _, mnemonic, op_str) in origin_code_ins_arr:
                comment += f'{mnemonic} {op_str}; '

            #patch
            bytes, _ = manager.ins_util.asm(asm_code, patch_ins_addr, True)
            print(f'patched at: {hex(patch_ins_addr)}, asm_code = {asm_code}, jump_info = {cur_jump_info_str}')
            idaapi.patch_bytes(patch_ins_addr, bytes)

            #添加注释
            idc.set_cmt(patch_ins_addr, comment, 1)


        else:
            bad_table[addr_key] = cur_jump_info_str
        
    #打印异常信息
    if len(bad_table) > 0:
        print(f'\n\n----------- {ins_mnemonic} 特殊情况，需手动patch ----------------')
        for addr_key in bad_table.keys():
            print(f'addr = {addr_key}, jmp_infos = {bad_table[addr_key]}' )




'''解析跳转信息
jmp_info = 'lt_true: 0x16324',  返回：0x16324, lt, true, None
jmp_info = 'lt_true_0x16000-0-2: 0x16324',  返回：0x16324, lt, true, 0x16000-0-2
'''
def parse_single_jump_info(jump_info):
    infos = [item.strip() for item in jump_info.split(':')]
    dest_addr = int(infos[1], 16)
    cond_desc_arr = infos[0].split('_')
    cond_name = cond_desc_arr[0]
    cond_value = cond_desc_arr[1]
    cond_other_desc = None
    if len(cond_desc_arr) == 3:
        cond_other_desc = cond_desc_arr[2]

    return dest_addr, cond_name, cond_value, cond_other_desc

''' 解析跳转信息
单分支：
jmp_info = '0x16324'
双分支：
jmp_info = 'lt_true: 0x16324 | lt_false: 0x16418'
jmp_info = 'lt_true_0x16000-0-2: 0x16324 | lt_false_0x16000-0-2: 0x16418'
'''
def parse_jump_info(patch_ins_addr, ins_mnemonic, jump_info):

    asm_code = None
    code_size = 4
    sub_jmp_infos = [item.strip() for item in jump_info.split('|')]
    if len(sub_jmp_infos) == 1:
        dest_addr = int(sub_jmp_infos[0], 16)
        if is_valid_addr(dest_addr):
            asm_code = f'{ins_mnemonic} {hex(dest_addr)}'

    elif len(sub_jmp_infos) == 2:
        #找到ture, false分支
        jump_info_true = None
        jump_info_false = None
        jump_info0 = sub_jmp_infos[0]
        jump_info1 = sub_jmp_infos[1]
        if 'true' in jump_info0:
            jump_info_true, jump_info_false = jump_info0, jump_info1
        else:
            jump_info_true, jump_info_false = jump_info1, jump_info0

        #解析单个跳转信息
        next_addr_val = patch_ins_addr + 4
        dest_addr_true, cond_name, _, cond_other_desc = parse_single_jump_info(jump_info_true)
        dest_addr_false, _, _, _ = parse_single_jump_info(jump_info_false)

        cond_name = convert_cond_code(cond_name)  #cond_name.upper()
        if is_valid_addr(dest_addr_true) and is_valid_addr(dest_addr_false):
            if cond_other_desc is None:
                if dest_addr_true == next_addr_val:
                    asm_code = f'{ins_mnemonic}.{ZZCondTable[cond_name]} {hex(dest_addr_false)}'    
                elif dest_addr_false == next_addr_val:
                    asm_code = f'{ins_mnemonic}.{cond_name} {hex(dest_addr_true)}'
                else:
                    patch_ins_addr = patch_ins_addr - 4
                    asm_code = f'{ins_mnemonic}.{cond_name} {hex(dest_addr_true)};'
                    asm_code += f'{ins_mnemonic} {hex(dest_addr_false)};'
                    code_size = 8

    return patch_ins_addr, code_size, asm_code
    
            
        
    

################################################ 初始化并运行 #######################################################

def init(config):

    global manager

    manager = OBFManager(config)

    #1.创建unicorn
    bin_end_addr = idc.get_inf_attr(idc.INF_MAX_EA)
    bin_bytes = idaapi.get_bytes(0, bin_end_addr)
    isARM64 = config.arch == ZZ_ARCH_ARM64
    uc = UnicornUtil.create_unicorn(isARM64, manager.config.mem_code, manager.config.mem_stack, bin_bytes, hook_code, hook_unmapped_mem_access)
    manager.set_uc(uc)
    return manager


def deobf(func_addr, is_patch):
    
    global manager


    print(f'\n\n--------------------- 开始模拟执行，func = {hex(func_addr)} ------------------------')

    #1.重置manager
    manager.reset()

    #2.创建第一条路径，开启模拟执行
    first_path = ZZPathInfo(0, manager.config.mem_code[0] + func_addr, None, None)
    manager.add_path(first_path) 
    while not manager.path_queue.empty(): #一直循环，直到队列为空
        #获取并执行path
        cur_path = manager.pop_path()
        emu_run_path(cur_path) 

    #3.打印结果
    print(f'--------------------- 执行结果打印，func = {hex(func_addr)} ----------------------')
    manager.print_track_result()

    #4.patch
    print(f'--------------------- 开始Patch，func = {hex(func_addr)} ---------------------')
    if is_patch:
        patch('br')
        patch('blr')



