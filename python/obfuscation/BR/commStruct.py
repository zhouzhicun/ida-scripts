import re
import queue


from insnUtil import *



class OBFManager:
    def __init__(self, config):

        self.config = config
        self.ins_util = OBFInsnUtil(config.arch)
        self.uc = None

        self.reset()


    #重置
    def reset(self):
        self.br_table = {}
        self.blr_table = {}
        self.path_queue = queue.Queue()         #路径队列
        self.addedPathDict = {}                 #已添加过的Path，防止重复添加
        self.cur_path = None                    #当前Path


    def set_uc(self, uc):
        self.uc = uc

    #重置PathTraceState
    def set_cur_path(self, cur_path):
        self.cur_path = cur_path


    #入队执行，校验Path是否添加到队列，防止重复执行
    def add_path(self, path):
        path_identity = path.path_identity()
        if path_identity not in self.addedPathDict:
            print(f'add path = {path_identity}')
            self.addedPathDict[path_identity] = 1
            self.path_queue.put(path)

    #从队列中取出一个path，开始执行
    def pop_path(self):
        return self.path_queue.get()
    
    #判断是否为死代码
    def is_dead_code(self):
        return self.cur_path.ins_count() > self.config.dead_code_insn_max_count

    #打印结果
    def print_track_result(self):
        #打印所有BR分支
        print('---------------- print all br -----------------')
        sorted_keys = sorted(self.br_table.keys())
        for addr_str in sorted_keys:
            print(f'br_addr = {addr_str}, jump info = {self.br_table[addr_str]}' )

        #打印所有BLR分支
        print('---------------- print all blr -----------------')
        sorted_keys = sorted(self.blr_table.keys())
        for addr_str in sorted_keys:
            print(f'br_addr = {addr_str}, jump info = {self.blr_table[addr_str]}' )





#####################################################################################################

#配置
class OBFConfig:
    def __init__(self, arch, mem_code, mem_stack, so_start_addr, so_end_addr, stack_chk_fail_func_addr, dead_code_insn_max_count, trace_ins_path_table):
        self.arch = arch
        self.mem_code = mem_code                                    #代码内存范围
        self.mem_stack = mem_stack                                  #栈内存范围
        self.so_start_addr = so_start_addr                          #so代码起止地址
        self.so_end_addr = so_end_addr                              
        self.stack_chk_fail_func_addr = stack_chk_fail_func_addr    #__stack_chk_fail_addr函数地址
        self.dead_code_insn_max_count = dead_code_insn_max_count    #死代码检测最大指令条数
        self.trace_ins_path_table = trace_ins_path_table            #需要trace指令的路径表



#条件指令信息
class ZZCondInfo:
    def __init__(self, cond_ins_name, cond, dest_reg_name, cond_true_value, cond_false_value):
        self.cond_ins_name = cond_ins_name          #条件指令名字
        self.cond = cond                            #条件
        self.dest_reg_name = dest_reg_name          #目的寄存器名字
        self.cond_true_value = cond_true_value      #条件true的值
        self.cond_false_value = cond_false_value    #条件false的值

#指令信息
class ZZInsnInfo:
    def __init__(self, addr, ins, context):
        self.addr = addr                        #指令地址
        self.context = context                  #当前上下文
        self.ins = ins                          #指令


#路径信息
class ZZPathInfo:
    def __init__(self, prev_addr, start_addr, context, cond_desc):
        self.prev_addr = prev_addr          #上一条指令
        self.start_addr = start_addr        #起始地址
        self.context = context              #上下文
        self.cond_desc = cond_desc          #条件描述
        self.ins_stack = []                 #指令栈

    def ins_count(self):
        return len(self.ins_stack)

    def add_ins(self, ins):
        self.ins_stack.append(ins)

    #路径标识, 用于标识路径唯一性
    def path_identity(self):
        path_desc = f"{hex(self.start_addr)}"
        if self.cond_desc is not None:
            path_desc =  path_desc + "_" + self.cond_desc
        return path_desc
      
    def path_desc(self):
        desc = f'start_addr = {hex(self.start_addr)},  prev_addr = {hex(self.prev_addr)},  cond_desc = {self.cond_desc}, context = {self.context}'
        return desc
