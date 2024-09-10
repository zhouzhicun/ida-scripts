
import idautils
import idaapi
import idc
import ida_nalt
import ida_entry
import ida_ida

from operator import itemgetter
import zzPluginBase.utils as utils



################################## dump反编译的伪代码 ############################################

#dump指定地址范围的反编译伪代码
def get_func_code(start, end): 
    code = ""
    for func in idautils.Functions(start, end):
        #反编译函数，得到伪代码
        code += str(idaapi.decompile(func)) + "\n\n"
    return code


#dump指定节的反编译伪代码， 如果segName=None, 则dump所有函数的伪代码
def get_all_func_code(segNames = None):
    if segNames is None:
        return get_func_code(0, idc.BADADDR)

    resultCode = ''
    for segName in segNames:
        seg = idaapi.get_segm_by_name(segName)
        if seg is None:
            continue
        start = seg.start_ea
        end = seg.end_ea
        resultCode += get_func_code(start, end)
    return resultCode




################################## dump 匹配的指令 ############################################


#获取匹配的指令
def get_all_instructions(pattern = None):

    result = []
    start, size = utils.getSegmentAddrRange("text")
    if size == 0:
        return result

    # 遍历每一条指令
    end_address = start + size
    cur_address = start
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


#获取所有BR_CSEL配对指令
def get_all_BR_CSEL():
    brArr = get_all_instructions("BR")
    br_csel_arr = []
    for br in brArr:
        brAddr = br[0]
        cur_addr = brAddr
        for i in range(1, 10):
            
            cur_addr = idc.prev_head(cur_addr)
            mnem = idc.print_insn_mnem(cur_addr)
            if mnem == "RET":
                break
            if mnem  == "CSEL" or mnem == "CSET":
                disasm = idc.generate_disasm_line(cur_addr, 0)
                br_csel_arr.append((brAddr, cur_addr, disasm))
                break
    return br_csel_arr




################################## 获取函数列表 ############################################

##常量定义
dump_func_divider = "\n-------------------------------dump func list --------------------------------\n"
func_field_name = "funcName"
func_field_address = "address"
func_field_xrefCount = "xrefCount"
func_field_insnCount = "insnCount"
func_field_rate = "rate"
func_field_topNum = 50


#获取函数列表
def get_func_list():
    funcList = ""
    maxAddress = ida_ida.inf_get_max_ea()
    for func in idautils.Functions(0, maxAddress):
        if len(list(idautils.FuncItems(func))) > 50:
            functionName = str(idaapi.ida_funcs.get_func_name(func))
            oneFunction = hex(func) + "!" + functionName + "\t\n"
            funcList += oneFunction
    print(funcList)
    return funcList


#获取函数列表，按照xref数量排序
def get_func_list_orderby_xref():
    functionList = []
    for func in idautils.Functions():
        xrefs = idautils.CodeRefsTo(func, 0)
        xrefCount = len(list(xrefs))
        oneFuncDict = {
            func_field_name: idc.get_func_name(func), 
            func_field_address: hex(func), 
            func_field_xrefCount: xrefCount
            }
        functionList.append(oneFuncDict)
    function_list_by_countNum = sorted(functionList, key=itemgetter(func_field_xrefCount), reverse=True)

    funcList = dump_func_divider
    for func in function_list_by_countNum[:func_field_topNum]:
        funcList += f'{func_field_name}:{func[func_field_name]}, {func_field_address}:{func[func_field_address]}, {func_field_xrefCount}:{func[func_field_xrefCount]}\n'
    print(funcList)
    return funcList



#获取函数列表，按照指令数量排序
def get_func_list_orderby_insn_count():
    functionList = []
    for func in idautils.Functions():
        insnCount = idc.get_func_attr(func, idc.FUNCATTR_END) - idc.get_func_attr(func, idc.FUNCATTR_START)
        oneFuncDict = {
            func_field_name: idc.get_func_name(func), 
            func_field_address: hex(func), 
            func_field_insnCount: insnCount
        }
        functionList.append(oneFuncDict)

    function_list_by_countNum = sorted(functionList, key=itemgetter(func_field_insnCount), reverse=True)
  
    funcList = dump_func_divider
    for func in function_list_by_countNum[:func_field_topNum]:
        funcList += f'{func_field_name}:{func[func_field_name]}, {func_field_address}:{func[func_field_address]}, {func_field_insnCount}:{func[func_field_insnCount]}\n'
    print(funcList)
    return funcList


#获取函数列表，按照加解密特征指令数量排序(LSL, AND, ORR, LSR, ROR)
def get_func_list_orderby_eor():
    functionList = []
    for addr in list(idautils.Functions()):
        funcName = idc.get_func_name(addr)
        func = idaapi.get_func(addr)
        length = func.size()
        dism_addr = list(idautils.FuncItems(addr))
        count = 0
        if length > 0x10:
            for line in dism_addr:
                m = idc.print_insn_mnem(line)
                if m.startswith("LSL") | m.startswith("AND") | m.startswith("ORR") | m.startswith("LSR") | m.startswith("ROR"):
                    count += 1

    
            oneFuncDict = {
                func_field_name: funcName, 
                func_field_address: hex(addr), 
                func_field_rate: count / length
            }
            functionList.append(oneFuncDict)

    function_list_by_countNum = sorted(functionList, key=itemgetter(func_field_rate), reverse=True)

    funcList = dump_func_divider
    for func in function_list_by_countNum[:func_field_topNum]:
        funcList += f'{func_field_name}:{func[func_field_name]}, {func_field_address}:{func[func_field_address]}, {func_field_rate}:{func[func_field_rate]}\n'
    print(funcList)
    return funcList



#获取导出函数列表
def get_export_func_list():

    exports = []
    
    # 获取当前二进制文件的导入函数数量
    n = ida_entry.get_entry_qty()
    for i in range(0, n):
        # 获取第 i 个导入函数的序号
        ordinal = ida_entry.get_entry_ordinal(i)
        # 使用序号获取导入函数的地址
        ea = ida_entry.get_entry(ordinal)
        # 使用序号获取导入函数的名称
        name = ida_entry.get_entry_name(ordinal)
        # 将导入函数的名称和地址作为一个字典添加到列表中
        exports.append({func_field_name: name, func_field_address: hex(ea)})
    
    funcList = dump_func_divider
    for func in exports:
        funcList += f'{func_field_name}:{func[func_field_name]}, {func_field_address}:{func[func_field_address]}\n'
    print(funcList)
    return funcList



#获取导入函数列表
def get_import_func_list():

    def imp_cb(ea, name, ord):
        if not name:
            name = ''
        imports.append({func_field_name: name, func_field_address: hex(ea)})
        return True

    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(0, nimps):
        ida_nalt.enum_import_names(i, imp_cb)

    funcList = dump_func_divider
    for func in imports:
        funcList += f'{func_field_name}:{func[func_field_name]}, {func_field_address}:{func[func_field_address]}\n'
    print(funcList)
    return funcList


