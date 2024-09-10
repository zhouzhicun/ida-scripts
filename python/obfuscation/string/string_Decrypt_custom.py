

'''
针对自定义字符串解密函数 

特征：
1.调用字符串解密函数，返回解密后的字符串堆地址，例如：
v0 = sub_ABB0(flt_26E70, 20);   //调用sub_ABB0函数进行解密
_system_property_get(v0, v2);


脚本解密思路：
字符串解密完整流程应该分四步走:
1.通过交叉引用获取所有调用解密函数的上层函数
2.获取密文首地址以及其长度
3.调用 decrypt 函数
4.明文以注释或回填或其他某种方式予以展示，增强静态分析时的体验

'''


import re
import ida_idaapi
import idaapi
import idc
import ida_auto
import ida_bytes
import idautils

import flare_emu
from operator import itemgetter

#######################################################################################

#预处理：
def init():
    start = 0
    end = 0
    for seg in idautils.Segments():
        name = idc.get_segm_name(seg)
        if name == ".data":
            start = idc.get_segm_start(seg)
            end = idc.get_segm_end(seg)

    #找到 data 段，将其中所有数据先 del_items转成 undefined，再 create_data转成 byte_xxx。
    for address in range(start, end):
        ida_bytes.del_items(address, 0, 1)
        ida_bytes.create_data(address, 0, 1, ida_idaapi.BADADDR)


#解密后，重新分析
def final():
    for i in idautils.Segments():
        seg = idaapi.getseg(i)
        segName = idaapi.get_segm_name(seg)
        if "data" in segName:
            startAddress = seg.start_ea
            endAddress = seg.end_ea
            ida_bytes.del_items(startAddress, 0, endAddress)
            ida_auto.plan_and_wait(startAddress, endAddress)

###################################################################################

##常量定义
dump_func_divider = "\n-------------------------------dump func list --------------------------------\n"
func_field_name = "funcName"
func_field_address = "address"
func_field_xrefCount = "xrefCount"
func_field_insnCount = "insnCount"
func_field_rate = "rate"
func_field_topNum = 50


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


######################################### 对指定解密函数 匹配，解析，模拟执行并Patch ##############################################



#匹配解密函数调用，并解析函数参数
def matchArgs(xrefaddress, decrypt_func_addr):
    #1.反编译该引用地址所在的函数, 并得到伪代码
    cfun = idaapi.decompile(xrefaddress)   
    codeStr = str(cfun)

    #2.解密解密函数的调用参数：字符串地址，长度
    decrypt_func_str = 'sub_' + hex(decrypt_func_addr)[2:]
    argsMatch = []
    callList = re.findall(f'{decrypt_func_str}\(.*?&byte_([0-9a-fA-F]+), (\d+)\)', codeStr)
    for one in callList:
        argsprint = []
        argsprint.append(int(one[0], 16))
        argsprint.append(int(one[1], 10))
        argsMatch.append(argsprint)
    return argsMatch


def emu_run_decrypt(emu_helper, func_addr, str_addr, str_len):

    emu_helper.emulateRange(func_addr, registers={"arg1": str_addr, "arg2": str_len})
    result = emu_helper.getRegVal('X0')

    #str = emu_helper.getEmuString(result).decode("UTF-8")
    plain_text_bytes = emu_helper.getEmuBytes(result, str_len)
    ida_bytes.patch_bytes(str_addr, bytes(plain_text_bytes))
    ida_bytes.patch_byte(str_addr + str_len, 0)
    
    print(f"decrypt string => addr = {hex(str_addr)}  bytes = {plain_text_bytes}")




# func_addr = 0xABB0
def decryptOneFunc(decrypt_func_addr):

    #1.获取decrypt_func_addr的所有引用
    xrefs = idautils.CodeRefsTo(decrypt_func_addr, 0)
    
    #2.遍历所有引用，获取其所属函数，然后匹配到解密函数的调用，并进一步解析得到字符串地址和长度
    funcList = []
    addressList = []
    for xref in list(xrefs):
        # 尝试反编译交叉引用所涉及到的函数，decompile方法需要传入地址，就会反编译其所属函数
        # 一些函数反编译会失败，所以需要加个异常处理
        try:
            funcName = idc.get_func_name(xref)
            if funcName not in funcList:
                funcList.append(funcName)
                argsMatch = matchArgs(xref, decrypt_func_addr)     
                for one in argsMatch:
                    str_address = one[0]
                    if str_address not in addressList:
                        addressList.append(str_address)
                        str_length = one[1]
                        emu_run_decrypt(emu_helper, decrypt_func_addr, str_address, str_length)
              
                    else:
                        pass
            else:
                pass
        except:
            pass


########################################### 解密 ##############################################


emu_helper = flare_emu.EmuHelper()


def decrypt():
    #1.解密函数列表，找到所有自定义的解密函数
    decrypt_func_table = [
        0xABB0,
        0xABD0,
    ]

    #2.预处理
    init()

    #3.逐个处理   
    for func_addr in decrypt_func_table:
        decryptOneFunc(func_addr)

    #4.重新分析
    final()



def main():
    #dump 函数列表
    get_func_list_orderby_xref()

    #解密
    #decrypt()