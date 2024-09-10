
import ida_auto
import ida_bytes
import ida_segment

import binascii
import idautils
import idaapi
import idc
import ida_nalt

import os
import time



############################################################################


# 获取SO库所在路径以及文件名
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filepath, filename


# 获取指定节的地址范围
def getSegmentAddrRange(segName):
    start = 0
    size = 0
    # 将地址范围限定于指定节
    for segIndex in idautils.Segments():
        temp_seg = idaapi.getseg(segIndex)
        temp_segName = ida_segment.get_segm_name(temp_seg)
        if segName in temp_segName:
            start = temp_seg.start_ea
            size = temp_seg.size()
            break
    return start, size



# 获取函数的首地址
def get_func_start_address(ea):
    return idc.get_func_attr(ea, idc.FUNCATTR_START)

# 写文件
def writeFile(fileName, content):
    so_path, so_name = getSoPathAndName()
    fileName = so_name.split(".")[0] + "_" + fileName
    save_path = os.path.join(so_path, fileName)
    with open(save_path, "w", encoding="utf-8") as F:
        F.write(content)
    F.close()
    print(f"location: {save_path}")



################################# 查找代码 ###########################################

'''
二进制搜索：搜索指定地址范围内的指定模式；
hexStr: 需要搜索的16进制字符串，支持空格隔开；支持空格隔开；例如："000000000000000" 或者 "11 22 33 44 55 66 77 88"
返回匹配的地址列表
'''
def searchCodeWithAddr(start, end, hexstr):
    matchs = []
    addr = start
    if end == 0:
        end = idc.BADADDR
    if end != idc.BADADDR:
        end = end + 1
    
    while True:
        addr = ida_bytes.bin_search(addr, end, bytes.fromhex(hexstr), None, idaapi.BIN_SEARCH_FORWARD, idaapi.BIN_SEARCH_NOCASE)
        if addr == idc.BADADDR:
            break
        else:
            matchs.append(addr)
            addr = addr + 1
    return matchs


# 查找指定代码
def searchCode(segNames, hexstr):
    matches = []
    if segNames is None or len(segNames) == 0:
        matches.extend(searchCodeWithAddr(0, 0, hexstr))
    else:
        for segName in segNames:
            start, size = getSegmentAddrRange(segName)
            if size > 0:
                matches.extend(searchCodeWithAddr(start, start + size, hexstr))
    return matches


########################################### 其他 ###########################################


#将bytes对象转换为16进制字符串
def hexStrFromBytes(byteArr):
    return binascii.hexlify(byteArr).decode()


'''
patch操作
start_addr: 起始地址；
hex_string: 需要patch的16进制字符串，支持空格隔开；例如："000000000000000" 或者 "11 22 33 44 55 66 77 88"
'''
def patchBytes(start_addr, hexstr):
    byteArr = bytes.fromhex(hexstr)
    idaapi.patch_bytes(start_addr, byteArr)


#重建指令
def makeInsn(addr):
    if idc.create_insn(addr) == 0:
        idc.del_items(addr, idc.DELIT_EXPAND)
        idc.create_insn(addr)
    idc.auto_wait()


'''
删除指定段的分析，然后重新分析；
segNameArr: 需要重新分析的段名数组；例如：[".text", ".data"]
'''
def reAnalyze(startAddress, endAddress):
    ida_bytes.del_items(startAddress, 0, endAddress)
    ida_auto.plan_and_wait(startAddress, endAddress)

def reAnalyze(segNameArr):
    for i in idautils.Segments():
        seg = idaapi.getseg(i)
        segName = idaapi.get_segm_name(seg)

        #判断段名是否在segNameArr中，是的话先删除该段的分析，然后重新分析；
        if segName in segNameArr:
            startAddress = seg.start_ea
            endAddress = seg.end_ea
            reAnalyze(startAddress, endAddress)

