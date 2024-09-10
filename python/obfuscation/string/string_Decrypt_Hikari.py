

'''
针对 Hikari(光) OLLVM 字符串加密
脚本来源：白龙-字符串加密第二篇：https://www.yuque.com/lilac-2hqvv/hgwa9g/rhx7nb?#a92VD

Hikari 字符串加密特征：
1.字符串使用的时候，才进行解密；类似如下伪代码：
byte_6225C ^= 0x5Eu;
byte_6225D ^= 0x69u;
byte_6225E ^= 0x5Fu;
byte_6225F ^= 0xA9u;
byte_62260 ^= 0x21u;
byte_62261 ^= 0xA3u;
byte_62262 ^= 0x8Cu;
byte_62263 ^= 0x8Bu;
byte_62264 ^= 0xE4u;


脚本解密思路：
1.预处理：找到 data 段，将其中所有数据先 del_items转成 undefined，再 create_data转成 byte_xxx。
2.解密函数：首先反编译函数得到伪代码，然后匹配如下两种模式并patch：
模式1：byte_xxx ^= AAAu; 
模式2：byte_xxx = ~byte_xxx
3.找到所有函数，逐个解密。

'''


import re
import ida_idaapi
import idaapi
import idc
import ida_auto
import ida_bytes
import idautils


#解密前预处理
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



def decryptOne(addr):
    decompilerStr = str(idaapi.decompile(addr))
    mode1(decompilerStr)
    mode2(decompilerStr)

    #匹配并patch模式1：byte_xxx ^= AAAu 
    def mode1(codes):
        matches = re.findall(r"byte_([0-9a-fA-F]+) \^= (.*)u", codes)
        if len(matches) > 0:
            for match in matches:
                address = int(match[0], 16)
                xorValue = int(match[1], 16)
                decrypt_c = xorValue ^ idaapi.get_byte(address)
                ida_bytes.patch_byte(address, decrypt_c)

    #匹配并patch模式2：byte_xxx = ~byte_xxx
    def mode2(codes):
        matches = re.findall(r"byte_([0-9a-fA-F]+) = ~byte_\1", codes)
        if len(matches) > 0:
            for match in matches:
                address = int(match, 16)
                xorValue = 0xFF
                decrypt_c = xorValue ^ idaapi.get_byte(address)
                ida_bytes.patch_byte(address, decrypt_c)


def decryptAll():
    for func in idautils.Functions(0, ida_idaapi.BADADDR):
        try:
            decryptOne(func)
        except:
            pass


decryptAll()