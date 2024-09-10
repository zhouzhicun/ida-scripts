
import zzPluginBase.utils as utils
import zzPluginBase.funcUtils as funcUtils


#修改下面参数，然后运行脚本即可
hex_string = "0000000000000000000000000000000000000000000000000000000000000000"
start_addr = 0x3D6F0
segNameArr = [".text"]

utils.patch_bytes(start_addr, hex_string)
utils.reAnalyze(segNameArr)



