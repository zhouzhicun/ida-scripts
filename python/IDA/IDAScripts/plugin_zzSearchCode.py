


import idaapi
from ida_idaapi import plugin_t

import zzPluginBase.utils as utils
import zzPluginBase.funcUtils as funcUtils
import zzPluginBase.pluginUtils as pluginUtils



################################ 插件逻辑 ##########################################

svc0_code = "010000D4"       #svc 0
svc80_code = "011000D4"      #svc 0x80

def searchAllSVC():
    segNames = None
    svc0Arr = utils.searchCode(segNames, svc0_code)
    svc80Arr = utils.searchCode(segNames, svc80_code)
    printResult("found SVC0 at all: \n", svc0Arr)
    printResult("found SVC80 at all: \n", svc80Arr)

    segNames = ['.text']
    svc0Arr = utils.searchCode(segNames, svc0_code)
    svc80Arr = utils.searchCode(segNames, svc80_code)
    printResult("found SVC0 at .text: \n", svc0Arr)
    printResult("found SVC80 at .text: \n", svc80Arr)


def searchBR():
    brCodeArr = funcUtils.get_all_instructions("BR")
    print("found BR at: \n" + formatCode(brCodeArr))

def searchBLR():
    brCodeArr = funcUtils.get_all_instructions("BLR")
    print("found BLR at: \n" + formatCode(brCodeArr))


def searchCSEL():
    cselCodeArr = funcUtils.get_all_instructions("CSEL")
    ssetCodeArr = funcUtils.get_all_instructions("CSET")
    print("found CSEL at: \n" + formatCode(cselCodeArr))
    print("found CSET at: \n" + formatCode(ssetCodeArr))


def searchBR_CSEL():
    br_csel_codeArr = funcUtils.get_all_BR_CSEL()

    desc = '-----------------------  dump br-csel -------------------------------\n'
    for code in br_csel_codeArr:
        br_addr = code[0]
        csel_addr = code[1]
        csel_asm = code[2]
        desc += f"0x{br_addr:08X} 0x{csel_addr:08X}: {csel_asm}" + '\n'
    print(desc)


def formatCode(codeArr):
    result = ""
    for code in codeArr:
        address = code[0]
        disasm = code[1]
        result += f"0x{address:08X}: {disasm}" + '\n'
    return result


def printResult(tip, matchAddrs):
    str = tip
    for addr in matchAddrs:
        str += hex(addr) + ","
    print(str)  



#################################### 插件配置 ##################################################


ZZSearchCode_wanted_name = 'ZZSearchCode'
ZZSearchCode_comment = ''
ZZSearchCode_help = ''
ZZSearchCode_wanted_hotkey = ''
ZZSearchCode_flags = idaapi.PLUGIN_KEEP

ZZSearchCodeMenuConfig = pluginUtils.PluginMenuConfig("ZZSearchCode/", [
    pluginUtils.PluginSubMenu('my:search_svc', '搜索SVC指令', searchAllSVC),
    pluginUtils.PluginSubMenu('my:search_br', '搜索BR指令', searchBR),
    pluginUtils.PluginSubMenu('my:search_blr', '搜索BLR指令', searchBLR),
    pluginUtils.PluginSubMenu('my:search_csel', '搜索CSEL/CSET指令', searchCSEL),
    pluginUtils.PluginSubMenu('my:search_br_csel', '搜索 BR + CSEL/CSET指令', searchBR_CSEL)
])


#################################### 插件框架 ##################################################

class ZZSearchCodeUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        pluginUtils.registerUIHook(widget, popup_handle, ZZSearchCodeMenuConfig)


class ZZSearchCode(plugin_t):

    wanted_name = ZZSearchCode_wanted_name
    comment = ZZSearchCode_comment
    help = ZZSearchCode_help
    wanted_hotkey = ZZSearchCode_wanted_hotkey
    flags = ZZSearchCode_flags


    def init(self):

        pluginUtils.registerAction(ZZSearchCodeMenuConfig)

        global my_ui_hooks
        my_ui_hooks = ZZSearchCodeUIHooks()
        my_ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        pass

    def term(self):
        pass 


# 注册插件
def PLUGIN_ENTRY():
    return ZZSearchCode()















