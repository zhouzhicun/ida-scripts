

import idaapi
from ida_idaapi import plugin_t

import zzPluginBase.emuRun as emuRun
import zzPluginBase.emuRunFlare as falreEmuRun
import zzPluginBase.pluginUtils as pluginUtils
import zzPluginBase.decryptString as decryptString


#####################################  插件逻辑  ##############################################

#字符串解密(hikari混淆)
def decryptStringHikari():
    decryptString.HikariHandler.decryptString()

#模拟执行指令
def emuRunCode():
    (valid, start, end, regName) = emuRun.check_code()
    if valid:
        falreEmuRun.emu_run_code(start, end, regName)

#模拟执行指令并Patch
def emuRunPatchCode():
    (valid, start, end, regName) = emuRun.check_code()
    if valid:
        result = falreEmuRun.emu_run_code(start, end, regName)
        emuRun.patch_code(start, end, result)


#################################### 插件配置 ##################################################


ZZDeObfuscate_wanted_name = 'ZZDeObfuscate'
ZZDeObfuscate_comment = ''
ZZDeObfuscate_help = ''
ZZDeObfuscate_wanted_hotkey = ''
ZZDeObfuscate_flags = idaapi.PLUGIN_KEEP

ZZDeObfuscateMenuConfig = pluginUtils.PluginMenuConfig("ZZDeObfuscate/", [
    pluginUtils.PluginSubMenu('my:decrypt_string_hikari', 'Hikari混淆字符串解密', decryptStringHikari),
    pluginUtils.PluginSubMenu('my:emu_run_code', '模拟执行选中指令', emuRunCode),
    pluginUtils.PluginSubMenu('my:emu_run_code_patch', '模拟运行选中指令并Patch', emuRunPatchCode),
])


#################################### 插件框架 ##################################################

class ZZDeObfuscateUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        pluginUtils.registerUIHook(widget, popup_handle, ZZDeObfuscateMenuConfig)


class ZZDeObfuscate(plugin_t):

    wanted_name = ZZDeObfuscate_wanted_name
    comment = ZZDeObfuscate_comment
    help = ZZDeObfuscate_help
    wanted_hotkey = ZZDeObfuscate_wanted_hotkey
    flags = ZZDeObfuscate_flags


    def init(self):

        pluginUtils.registerAction(ZZDeObfuscateMenuConfig)

        global my_ui_hooks
        my_ui_hooks = ZZDeObfuscateUIHooks()
        my_ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        pass

    def term(self):
        pass 


# 注册插件
def PLUGIN_ENTRY():
    return ZZDeObfuscate()

