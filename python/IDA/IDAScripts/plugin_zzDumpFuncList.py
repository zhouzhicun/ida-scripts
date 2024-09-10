
import idaapi
from idaapi import plugin_t

import zzPluginBase.utils as utils
import zzPluginBase.funcUtils as funcUtils
import zzPluginBase.pluginUtils as pluginUtils


############################# 插件逻辑 ######################################

def get_all_instructions():
    allInsn = funcUtils.get_all_instructions()
    utils.writeFile("allInstructions.txt", allInsn)

#获取所有函数伪代码
def get_all_func_code():
    allFuncCode = funcUtils.get_all_func_code()
    utils.writeFile("functionCode.txt", allFuncCode)


#获取函数列表
def get_func_list():
    funcList = funcUtils.get_func_list()
    utils.writeFile("functionList.txt", funcList)


#获取函数列表，按照xref数量排序
def get_func_list_orderby_xref():
    funcList = funcUtils.get_func_list_orderby_xref()
    utils.writeFile("functionList_xref.txt", funcList)


#获取函数列表，按照指令数量排序
def get_func_list_orderby_insn_count():
    funcList = funcUtils.get_func_list_orderby_insn_count()
    utils.writeFile("functionList_insnCount.txt", funcList)

#获取函数列表，按照加解密特征指令数量排序(LSL, AND, ORR, LSR, ROR)
def get_func_list_orderby_eor():
    funcList = funcUtils.get_func_list_orderby_eor()
    utils.writeFile("functionList_eor.txt", funcList)


#获取导出函数列表
def get_export_func_list():
    funcList = funcUtils.get_export_func_list()
    utils.writeFile("functionList_export.txt", funcList)

#获取导入函数列表
def get_import_func_list():
    funcList = funcUtils.get_import_func_list()
    utils.writeFile("functionList_import.txt", funcList)





#################################### 插件配置 ##################################################

ZZDumpFunc_wanted_name = 'ZZDumpFunc'
ZZDumpFunc_comment = ''
ZZDumpFunc_help = ''
ZZDumpFunc_wanted_hotkey = ''
ZZDumpFunc_flags = idaapi.PLUGIN_KEEP

ZZDumpFuncMenuConfig = pluginUtils.PluginMenuConfig("ZZDumpFunc/", [
    pluginUtils.PluginSubMenu('my:dump_all_instructions', 'dump函数所有汇编', get_all_instructions),
    pluginUtils.PluginSubMenu('my:dump_func_code', 'dump函数伪代码', get_all_func_code),
    pluginUtils.PluginSubMenu('my:dump_func_list', 'dump函数列表', get_func_list),
    pluginUtils.PluginSubMenu('my:dump_func_orderby_xref', 'dump函数列表，按xref引用排序', get_func_list_orderby_xref),
    pluginUtils.PluginSubMenu('my:dump_func_orderby_insnCount', 'dump函数列表，按指令数排序', get_func_list_orderby_insn_count),
    pluginUtils.PluginSubMenu('my:dump_func_orderby_eor', 'dump函数列表，按逻辑指令数排序', get_func_list_orderby_eor),
    pluginUtils.PluginSubMenu('my:dump_func_exports', 'dump导出符号表', get_export_func_list),
    pluginUtils.PluginSubMenu('my:dump_func_imports', 'dump导入符号表', get_import_func_list),
])




#################################### 插件框架 ##################################################

class ZZDumpFuncUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        pluginUtils.registerUIHook(widget, popup_handle, ZZDumpFuncMenuConfig)


class ZZDumpFunc(plugin_t):

    wanted_name = ZZDumpFunc_wanted_name
    comment = ZZDumpFunc_comment
    help = ZZDumpFunc_help
    wanted_hotkey = ZZDumpFunc_wanted_hotkey
    flags = ZZDumpFunc_flags


    def init(self):

        pluginUtils.registerAction(ZZDumpFuncMenuConfig)

        global my_ui_hooks
        my_ui_hooks = ZZDumpFuncUIHooks()
        my_ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        pass

    def term(self):
        pass 


# 注册插件
def PLUGIN_ENTRY():
    return ZZDumpFunc()

