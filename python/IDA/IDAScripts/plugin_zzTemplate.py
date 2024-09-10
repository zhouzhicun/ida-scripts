

'''
插件模板：
用途：通过简单的封装，实现插件的基本逻辑.

如何使用：
1.复制下面所有代码到新的插件脚本文件中；
2.搜索 'ZZPluginTemplate' 并 全局替换为自己的插件名；
3.修改插件配置；
4.实现插件逻辑。

'''



import idaapi
from ida_idaapi import plugin_t
import zzPluginBase.pluginUtils as pluginUtils


###################################  插件逻辑  #############################################


def func1():
    print("hello func1")

def func2():
    print("hello func2")

def func3():
    print("hello func3")



#################################### 插件配置 ##################################################


ZZPluginTemplate_wanted_name = 'ZZPluginTemplate'
ZZPluginTemplate_comment = ''
ZZPluginTemplate_help = ''
ZZPluginTemplate_wanted_hotkey = ''
ZZPluginTemplate_flags = idaapi.PLUGIN_KEEP

ZZPluginTemplateMenuConfig = pluginUtils.PluginMenuConfig("ZZPluginTemplate/", [
    pluginUtils.PluginSubMenu('my:func1', 'func1', func1),
    pluginUtils.PluginSubMenu('my:func2', 'func2', func2),
    pluginUtils.PluginSubMenu('my:func3', 'func3', func3)
])


#################################### 插件框架 ##################################################

class ZZPluginTemplateUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        pluginUtils.registerUIHook(widget, popup_handle, ZZPluginTemplateMenuConfig)


class ZZPluginTemplate(plugin_t):

    wanted_name = ZZPluginTemplate_wanted_name
    comment = ZZPluginTemplate_comment
    help = ZZPluginTemplate_help
    wanted_hotkey = ZZPluginTemplate_wanted_hotkey
    flags = ZZPluginTemplate_flags


    def init(self):

        pluginUtils.registerAction(ZZPluginTemplateMenuConfig)

        global my_ui_hooks
        my_ui_hooks = ZZPluginTemplateUIHooks()
        my_ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        pass

    def term(self):
        pass 


# 注册插件
def PLUGIN_ENTRY():
    return ZZPluginTemplate()

