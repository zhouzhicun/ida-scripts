import idc
import idaapi
import pyperclip

from ida_idaapi import plugin_t


############################################## 插件类型定义 ##########################################################

#plugin子菜单配置, 例如: menuName，menu注释，菜单对应的处理函数
class PluginSubMenu:
    def __init__(self, name, comment, handleFunc):
        self.name = name
        self.comment = comment
        self.handle = BaseHandle(handleFunc) 


#plugin菜单配置
class PluginMenuConfig:
    def __init__(self, mainMenu, subMenuArr):
        self.mainMenu = mainMenu
        self.subMenuArr = subMenuArr


#Basehandle定义
class BaseHandle(idaapi.action_handler_t):
    def __init__(self, handleFunc):
        idaapi.action_handler_t.__init__(self)
        self.handleFunc = handleFunc 

    def activate(self, ctx):
        self.handleFunc()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


############################################## 插件方法封装 ##########################################################

def registerUIHook(widget, popup_handle, pluginMenuConfig):
     if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            for subMenu in pluginMenuConfig.subMenuArr:
                idaapi.attach_action_to_popup(widget, popup_handle, subMenu.name, pluginMenuConfig.mainMenu)



def registerAction(pluginMenuConfig):

    for subMenu in pluginMenuConfig.subMenuArr:
        # 将动作绑定到菜单, 这个函数不支持 kwargs
        # name, label, handler, shortcut=None, tooltip=None, icon=-1, flags=0
        actionDesc = idaapi.action_desc_t(subMenu.name,  subMenu.comment, subMenu.handle, '', '')
        idaapi.register_action(actionDesc)



