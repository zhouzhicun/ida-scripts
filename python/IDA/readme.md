

## IDA常用API
参考文档：https://cloud.tencent.com/developer/article/2216945


## IDA插件和脚本简介

IDA插件：
将自实现的IDA插件文件(例如 zzCopyCode.py)和zzPluginBase文件夹 复制到 ida/plugins目录下即可。
如果插件没提供菜单，则从 Edit -> Plugins 打开; 如果有提供菜单，则可以直接右键打开。


IDA脚本：
执行方式有三种：
方式1(推荐)：IDA -> File -> Script File
选中脚本文件直接运行；修改脚本需要先在编辑器中修改好。支持脚本文件导入其他python文件。

方式2（推荐）：IDA -> File -> Script Command
选择导入脚本文件，然后点击Run运行；可支持脚本编辑，且支持脚本文件导入其他python文件。

方式3（不推荐）：复制脚本文件，粘贴到IDA底部的python输入栏.

## 本工程介绍
工程模块化：
由于脚本执行只能import当前目录下的子目录里的python文件，因此将脚本和插件放到同一目录下，
封装好的基础代码放在 zzPluginBase子目录下，方面插件和脚本复用。
脚本文件名以 script_开头， 插件文件名以 plugin_开头。


## python库安装：
keystone安装：pip install keystone-engine （注意：需安装keystone-engine库）
capstone安装：pip install capstone


Bip是目前最完善的 IDA 插件封装。
参考文档：https://www.yuque.com/lilac-2hqvv/zfho3g/gn0ahl?

Bip安装：
1.下载源码：https://github.com/synacktiv/bip/
2.然后cd到bip目录，执行python install.py 即可安装。
如果IDA安装时指定了自定义目录，那么安装Bip时也需要指定IDA的安装目录，比如：
python install.py --dest "python install.py --dest C:/dev/IDA_Pro_8.3"



## dump内存
dump内存:
dump 可以使用 frida, dd命令(ADB)、IDA动态调试、 GG修改器、 GDB/LLDB 等等。
如果不存在 Anti Frida，那么 Frida dump就是最方便的选择。

回填使用 IDA 脚本更不是唯一选择，只需要使得 dump 下来的内容覆盖原先 data 段的物理地址范围就行。
需要注意区分物理偏移和虚拟地址，IDA 解析和展示 SO 时，采用虚拟地址（address），而处理静态文件时，需要基于实际偏移 offset 。
以 data segment 的起始地址为例，其虚拟地址和实际物理偏移并不一定相同。
1.IDA 中 patch 遵照其虚拟地址即可，因为 IDA 会替我们处理，映射到合适的物理地址上，
2.而将 SO 作为二进制文件 patch 时，需要用实际物理地址。可以使用 readelf 查看详细的节信息。


字符串加密解密：
OLLVM 的变种 Armariris 和 hikari 都是在字符串使用的时候才解密。
并且字符串解密函数作为内联函数，更有利于代码保护；否则的话，通过hook解密函数，就可以定位到检测点。



## 去LLVM混淆
参考文档：
记一次基于unidbg模拟执行的去除ollvm混淆： https://bbs.kanxue.com/thread-277086.htm
ARM64 OLLVM反混淆：https://bbs.kanxue.com/thread-252321.htm
使用unicorn模拟执行去除混淆：https://bbs.kanxue.com/thread-280231.htm



