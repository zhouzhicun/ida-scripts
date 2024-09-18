## 简介

仓库分为三个文件夹：encrypt,  IDA, obfuscation。

### obfuscation

该文件夹实现了 OLLVM混淆的反混淆处理，包括字符串加密混淆，BR/BLR混淆。字符串加密反混淆的脚本来源于白龙的知识星球。

so分析处理步骤：

1. 判断是否有壳，有则先去壳；判断是否有加密，有则dump解密后的so。 
2. 是否有花指令，有则先去花；
3. 判断是否有 BR/BLR混淆，有则先去BR/BLR混淆；
4. 如果有平坦化混淆，则使用d810去混淆，或者自实现脚本辅助去混淆。

反混淆脚本思路详解：

https://lpr8dxxmqn.feishu.cn/docx/K1QWdV0ydocOIPx1HgHcB3ednMf?from=from_copylink



### IDA

该文件夹下封装了 一些简单的 IDA脚本和插件，提高工作效率。



### encrypt

该文件夹下面是一些常用加密算法的python/java实现， 主要分析并还原魔改的加密算法。

对于魔改的加密算法：

首先复制一份算法源码，然后进行对比分析（即源码和魔改算法的对比分析），找出魔改点，并修改源码，最终得到魔改算法的完整实现。



