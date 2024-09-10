
import phoenixAES

'''
白盒AES算法逆推秘钥
参考文档：
浅谈加密算法 aes: http://91fans.com.cn/post/ilikeaes/#gsc.tab=0
找回消失的密钥 --- DFA分析白盒AES算法: http://91fans.com.cn/post/ilikeaestwo/#gsc.tab=0
AES加密：https://www.yuque.com/nanren-w8l2z/xgu63m/uoff9ovsmhqki9wh?singleDoc#
轮秘钥逆推主秘钥(支持DES AES SM4)：https://github.com/SideChannelMarvels/Stark


DFA原理（构造缺陷数据）：
DFA攻击简单来说就是在倒数第一轮列混合和倒数第二轮列混合之间，修改此时中间结果的一个字节，会导致最终密文和正确密文有4个字节的不同。
通过多次的修改，得到多组错误的密文，然后通过正确密文和这些错误密文能够推算出第10轮的密钥（加密模式下），继而能推算出原始密钥。
'''

def crack(cipherText):
    tacefile = 'tracefile'
    with open(tacefile, 'wb') as t:
        t.write(cipherText.encode('utf8'))
    phoenixAES.crack_file(tacefile, [], True, False, 3)


############################ 1.构造故障密文，逆推最后一轮秘钥  #################################


#第1行传正确密文，后面16行传入故障密文
cipherText = """
2a2e0209344d716a699f8cb7591a9ea2
d92e0209344d714a699fc6b759f49ea2
5e2e0209344d710e699f52b7594e9ea2
762e0209344d7157699fe0b759a59ea2
a42e0209344d710e699f16b759c09ea2
2a3a0209d84d716a699f8c20591a55a2
2ab80209114d716a699f8c60591a5da2
2a290209434d716a699f8c5f591a61a2
2a760209fd4d716a699f8c7e591aa4a2
2a2ea009342b716ac09f8cb7591a9e0a
2a2e86093401716a929f8cb7591a9ea1
2a2ed1093474716aab9f8cb7591a9ea9
2a2ee609340f716a8e9f8cb7591a9ea7
2a2e0290344de86a69bf8cb7a21a9ea2
2a2e0283344de06a69fd8cb7241a9ea2
2a2e029d344db06a694a8cb78d1a9ea2
2a2e024d344d916a69638cb7ba1a9ea2
"""

crack(cipherText)

''' 正常返回：
Round key bytes recovered:
13111D7FE3944A17F307A78B4D2B30C5
Last round key #N found:
13111D7FE3944A17F307A78B4D2B30C5
'''


############################ 2.逆推主秘钥  #################################

'''

1.编译stark：https://github.com/SideChannelMarvels/Stark
需要安装minGW, 参考文档：https://segmentfault.com/a/1190000042348071
安装好之后，进入stark目录，执行如下命令即可：
mingw32-make

2.运行aes_keyschedule.txt 逆推主秘钥，格式： ./stark 轮秘钥 轮次; 例如：
.\aes_keyschedule.exe D014F9A8C9EE2589E13F0CC8B6630CA6 10

'''

