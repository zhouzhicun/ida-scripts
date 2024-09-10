


import idc
import idautils
import zzPluginBase.jniSignature as jniSignature




###################################### patch动态注册的JNI方法 脚本逻辑 ################################################

''' 注意：
JNI方法不区分类方法还是实例方法，即为了脚本方法，JNI方法的第二个参数统一使用 jobject obj.

'''



def load_patch_methods(lines):
    
    methodLines = methods.split("\n")

    for line in methodLines:
        line.strip()
        arr = line.split(" ")
        if len(arr) < 13:
            continue

        clsName = arr[2]
        funcName = arr[4]
        sig = arr[6]
        offset_info = arr[12].split("!")
        addr = int(offset_info[1], 16)

        jni_method_name, ret, args = jniSignature.parse_method_signature(clsName, funcName, sig)
        print("jni_method_name = {}, ret = {}, args = {}".format(jni_method_name, ret, args))
        apply_signature(addr,  jni_method_name, ret, args)


def apply_signature(ea, funcname, ret, args):
    print('apply 0x%x %s', ea, funcname)
    decl = '{} {}({})'.format(ret, funcname, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    idc.set_name(ea, funcname)
    idc.apply_type(ea, prototype_details)





###################################### 业务实现 ################################################


#只需要修改这个参数即可
methods = '''
[RegisterNatives] java_class: com.moji.mjweather.library.Digest name: nativeEncodeParams sig: (Ljava/lang/String;)Ljava/lang/String; fnPtr: 0x762ccdf1a0  fnOffset: 0x762ccdf1a0 libencrypt.so!0x3d1a0  callee: 0x762ccbc4b4 libencrypt.so!JNI_OnLoad+0x11c
[RegisterNatives] java_class: com.moji.mjweather.library.Digest name: nativeEncrypt sig: ([B)[B fnPtr: 0x762ccdf3b0  fnOffset: 0x762ccdf3b0 libencrypt.so!0x3d3b0  callee: 0x762ccbc4b4 libencrypt.so!JNI_OnLoad+0x11c
[RegisterNatives] java_class: com.moji.mjweather.library.Digest name: nativeDecrypt sig: ([B)[B fnPtr: 0x762ccdf4e8  fnOffset: 0x762ccdf4e8 libencrypt.so!0x3d4e8  callee: 0x762ccbc4b4 libencrypt.so!JNI_OnLoad+0x11c
[RegisterNatives] java_class: com.moji.mjweather.library.Digest name: nativeGenSKey sig: ()[B fnPtr: 0x762ccdf620  fnOffset: 0x762ccdf620 libencrypt.so!0x3d620  callee: 0x762ccbc4b4 libencrypt.so!JNI_OnLoad+0x11c
[RegisterNatives] java_class: com.moji.mjweather.library.Digest name: nativeGenPKey sig: ([B)[B fnPtr: 0x762ccdf6f0  fnOffset: 0x762ccdf6f0 libencrypt.so!0x3d6f0  callee: 0x762ccbc4b4 libencrypt.so!JNI_OnLoad+0x11c
'''


load_patch_methods(methods)