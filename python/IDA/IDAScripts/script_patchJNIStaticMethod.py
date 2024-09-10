

import idc
import idautils
import zzPluginBase.jniSignature as jniSignature

###################################### patch静态注册的JNI方法-脚本逻辑 ################################################


def load_methods(clsName, methods):
    methodArr = methods.split("\n")
    resultArr = []

    #1.解析方法
    for method in methodArr:
        method.strip()
        if len(method) == 0:
            continue

        index = method.index('(')
        if index == -1:
            continue

        name = method[0:index]
        sig = method[index:]
        resultArr.append((name, sig))

    #2.解析方法签名
    methodDic = {}
    for method in resultArr:
        name, sig = method
        jniMethodName, ret, args = jniSignature.parse_method_signature(clsName, name, sig)
        methodDic[jniMethodName] = (jniMethodName, ret, args)
        print("jniMethodName = {}, ret = {}, args = {}".format(jniMethodName, ret, args))

    return methodDic


def apply_signature(ea, sig):
    jniMethodName, ret, args = sig
    print('apply 0x%x %s', ea, jniMethodName)
    decl = '{} {}({})'.format(ret, jniMethodName, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    idc.set_name(ea, jniMethodName)
    idc.apply_type(ea, prototype_details)



def patch(clsName, methods):
    #1.加载方法
    methods = load_methods(clsName, methods)

    print("---------------------------------")  
    print(methods)
    print("---------------------------------")  

    #2.遍历函数，应用签名
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)
    failed = []

    for ea in idautils.Functions():
        fname = idc.get_func_name(ea)
        if fname.startswith('Java_'):
            sig = methods.get(fname)
            if sig is None:
                failed.append(fname)
            else:
                apply_signature(ea, sig)

    print('JNI functions patch failed ==> \n {}'.format(failed))
    idc.set_ida_state(st)




###################################### 业务实现 ################################################


#只需要修改这两个参数即可，一个是类名，一个是方法列表。
className = "com.moji.tool.AlibabaMarkJNIUtils"
methods = '''
getBoot()Ljava/lang/String;
getUpdate()Ljava/lang/String;
'''

patch(className, methods)