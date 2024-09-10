


######################################## JNI签名转换 ################################################


JNITYPE_DESCRIPTOR = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
}


#解析Java方法签名，得到签名类型数组
#例如："JIF"  => ['J', 'I', 'F']
def parse_type(atype):

    args = []
    if len(atype) == 0:
        return args
    
    #1.判断是否'['开头
    if atype[0] == '[':
        #2.判断'['后面是否为'L'，如果是则找到';'(对象数组)，否则直接取两个字符（基本类型数组）
        if atype[1] == 'L':
            index = atype.find(';')
            args.append(atype[:index+1])
            atype = atype[index+1:]
            args = args + parse_type(atype)
        else:
            args.append(atype[0:2])
            atype = atype[2:]
            args = args + parse_type(atype)

    elif atype[0] == 'L':       #3.判断是否'L'开头, 如果是则找到';'(对象)，否则取一个字符（基本类型）
        index = atype.find(';')
        args.append(atype[:index+1])
        atype = atype[index+1:]
        args = args + parse_type(atype)
    else:                       #4.基本类型
        args.append(atype[0:1])
        atype = atype[1:]
        args = args + parse_type(atype)

    return args



#将Java签名类型转换为jni类型
#例如："Ljava/lang/String;" => "jstring"
def convert_type(atype):

    if len(atype) == 0:
        return ''
    
    res = JNITYPE_DESCRIPTOR.get(atype)
    if res:
        if res == 'void':
            return res
        else:
            return 'j' + res
        
    if atype[0] == 'L':
        if atype == 'Ljava/lang/String;':
            res = 'jstring'
        else:
            res = 'jobject'

    elif atype[0] == '[':
        if atype[1] == 'L':
            sub_type = atype[1:]
            if sub_type == 'Ljava/lang/String;':
                res = 'jstring'
            else:
                res = 'jobject'
            res = '%sArray' % res
        else:
            res = JNITYPE_DESCRIPTOR.get(atype[1])
            res = 'j%sArray' % res
        
    else:
        print('Unknown descriptor: "%s".', atype)
        res = 'void'

    return res


def parse_method_signature(clsName, methodName, sig):

    clsName = clsName.replace('.', '_')
    retultMethodName = f"Java_{clsName}_{methodName}"

    #1.解析返回值类型
    ret = sig.split(')')[1]
    print("ret = {}".format(ret))
    ret = convert_type(ret)
 
    #2.解析参数类型
    result_args = "JNIEnv *env, jobject obj"
    argstr = sig.split(')')[0][1:]
    print("argstr = {}".format(argstr))
    other_args = parse_type(argstr)

    if len(other_args) > 0:
        other_args_desc = ''
        other_args_len = len(other_args)
        for i in range(other_args_len):
            temp = convert_type(other_args[i])
            if i == other_args_len - 1: 
                other_args_desc += f'{temp} a{i}'
            else:
                other_args_desc += f'{temp} a{i}, '
        result_args = f'{result_args}, {other_args_desc}'


    return retultMethodName, ret, result_args






