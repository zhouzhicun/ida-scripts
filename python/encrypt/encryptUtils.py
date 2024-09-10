############################## 加解密工具类方法  ##########################################

#字符串转data
def str_to_data(str):
    return str.encode('utf-8')

#data转字符串
def data_to_str(data):
    return data.decode('utf-8')

#data转hex
def data_to_hex(data):
    return data.encode('hex')


#字符串补位, 返回长度为16倍数的data
def pad_to_16_str(str):
    pad_len = 16 - (len(str) % 16)
    str += '\0' * pad_len
    return str.encode('utf-8')

#bytes补位, 返回长度为16倍数的data
def pad_to_16_data(data):
    pad_bytes = 16 - (len(data) % 16)
    return data + bytes([0] * pad_bytes)