
#################################### AES128分组加密  #######################################

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE,
    0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
    0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
    0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB,
    0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
    0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A,
    0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50,
    0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10,
    0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64,
    0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE,
    0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91,
    0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65,
    0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
    0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86,
    0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE,
    0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0,
    0x54, 0xBB, 0x16,
)
Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix

def shiftRound(array, num):
    '''
    :param array: 需要循环左移的数组
    :param num: 循环左移的位数
    :return: 使用Python切片，返回循环左移num个单位的array
    '''
    return array[num:] + array[:num]

def g(array, index):
    '''
    g 函数
    :param array: 待处理的四字节数组
    :index:从1-10，每次使用Rcon中不同的数
    '''
    # 首先循环左移1位
    array = shiftRound(array, 1)
    # 字节替换
    array = [Sbox[i] for i in array]
    # 首字节和rcon中对应元素异或
    array = [(Rcon[index] ^ array[0])] + array[1:]
    return array

def xorTwoArray(array1, array2):
    '''
    返回两个数组逐元素异或的新数组
    :param array1: 一个array
    :param array2: 另一个array
    :return:
    '''
    assert len(array1) == len(array2)
    return [array1[i] ^ array2[i] for i in range(len(array1))]

def showRoundKeys(kList):
    for i in range(len(kList)):
        print("K%02d:" % i + "".join("%02x" % k for k in kList[i]))

def keyExpand(key):
    master_key = text2matrix(key)
    round_keys = [[0] * 4 for i in range(44)]
    # 规则一(图中红色部分)
    for i in range(4):
        round_keys[i] = master_key[i]
    for i in range(4, 4 * 11):
        # 规则二(图中红色部分)
        if i % 4 == 0:
            round_keys[i] = xorTwoArray(g(round_keys[i - 1], i // 4), round_keys[i - 4])
        # 规则三(图中橙色部分)
        else:
            round_keys[i] = xorTwoArray(round_keys[i - 1], round_keys[i - 4])
    showRoundKeys(round_keys)
    return round_keys

def AddRoundKeys(state, roundKey):
    result = [[] for i in range(4)]
    for i in range(4):
        result[i] = xorTwoArray(state[i], roundKey[i])
    return result

def SubBytes(state):
    result = [[] for i in range(4)]
    for i in range(4):
        result[i] = [Sbox[i] for i in state[i]]
    return result

def ShiftRows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
    return s

def mul_by_02(num):
    if num < 0x80:
        res = (num << 1)
    else:
        res = (num << 1) ^ 0x1b
    return res % 0x100

def mul_by_03(num):
    return mul_by_02(num) ^ num

def MixColumns(state):
    for i in range(4):
        s0 = mul_by_02(state[i][0]) ^ mul_by_03(state[i][1]) ^ state[i][2] ^ state[i][3]
        s1 = state[i][0] ^ mul_by_02(state[i][1]) ^ mul_by_03(state[i][2]) ^ state[i][3]
        s2 = state[i][0] ^ state[i][1] ^ mul_by_02(state[i][2]) ^ mul_by_03(state[i][3])
        s3 = mul_by_03(state[i][0]) ^ state[i][1] ^ state[i][2] ^ mul_by_02(state[i][3])
        state[i][0] = s0
        state[i][1] = s1
        state[i][2] = s2
        state[i][3] = s3
    return state


def state2Text(state):
    text = sum(state, [])
    return "".join("%02x" % k for k in text)


def encrypt(input_bytes, kList):
    '''
    :param input_bytes: 输入的明文
    :param kList: K0-K10
    :return:
    '''
    plainState = text2matrix(input_bytes)
    # 初始轮密钥加 K0
    state = AddRoundKeys(plainState, kList[0:4])
    for i in range(1, 10):
        # 字节替换
        state = SubBytes(state)
        # 循环左移
        state = ShiftRows(state)

        #添加下面测试代码，依次修改state[0..3][0..3] = 0x11, 得到16组故障密文
        # if i == 9:
        #     state[0][0] = 0x11

        # 列混淆
        state = MixColumns(state)
        # 轮密钥加 K1-K9
        state = AddRoundKeys(state, kList[4 * i:4 * (i + 1)])
    # 字节替换
    state = SubBytes(state)
    # 循环左移
    state = ShiftRows(state)
    # 轮密钥加 K10
    state = AddRoundKeys(state, kList[40:44])
    return state


################################## AES 分组加密测试 ############################################


print("======================== 分组加密 ==========================")

input_bytes = 0x00112233445566778899aabbccddeeff
key = 0x2b7e151628aed2a6abf7158809cf4f3c
kList = keyExpand(key)
cipherState = encrypt(input_bytes, kList)
cipher = state2Text(cipherState)
print("cipher = ", cipher)