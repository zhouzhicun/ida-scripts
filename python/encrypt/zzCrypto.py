

import binascii
import hashlib
import hmac
import base64

# pip uninstall crypto
# pip uninstall pycryptodome
# pip install pycryptodome
from Crypto.Cipher import AES, DES, DES3, ARC4, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import PBKDF2

import encryptUtils as eu



'''
参考文档：
【爬虫知识】爬虫常见加密解密算法
https://mp.weixin.qq.com/s?__biz=MzkyMzcxMDM0MQ==&mid=2247500487&idx=1&sn=a4c5f203fd42fdd8c7ff4d4e144f0d1b&source=41#wechat_redirect

CTF&爬虫：掌握这些特征，一秒识别密文加密方式
https://www.cnblogs.com/ikdl/p/15802507.html

'''



class ZZCrypto:


    ############################ DES3加解密（mode = DES3.MODE_OFB）  ############################

    @classmethod
    def des3_encrypt(cls, keyData, plainText, ivData):
        des_encrypt = DES3.new(eu.pad_to_16_data(keyData), mode=DES3.MODE_OFB, iv=ivData)
        resultBytes = des_encrypt.encrypt(eu.pad_to_16_str(plainText))
        return resultBytes
    
    @classmethod
    def des3_decrypt(cls, keyData, cipherBytes, ivData=None):
        des_decrypt = DES3.new(eu.pad_to_16_data(keyData), mode=DES3.MODE_OFB, iv=ivData)
        resultBytes = des_decrypt.decrypt(cipherBytes)
        return resultBytes
    

    

    ############################ RC4加解密  ############################

    @classmethod
    def rc4_encrypt(cls, key, text):
        enc = ARC4.new(key.encode('utf8'))
        res = enc.encrypt(text.encode('utf-8'))
        res = base64.b64encode(res)
        return res

    @classmethod
    def rc4_decrypt(cls, key, base64CipherData):
        data = base64.b64decode(base64CipherData)
        enc = ARC4.new(key.encode('utf8'))
        res = enc.decrypt(data)
        return res
    
 


    ############################ RSA加解密（rsa每次公钥加密返回不同结果）  ############################

    @classmethod
    def genRSAKey(self):
        rsaKey = RSA.generate(1024)
        publicKey = rsaKey.publickey().export_key()
        privateKey = rsaKey.export_key()
        return publicKey, privateKey

    #key：公钥(字符串或者bytes)，plainText：明文字符串
    #返回：base64的密文字符串
    @classmethod
    def rsa_encrypt(cls, publicKey, plainText):
        rsa_key = RSA.importKey(publicKey)
        cipher = PKCS1_v1_5.new(rsa_key)
        base64CipherText = base64.b64encode(cipher.encrypt(eu.str_to_data(plainText)))
        return eu.data_to_str(base64CipherText)

    #key：私钥(字符串或者bytes)，base64CipherText：base64的密文字符串   
    #返回：明文字符串
    @classmethod
    def rsa_decrypt(cls, privateKey, base64CipherText):
        rsa_key = RSA.importKey(privateKey)
        cipher = PKCS1_v1_5.new(rsa_key)
        plainText = cipher.decrypt(base64.b64decode(eu.str_to_data(base64CipherText)), None)
        return eu.data_to_str(plainText)
    





# ####################################################################################


def des3_test():
    print("===================== DES3 加解密 ===========================")
    text = 'I love Python!'
    keyData = b'12345678'
    iv = Random.new().read(DES3.block_size)
    resultBytes = ZZCrypto.des3_encrypt(keyData, text, iv)
    print("des3加密：", resultBytes)
    resultBytes = ZZCrypto.des3_decrypt(keyData, resultBytes, iv)
    print("des3解密:", resultBytes)


def rc4_test():
    print("===================== RC4 加解密 ===========================")
    secret_key = '12345678'   # 密钥
    text = 'I love Python!'   # 加密对象
    encrypted_str = ZZCrypto.rc4_encrypt(secret_key, text)
    print('加密字符串：', encrypted_str)
    decrypted_str = ZZCrypto.rc4_decrypt(secret_key, encrypted_str)
    print('解密字符串：', decrypted_str)


def rsa_test():
    print("===================== RSA 加解密 ===========================")
    publicKey, privateKey = ZZCrypto.genRSAKey()
    print("publicKey = ", publicKey)
    print("privateKey = ", privateKey)
    text = "hello, world"
    cipherText = ZZCrypto.rsa_encrypt(publicKey, text)
    print("cipherText = ", cipherText)
    plainText = ZZCrypto.rsa_decrypt(privateKey, cipherText)
    print("plainText = ", plainText)


def crypto_test():
    des3_test()
    rc4_test()
    rsa_test()

crypto_test()