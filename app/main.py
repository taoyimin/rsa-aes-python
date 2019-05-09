#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:Tao Yimin
# Time  :2019/5/7 19:29
from Crypto.Random import get_random_bytes

from app.AESCipher import AESCipher
from app.RSACipher import RSACipher
from app.config import Config

# 客户端代码
text = 'hello server!'

# 随机生成aes的密钥
aes_key = get_random_bytes(16)
print('随机生成的aes密钥:\n%s' % aes_key)

aes_cipher = AESCipher(aes_key)
rsa_cipher = RSACipher()

# 使用aes密钥对数据进行加密
encrypt_text = aes_cipher.encrypt(text)
print('经过aes加密后的数据:\n%s' % encrypt_text)

# 使用客户端私钥对aes密钥签名
signature = rsa_cipher.sign(Config.CLIENT_PRIVATE_KEY, aes_key)
print('签名:\n%s' % signature)

# 使用服务端公钥加密aes密钥
encrypt_key = rsa_cipher.encrypt(Config.SERVER_PUBLIC_KEY, aes_key)
print('加密后的aes密钥:\n%s' % encrypt_key)

# 客户端发送密文、签名和加密后的aes密钥
print('\n************************分割线************************\n')
# 接收到客户端发送过来的signature encrypt_key encrypt_text

# 服务端代码
# 使用服务端私钥对加密后的aes密钥解密
aes_key = rsa_cipher.decrypt(Config.SERVER_PRIVATE_KEY, encrypt_key)
print('解密后的aes密钥:\n%s' % aes_key)

# 使用客户端公钥验签
result = rsa_cipher.verify(Config.CLIENT_PUBLIC_KEY, aes_key, signature)
print('验签结果:\n%s' % result)

# 使用aes私钥解密密文
aes_cipher = AESCipher(aes_key)
decrypt_text = aes_cipher.decrypt(encrypt_text)
print('经过aes解密后的数据:\n%s' % decrypt_text)