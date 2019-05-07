#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:Tao Yimin
# Time  :2019/5/6 17:58
import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from app.config import Config


class RSACipher():
    """
    RSA加密、解密、签名、验签工具类
    """

    def encrypt(self, key, raw):
        """
        加密方法
        :param key: 公钥
        :param raw: 需要加密的明文 bytes
        :return: base64编码的密文 bytes
        """
        public_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, key, enc):
        """
        解密方法
        :param key: 私钥
        :param enc: base64编码的密文 bytes
        :return: 解密后的明文 bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(enc))

    def sign(self, key, text):
        """
        签名方法
        :param key: 私钥
        :param text: 需要签名的文本 bytes
        :return: base64编码的签名信息 bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(hash_value)
        return base64.b64encode(signature)

    def verify(self, key, text, signature):
        """
        验签方法
        :param key: 公钥
        :param text: 需要验签的文本 bytes
        :param signature: base64编码的签名信息 bytes
        :return: 验签结果 bool
        """
        public_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(hash_value, base64.b64decode(signature))

if __name__ == '__main__':
    # 客户端代码
    text = b'hello'
    cipher = RSACipher()
    # 使用服务端公钥加密
    encrypt_text = cipher.encrypt(Config.SERVER_PUBLIC_KEY, text)
    print('加密后:\n%s' % encrypt_text)
    # 使用客户端私钥签名
    signature = cipher.sign(Config.CLIENT_PRIVATE_KEY, encrypt_text)
    print('签名:\n%s' % signature)

    # 服务端代码
    # 使用客户端公钥验签
    result = cipher.verify(Config.CLIENT_PUBLIC_KEY, encrypt_text, signature)
    print('验签:\n%s' % result)
    # 使用服务端私钥解密
    decrypt_text = cipher.decrypt(Config.SERVER_PRIVATE_KEY, encrypt_text)
    print('解密后:\n%s' % decrypt_text)

