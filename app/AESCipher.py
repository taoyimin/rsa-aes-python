#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:Tao Yimin
# Time  :2019/5/6 20:24
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import base64

class AESCipher:
    def __init__(self, key):
        self.bs = 16
        """AES 128的key长度为16字节"""
        self.key = hashlib.sha256(key.encode()).digest()[:16]


    def encrypt(self, message):
        message = self._pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')


    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')