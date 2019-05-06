#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:Tao Yimin
# Time  :2019/5/6 17:58
import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from app.config import Config


class RSACipher():

    def encrypt(self, key, text):
        public_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return base64.b64encode(cipher.encrypt(text.encode())).decode()

    def decrypt(self, key, text):
        private_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(text)).decode()

if __name__ == '__main__':
    text = 'hello'
    cipher = RSACipher()
    encrypt_text = cipher.encrypt(Config.CLIENT_PUBLIC_KEY, text)
    print('加密后:%s' % encrypt_text)
    decrypt_text = cipher.decrypt(Config.CLIENT_PRIVATE_KEY, encrypt_text)
    print('解密后:%s' % decrypt_text)