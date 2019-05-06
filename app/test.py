#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:Tao Yimin
# Time  :2019/5/6 19:45
import rsa

(pubkey, privkey) = rsa.newkeys(1024)
print('公钥:\n%s' % pubkey)
print('私钥:\n%s' % privkey)
message = 'hello'
encrypt_text = rsa.encrypt(message.encode(), pubkey)
print('加密后的密文:\n%s' % encrypt_text)
decrypt_text = rsa.decrypt(encrypt_text, privkey)
print('解密后的明文:\n%s' % decrypt_text)
