#Usage
###Client
```python
# 明文
text = 'hello client!'

# 随机生成aes的密钥
aes_key = get_random_bytes(16)

aes_cipher = AESCipher(aes_key)
rsa_cipher = RSACipher()

# 使用aes密钥对数据进行加密
encrypt_text = aes_cipher.encrypt(text)

# 使用客户端私钥对aes密钥签名
signature = rsa_cipher.sign(Config.CLIENT_PRIVATE_KEY, aes_key)

# 使用服务端公钥加密aes密钥
encrypt_key = rsa_cipher.encrypt(Config.SERVER_PUBLIC_KEY, aes_key)
```

###Server
```python
# 服务端代码
# 模拟接收到客户端的加密aes密钥、签名、加密的密文
encrypt_key = 'u+j5z9A7YrUFFf5UJ4PhynyKVx8/irC1/oFl7xpq0PzQtWxi0RzlrT/OY2L1nqlCOAAFj8Q6JDvrxV66nl/oEhrwvcETr3kcehqZmYJs6xr7ROf6b80UfibifoL7TOs2GhQOdMm0vlRb8vgBEKqc9uX4NN73M4FCH6zzf86mNAI='
signature = '3mHEuVWjAPytInJsC41dprKTAMAJ5mbct4Tv1nzltfC4mxGxOH1B55a9qjkZ0hkUyBw/aukmUNcikSNB27g7kZ+WG3DQMr799fVmX9YA6G8xj3yjM8zvIo13agBtkiZ9Da1tmYC0yynU9CY/6VUYpUYnrs2Ci9Ttir0fDNkhSF8='
encrypt_text = 'JYhBn/AGsfRhuf/x2tvtkw=='

# 使用服务端私钥对加密后的aes密钥解密
aes_key = rsa_cipher.decrypt(Config.SERVER_PRIVATE_KEY, encrypt_key)

# 使用客户端公钥验签
result = rsa_cipher.verify(Config.CLIENT_PUBLIC_KEY, aes_key, signature)

# 使用aes私钥解密密文
aes_cipher = AESCipher(aes_key)
decrypt_text = aes_cipher.decrypt(encrypt_text)
```