from Crypto.Cipher import AES


def aes_cfb_encrypt(plaintext: str, iv_hex: str, key_hex: str) -> str:
    """
    AES/CFB/NoPadding加密，返回加密结果的十六进制字符串

    :param plaintext: 待加密的明文
    :param iv_hex: 十六进制格式的初始化向量(IV)
    :param key_hex: 十六进制格式的密钥(Key)
    :return: 加密结果的十六进制字符串
    """
    # 将十六进制的IV和Key转换为字节
    iv_bytes = bytes.fromhex(iv_hex)
    key_bytes = bytes.fromhex(key_hex)

    # 创建AES-CFB加密器（segment_size=128表示完整块反馈）
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv_bytes, segment_size=128)

    # 执行加密（CFB模式不需要填充）
    ciphertext_bytes = cipher.encrypt(plaintext.encode('utf-8'))

    # 将加密结果转换为十六进制字符串
    return ciphertext_bytes.hex()


# 用户提供的参数
iv_hex = "65383932323563666262696d676b6375"
key_hex = "6363383864646339333537666634363165303866303437616564656536393262"
plaintext = '{"oauth_type":"pwa","oauth_id":"qvUO7Vu7MUZScMqI1750164542439","version":"7.1.0","mod":"index","code":"search_v1","page":1,"limit":24,"type":7,"key":"叼嘿咯","timestamp":1750432881455}'  # 替换为需要加密的内容

# 执行加密
encrypted_hex = aes_cfb_encrypt(plaintext, iv_hex, key_hex)
print("加密结果(Hex):", encrypted_hex)