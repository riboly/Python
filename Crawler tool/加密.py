from Crypto.Cipher import AES
import time
import hashlib
import requests
import http.client
import json
import binascii
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
search_text = '身材'#搜索关键词
iv_hex = "65383932323563666262696d676b6375"
key_hex = "6363383864646339333537666634363165303866303437616564656536393262"
timestamp_str = str(int(time.time()))
print("time:", timestamp_str)
plaintext = '{"oauth_type":"pwa","oauth_id":"lHXxcIXyHRHxRxyj1748116963193","version":"7.1.0","mod":"index","code":"search_v1","page":1,"limit":24,"type":7,"key":"'+search_text+'","timestamp":'+timestamp_str+'}'  # 替换为需要加密的内容
print("plaintext:", plaintext)
# 执行加密
encrypted_hex = aes_cfb_encrypt(plaintext, iv_hex, key_hex)
print("data加密结果(Hex):", encrypted_hex)

# 生成sign
def generate_sign(params, salt):
    # 1. 筛选非空参数并排序
    param_list = []
    if params.get('client'):
        param_list.append(f"client={params['client']}")
    if params.get('data'):
        param_list.append(f"data={params['data']}")
    if params.get('timestamp'):
        param_list.append(f"timestamp={params['timestamp']}")
    param_list.sort()  # ASCII升序排序

    # 2. 拼接参数 + 盐值
    raw_string = "&".join(param_list) + salt
    print("拼接后字符串:", raw_string)  # 调试输出

    return raw_string
# 测试参数
input_params = {
    "client": "pwa",
    "data": encrypted_hex,
    "timestamp": timestamp_str
}
salt = "cc88ddc9357ff461e08f047aedee692b"  # 从_0x105a17取得
# 执行签名
sign_raw = generate_sign(input_params, salt)
sign_sha256 = hashlib.sha256(sign_raw.encode('utf-8')).hexdigest()
print("sign_SHA256:", sign_sha256)
sign_md5 = hashlib.md5(sign_sha256.encode('utf-8')).hexdigest()
print("sign_md5:", sign_md5)

# 网络访问
post_bodydata = 'client=pwa&timestamp='+timestamp_str+'&data='+encrypted_hex+'&sign='+sign_md5
print("post body:", post_bodydata)


# 目标主机和路径
host = "jvtijg.qrmwqlm.xyz"
path = "/pwa.php"

# 构造原始 HTTP 请求
request_headers = """\
Host: jvtijg.qrmwqlm.xyz
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0
Accept: application/json, text/plain, */*
sec-ch-ua: "Microsoft Edge";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Origin: https://pwa3.lxmebhpm.xyz
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Language: zh-CN,zh;q=0.9
"""

# POST 数据（原始表单格式）
post_data = post_bodydata

# 计算 Content-Length
content_length = len(post_data.encode('utf-8'))

# 添加 Content-Length 头
request_headers += f"Content-Length: {content_length}\r\n"

# 建立 HTTPS 连接
conn = http.client.HTTPSConnection(host)

# 发送请求
conn.request(
    method="POST",
    url=path,
    body=post_data,
    headers=dict(line.split(": ", 1) for line in request_headers.strip().split("\n"))
)

# 获取响应
print("")
print("\033[32m>>>>网络请求发起...  \033[0m")
response = conn.getresponse()
body_ADS_data = response.read().decode('utf-8')
print(f"Status: {response.status} {response.reason}")
print("Response Body:")
print(body_ADS_data)
json_data = json.loads(body_ADS_data)
data_value = json_data["data"]
print(data_value)
# 关闭连接
conn.close()

#解密网络数据包
def aes_cfb_encrypt(plaintext: str, key_hex: str, iv_hex: str) -> str:
    """
    AES/CFB/NoPadding加密函数
    :param plaintext: 明文字符串
    :param key_hex: 十六进制格式的密钥
    :param iv_hex: 十六进制格式的初始向量
    :return: 十六进制格式的密文
    """
    # 将十六进制密钥和IV转换为字节
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)

    # 创建AES/CFB加密器（segment_size=128表示使用整个块）
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)

    # 加密数据（不需要填充）
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))

    # 返回十六进制格式的密文
    return ciphertext.hex()


def aes_cfb_decrypt(ciphertext_hex: str, key_hex: str, iv_hex: str) -> str:
    """
    AES/CFB/NoPadding解密函数
    :param ciphertext_hex: 十六进制格式的密文
    :param key_hex: 十六进制格式的密钥
    :param iv_hex: 十六进制格式的初始向量
    :return: 解密后的原始字符串
    """
    # 将十六进制密钥、IV和密文转换为字节
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # 创建AES/CFB解密器
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)

    # 解密数据
    plaintext = cipher.decrypt(ciphertext)

    # 返回原始字符串
    return plaintext.decode('utf-8')


# 示例使用
if __name__ == "__main__":
    # 您提供的密钥和IV（十六进制格式）
    IV_HEX = "65383932323563666262696d676b6375"
    KEY_HEX = "6363383864646339333537666634363165303866303437616564656536393262"


    # 加密测试
    #original_text = "Python AES/CFB/NoPadding 测试数据!"# 加密文本
    #encrypted_hex = aes_cfb_encrypt(original_text, KEY_HEX, IV_HEX)
    #print(f"加密结果 (HEX): {encrypted_hex}")
    # 解密测试
    encrypted_hex = data_value
    decrypted_text = aes_cfb_decrypt(encrypted_hex, KEY_HEX, IV_HEX)
    print(f"解密结果: {decrypted_text}")
    # 解析JSON数据
    try:
        parsed_data = json.loads(decrypted_text)

        # 提取所需字段
        for item in parsed_data['data']:
            title = item.get('title', 'N/A')
            nickName = item.get('nickName', 'N/A').strip()  # 去除多余空格
            playUrl = item.get('playUrl', 'N/A')

            # 打印结果
            print(f"标题: {title}")
            print(f"昵称: {nickName}")
            print(f"播放地址: {playUrl}")
            print("-" * 50)  # 分隔线

    except json.JSONDecodeError as e:
        print(f"JSON解析错误: {e}")
    except KeyError:
        print("JSON结构中缺少'data'字段")