from Crypto.Cipher import AES
import time
import hashlib
import requests
import http.client
import json
import binascii
import requests
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
#search_text = '91-晚晚「原创」'#搜索关键词
nickName_ = '91-蜜桃柚【原创】'#可能不需要填
uuid_ = 'dd6ad3d814a9b406450ffc9be265d8fd'
limit_ = '500'#限制视频个数
Vip_ZHUJI = 'https://long.nupeqc.cn'#Vip播放，下载接口，无时长限制
iv_hex = "65383932323563666262696d676b6375"
key_hex = "6363383864646339333537666634363165303866303437616564656536393262"


def append_to_file(line_content, file_path=r"C:\Users\Administrator\Desktop\AES.txt"):
    """
    将一行字符串追加到指定文件中

    参数:
        line_content: 要追加的字符串内容
        file_path: 文件路径(默认为桌面上的AES.txt)
    """
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(line_content + '\n')  # 自动添加换行符
        print(f"内容已追加到文件: {file_path}")
        return True
    except PermissionError:
        print(f"错误: 没有权限写入文件 {file_path}")
        return False
    except Exception as e:
        print(f"写入文件时发生错误: {e}")
        return False
def call_m3u8_downloader(title, m3u8_url):#调用逍遥一仙m3u8下载器
    data_payload = f"{title},{m3u8_url}"
    try:
        response = requests.post(
            "http://127.0.0.1:8787/",
            data={"data": data_payload, "type": "2"}
        )
        return response.json()['message'] == 'success'
    except Exception as e:
        print(f"调用失败，请检查下载器是否运行: {e}")
        return False
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
""" 生成sign
input_params = {
    "client": "pwa",
    "data": encrypted_hex,
    "timestamp": timestamp_str
}
"""
salt = "cc88ddc9357ff461e08f047aedee692b"  # 从_0x105a17取得
##########增强版数据生成A1
A1_bady_text = '{"oauth_type":"pwa","version":"4.5.0","timestamp":'+str(int(time.time() * 1000))+',"oauth_id":"lHXxcIXyHRHxRxyj1748116963193","mod":"system","code":"index","data":{}}'
print("A1_bady_text:", A1_bady_text)  # 调试输出
A1_bady_aes = aes_cfb_encrypt(A1_bady_text, iv_hex, key_hex)
print("A1_bady_aes:", A1_bady_aes)  # 调试输出

##############B1
B1_timestamp = str(int(time.time() * 1000))
input_params = {
    "client": "pwa",
    "data": A1_bady_aes,
    "timestamp":B1_timestamp
}
sign_raw = generate_sign(input_params, "cc88ddc9357ff461e08f047aedee692b")
sign_sha256 = hashlib.sha256(sign_raw.encode('utf-8')).hexdigest()
#print("sign_SHA256:", sign_sha256)
sign_md5 = hashlib.md5(sign_sha256.encode('utf-8')).hexdigest()
print("sign_md5:", sign_md5)
##############
B1_bady_text = '{"client":"pwa","timestamp":'+B1_timestamp+',"data":"'+A1_bady_aes+'","sign":"'+sign_md5+'","oauth_type":"pwa","version":"4.5.0","oauth_id":"lHXxcIXyHRHxRxyj1748116963193","mod":"index","code":"home","page":1}'
print("B1_bady_text:", B1_bady_text)
B1_bady_aes = aes_cfb_encrypt(B1_bady_text, iv_hex, key_hex)
print("B1_bady_aes:", B1_bady_aes)  # 调试输出

#########C1
C1_timestamp = str(int(time.time() * 1000))
input_params = {
    "client": "pwa",
    "data": B1_bady_aes,
    "timestamp":C1_timestamp
}
sign_raw = generate_sign(input_params, "cc88ddc9357ff461e08f047aedee692b")
sign_sha256 = hashlib.sha256(sign_raw.encode('utf-8')).hexdigest()
#print("sign_SHA256:", sign_sha256)
sign_md5 = hashlib.md5(sign_sha256.encode('utf-8')).hexdigest()
print("sign_md5:", sign_md5)
##############
C1_bady_text = '{"client":"pwa","timestamp":'+C1_timestamp+',"data":"'+B1_bady_aes+'","sign":"'+sign_md5+'","oauth_type":"pwa","version":"4.5.0","oauth_id":"lHXxcIXyHRHxRxyj1748116963193","mod":"index","code":"search","type":1,"key":"'+nickName_+'","page":1}'
print("C1_bady_text:", C1_bady_text)
C1_bady_aes = aes_cfb_encrypt(C1_bady_text, iv_hex, key_hex)
print("C1_bady_aes:", C1_bady_aes)  # 调试输出

#########D1
D1_timestamp = str(int(time.time() * 1000))
input_params = {
    "client": "pwa",
    "data": C1_bady_aes,
    "timestamp":D1_timestamp
}
sign_raw = generate_sign(input_params, "cc88ddc9357ff461e08f047aedee692b")
sign_sha256 = hashlib.sha256(sign_raw.encode('utf-8')).hexdigest()
sign_md5 = hashlib.md5(sign_sha256.encode('utf-8')).hexdigest()
print("sign_md5:", sign_md5)
D1_bady_text = '{"client":"pwa","timestamp":'+D1_timestamp+',"data":"","sign":"'+sign_md5+'","oauth_type":"pwa","version":"4.5.0","oauth_id":"lHXxcIXyHRHxRxyj1748116963193","mod":"user","limit":'+limit_+',"page":1,"code":"videos","uuid":"'+uuid_+'"}'
D1_bady_aes = aes_cfb_encrypt(D1_bady_text, iv_hex, key_hex)
print("D1_bady_aes:", D1_bady_aes)  # 调试输出

########E1
E1_timestamp = str(int(time.time() * 1000))
input_params = {
    "client": "pwa",
    "data": D1_bady_aes,
    "timestamp":E1_timestamp
}
sign_raw = generate_sign(input_params, "cc88ddc9357ff461e08f047aedee692b")
sign_sha256 = hashlib.sha256(sign_raw.encode('utf-8')).hexdigest()
sign_md5 = hashlib.md5(sign_sha256.encode('utf-8')).hexdigest()
print("sign_md5:", sign_md5)
E1_bady_text = 'client=pwa&timestamp='+E1_timestamp+'&data='+D1_bady_aes+'&sign='+sign_md5
print("E1_bady_text:", E1_bady_text)


#########数据构造完成
# 网络访问
post_bodydata = E1_bady_text
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
#print("Response Body:")
#print(body_ADS_data)
json_data = json.loads(body_ADS_data)
data_value = json_data["data"]
#print(data_value)
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
    #print(f"解密结果: {decrypted_text}")
    # 解析JSON数据
    try:
        parsed_data = json.loads(decrypted_text)
        # 获取项目数量
        item_count = len(parsed_data['data'])
        print(f"\033[32m>>>>共找到 {item_count} 个视频\033[0m")
        # 提取所需字段
        for item in parsed_data['data']:
            title = item.get('title', 'N/A')
            uuid = item.get('uuid', 'N/A')
            nickName = item.get('nickName', 'N/A').strip()  # 去除多余空格
            playUrl = item.get('playUrl', 'N/A').replace("https://10play.nupeqc.cn", Vip_ZHUJI)#提取播放地址，并替换成vip主机

            # 打印结果
            print(f"标题: {title}")
            print(f"用户昵称: {nickName}")
            print(f"uuid: {uuid}")
            print(f"播放地址: {playUrl}")
            print("-" * 50)  # 分隔线
            #call_m3u8_downloader(nickName+'-'+title, playUrl)#推送到逍遥一仙下载器
            append_to_file(nickName+'-'+title+','+playUrl, "D:/log.txt")#保存下载信息到本地,fluent_m3u8批量下载格式
    except json.JSONDecodeError as e:
        print(f"JSON解析错误: {e}")
    except KeyError:
        print("JSON结构中缺少'data'字段")