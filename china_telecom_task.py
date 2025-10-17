# -*- coding: utf-8 -*-
# process.env.chinaTelecomAccount = `
# 13454545457#123456
# 13454545457#456789
# `.trim();

'''
变量：chinaTelecomAccount
口令变量：dx_kl  口令用逗号,区分
变量格式: 手机号#服务密码
多号创建多个变量或者换行、&隔开
'''
import os
import re
import sys
import ssl
import time
import json
import httpx
import base64
import random
import certifi
import aiohttp
import asyncio
import logging
import datetime
import requests
import binascii
from http import cookiejar
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from urllib.parse import urlparse
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from aiohttp import ClientSession, TCPConnector
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
import pandas as pd
from tabulate import tabulate

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- START: 环境变量读取和初始化修复 ---
# 从环境变量读取账号信息。GitHub Actions 中使用 chinaTelecomAccount
chinaTelecomAccount = os.environ.get('chinaTelecomAccount') or os.environ.get('PHONES1') or ""
apptoken = os.environ.get('apptoken') or ""

# 口令变量，使用环境变量 dx_kl 或默认值
WELFARE_CODE = os.environ.get('dx_kl') or "心有灵犀,绑定福利,事事如意,2025加油,草长莺飞,888,年末狂欢,年末回馈"
WELFARE_CODES = [code.strip() for code in WELFARE_CODE.split(',') if code.strip()]

# 处理账号字符串，兼容换行符和 & 符号分隔
if '&' in chinaTelecomAccount:
    phone_list = [line.strip() for line in chinaTelecomAccount.split('&') if line.strip()]
else:
    phone_list = [line.strip() for line in chinaTelecomAccount.split('\n') if line.strip()]

# PHONES 变量用于后续的账号解析逻辑
PHONES = '\n'.join(phone_list)
# --- END: 环境变量读取和初始化修复 ---

MAX_RETRIES = 3
RATE_LIMIT = 10 

class RateLimiter:
    def __init__(self, rate_limit):
        self.rate_limit = rate_limit
        self.start_time = time.time()
        self.request_count = 0

    async def wait_for_limit(self):
        self.request_count += 1
        elapsed_time = time.time() - self.start_time
        if self.request_count > self.rate_limit:
            wait_time = 1.0 - elapsed_time
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.start_time = time.time()
            self.request_count = 1

def pcmToWav(pcm16, sampleRate):
    """将 PCM 16-bit 数据转换为 WAV Blob"""
    # 假设 pcm16 是 Int16Array
    dataView = new DataView(new ArrayBuffer(44 + pcm16.byteLength));
    let offset = 0;

    function writeString(str) {
        for (let i = 0; i < str.length; i++) {
            dataView.setUint8(offset + i, str.charCodeAt(i));
        }
        offset += str.length;
    }

    function writeUint32(val) {
        dataView.setUint32(offset, val, true);
        offset += 4;
    }

    function writeUint16(val) {
        dataView.setUint16(offset, val, true);
        offset += 2;
    }

    // RIFF header
    writeString('RIFF');
    writeUint32(36 + pcm16.byteLength);
    writeString('WAVE');

    // fmt chunk
    writeString('fmt ');
    writeUint32(16);
    writeUint16(1); // Audio format (1 for PCM)
    writeUint16(1); // Number of channels (1)
    writeUint32(sampleRate);
    writeUint32(sampleRate * 2); // Byte rate (SampleRate * NumChannels * BitsPerSample/8)
    writeUint16(2); // Block align (NumChannels * BitsPerSample/8)
    writeUint16(16); // Bits per sample (16)

    // data chunk
    writeString('data');
    writeUint32(pcm16.byteLength);
    
    // Copy PCM data
    let pcmOffset = offset;
    for (let i = 0; i < pcm16.length; i++) {
        dataView.setInt16(pcmOffset, pcm16[i], true);
        pcmOffset += 2;
    }

    return new Blob([dataView], { type: 'audio/wav' });
}

# -----------------------------------------------------------------------------------------------------
# 密钥配置 - 请勿随意修改，除非加密接口发生变化
# -----------------------------------------------------------------------------------------------------

# 1. DES3 密钥和 IV
des3_key = b"A!D89B5C82A2B3D04C5A6F29"  # 24字节密钥
des3_iv = b"01234567"                   # 8字节 IV

# 2. AES 密钥和 IV (用于某些特定接口)
aes_key_base = "b417c8008e330c6a"        # AES 密钥基
aes_iv = "1234567812345678"              # 16字节 IV

# 3. RSA 公钥 - 【重要】请替换为你实际需要的最新公钥字符串，并确保是 PEM 格式
# 如果程序运行失败，请优先检查此公钥是否过期或失效
rsa_public_key_str = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB
-----END PUBLIC KEY-----
"""

# -----------------------------------------------------------------------------------------------------
# 加密和解密函数
# -----------------------------------------------------------------------------------------------------

def encrypt_des3(data: str) -> str:
    """DES3 加密"""
    try:
        cipher = DES3.new(des3_key, DES3.MODE_CBC, des3_iv)
        # PKCS7 填充
        padded_data = pad(data.encode('utf-8'), DES3.block_size)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"DES3 加密失败: {e}")
        return ""

def decrypt_des3(encrypted_data: str) -> str:
    """DES3 解密"""
    try:
        cipher = DES3.new(des3_key, DES3.MODE_CBC, des3_iv)
        decoded = base64.b64decode(encrypted_data)
        decrypted = cipher.decrypt(decoded)
        # 移除 PKCS7 填充
        return unpad(decrypted, DES3.block_size).decode('utf-8')
    except Exception as e:
        logger.error(f"DES3 解密失败: {e}")
        return ""

def encrypt_rsa(data: str) -> str:
    """RSA 公钥加密"""
    try:
        # 移除公钥字符串中的 BEGIN/END 标记和换行符
        key_content = rsa_public_key_str.replace("-----BEGIN PUBLIC KEY-----", "")
        key_content = key_content.replace("-----END PUBLIC KEY-----", "")
        key_content = key_content.strip().replace('\n', '')

        # 重新构造 PEM 格式
        pem_key = (
            "-----BEGIN PUBLIC KEY-----\n" +
            key_content + "\n" +
            "-----END PUBLIC KEY-----"
        )
        
        public_key = RSA.import_key(pem_key.encode('utf-8'))
        cipher_rsa = PKCS1_v1_5.new(public_key)
        
        # RSA 加密分块处理，因为数据可能超过 RSA 密钥长度
        max_chunk = public_key.size_in_bytes - 11 # 1024位密钥通常是 117字节
        
        encrypted_chunks = []
        data_bytes = data.encode('utf-8')
        
        for i in range(0, len(data_bytes), max_chunk):
            chunk = data_bytes[i:i + max_chunk]
            encrypted_chunk = cipher_rsa.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
            
        encrypted_data = b"".join(encrypted_chunks)
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        logger.error(f"RSA 加密失败: {e}")
        return ""

# (Original AES encryption/decryption functions should be here if they were in the original script)
# ...

# -----------------------------------------------------------------------------------------------------
# 工具函数 (脱敏、推送等)
# -----------------------------------------------------------------------------------------------------

def get_first_three(phone):
    """获取手机号前2位"""
    return phone[:2] if phone and len(phone) >= 2 else phone

def mask_middle_four(value):
    """对中间7位进行脱敏"""
    if not value or len(value) < 8:
        return value
    return value[:2] + '*******' + value[-6:]

def send(title, content):
    """发送推送消息到 WXPusher"""
    if not apptoken:
        logger.info("未配置 WXPUSHER_APPTOKEN，跳过推送.")
        return

    # 从环境变量中获取用户 ID 列表
    uids_str = os.environ.get('WXPUSHER_UIDS')
    if not uids_str:
        logger.warning("未配置 WXPUSHER_UIDS，无法推送.")
        return
    uids = [uid.strip() for uid in uids_str.split(',') if uid.strip()]

    if not uids:
        logger.warning("WXPUSHER_UIDS 配置为空，无法推送.")
        return

    push_url = "http://wxpusher.zjiecode.com/api/send/message"
    
    # 构建推送数据
    data = {
        "appToken": apptoken,
        "content": content.replace('\n', '<br>'), # WXPusher 支持 HTML 换行
        "summary": title,
        "contentType": 2, # 2 表示 html 格式
        "uids": uids,
        "url": ""
    }

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(push_url, headers=headers, data=json.dumps(data), timeout=10)
        result = response.json()
        if result.get('code') == 1000:
            logger.info("WXPusher 消息推送成功.")
        else:
            logger.error(f"WXPusher 消息推送失败: {result.get('msg', '未知错误')}")
    except Exception as e:
        logger.error(f"WXPusher 推送请求异常: {e}")

# (Rest of the original script content, including the main logic and classes, goes here)
# ... (Assuming your original script had classes like CtClient, main logic, etc.)
# ... (Please paste the rest of your original content here)

# ==============================================================================
# 由于我无法访问您原始脚本的完整内容，您需要将您原始脚本中位于 
# `import pandas as pd` 之后的【所有】代码（包括所有的类定义、函数和主执行逻辑）
# 粘贴到此处。
# ==============================================================================

# ----------------- 【粘贴您原始脚本的剩余部分】 -----------------

# 假设您的原始脚本中 CtClient 类和任务执行逻辑在这里

class CtClient:
    """中国电信客户端，处理登录和任务执行"""
    def __init__(self, phone, password):
        self.phone = phone
        self.password = password
        self.headers = {
            # 基础头信息
            # ...
        }
        self.session = httpx.AsyncClient(timeout=30)
        self.results = {}

    async def login(self):
        """登录逻辑，使用 RSA 或其他加密方式处理密码"""
        logger.info(f"正在尝试登录账号: {mask_middle_four(self.phone)}")
        # 示例：RSA加密密码
        encrypted_password = encrypt_rsa(self.password)
        if not encrypted_password:
            self.results['登录'] = '✗(RSA加密失败)'
            return False

        # 示例登录请求 (请根据您原脚本中的实际逻辑进行调整)
        login_url = "https://appgologin.189.cn:9031/go_login/V2/login"
        payload = {
            "mobile": self.phone,
            "password": encrypted_password,
            "loginType": "PASSWD",
            # ... 其他参数
        }
        try:
            # ⚠️ 这里需要使用您的原始脚本的登录逻辑
            response = await self.session.post(login_url, json=payload, headers=self.headers)
            result = response.json()
            if result.get('res_code') == '0':
                self.results['登录'] = '✓'
                # 提取必要的 token/cookie
                # self.session.cookies.update(...)
                return True
            else:
                self.results['登录'] = f"✗({result.get('res_message', '登录失败')})"
                return False
        except Exception as e:
            self.results['登录'] = f"✗(请求异常: {str(e)})"
            return False

    # 示例：签到任务
    async def run_sign_in_task(self):
        """执行签到任务"""
        logger.info(f"执行签到任务...")
        sign_url = "https://wapact.189.cn:9001/SignActivity-api/task/signIn"
        try:
            response = await self.session.post(sign_url, headers=self.headers)
            result = response.json()
            if result.get('status') == 'SUCCESS':
                self.results['签到'] = '✓'
            else:
                self.results['签到'] = f"✗({result.get('msg', '签到失败')})"
        except Exception as e:
            self.results['签到'] = f"✗(请求异常: {str(e)})"

    # 示例：口令兑换任务
    async def run_exchange_task(self):
        """执行口令兑换任务"""
        if not WELFARE_CODES:
            self.results['口令兑换'] = '跳过(未配置口令)'
            return

        success_count = 0
        for kl in WELFARE_CODES:
            logger.info(f"尝试兑换口令: {kl}")
            exchange_url = "https://wapact.189.cn:9001/exchange/reward"
            payload = {"code": kl, "phone": self.phone}
            try:
                response = await self.session.post(exchange_url, json=payload, headers=self.headers)
                result = response.json()
                if result.get('status') == 'SUCCESS':
                    self.results[f'兑换-{kl}'] = '✓'
                    success_count += 1
                else:
                    self.results[f'兑换-{kl}'] = f"✗({result.get('msg', '失败')})"
                await asyncio.sleep(2) # 兑换之间暂停
            except Exception as e:
                self.results[f'兑换-{kl}'] = f"✗(请求异常)"

        if success_count > 0:
            self.results['口令兑换总计'] = f'成功({success_count}/{len(WELFARE_CODES)})'
        elif not any(key.startswith('兑换-') for key in self.results):
             self.results['口令兑换总计'] = f'✗(全部失败)'

    async def run_all_tasks(self):
        """执行所有任务"""
        if await self.login():
            await self.run_sign_in_task()
            await self.run_exchange_task()
            # ... 其他任务
        await self.session.aclose()


async def main():
    """主执行函数"""
    global timeValue, timeDiff
    if not PHONES:
        logger.error("请在环境变量 CHINA_TELECOM_ACCOUNTS 中配置手机号和服务密码!")
        return
        
    accounts = [line.split('#') for line in PHONES.split('\n') if '#' in line]
    if not accounts:
        logger.error("账号格式不正确，请确保格式为: 手机号#服务密码，并使用换行或 & 分隔.")
        return

    logger.info(f"共检测到 {len(accounts)} 个账号需要执行任务.")
    
    tasks = []
    all_results = []

    for phone, password in accounts:
        client = CtClient(phone.strip(), password.strip())
        tasks.append(client.run_all_tasks())
        all_results.append(client.results)

    # 并发执行所有账号任务
    await asyncio.gather(*tasks)

    # 结果整合与输出
    df = pd.DataFrame(all_results)
    df.insert(0, '手机号', [mask_middle_four(acc[0]) for acc in accounts])
    
    # 统计结果
    stats_df = df.apply(lambda x: pd.Series({
        '统计结果': f"成功:{len([s for s in x if s=='✓'])} 失败:{len([s for s in x if s=='✗'])}\"
    }), axis=1).reset_index()
    stats_df.columns = ['手机号', '统计结果']
    
    print("\n执行结果:")
    print(tabulate(df, headers='keys', tablefmt='grid', showindex=False))
    
    print("\n统计结果:")
    print(tabulate(stats_df, headers='keys', tablefmt='grid', showindex=False))
    
    # 发送推送
    push_title = f"中国电信任务执行报告 ({len(accounts)}个账号)"
    push_content = f"## {push_title}\n\n"
    push_content += tabulate(df, headers='keys', tablefmt='html', showindex=False)
    push_content += "\n\n"
    push_content += tabulate(stats_df, headers='keys', tablefmt='html', showindex=False)
    
    send(push_title, push_content)
    
try:
    if __name__ == "__main__":
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', None)
        pd.set_option('display.max_colwidth', None)
        
        # 确保 asyncio 事件循环运行 main 函数
        asyncio.run(main())

except Exception as e:
    logger.error(f"任务执行出错: {str(e)}")
