# -*- coding: utf-8 -*-
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
# 从环境变量读取账号信息。GitHub Actions 中使用 chinaTelecomAccount, CHINA_TELECOM_ACCOUNTS, 或 PHONES1
chinaTelecomAccount = (os.environ.get('chinaTelecomAccount') or 
                       os.environ.get('CHINA_TELECOM_ACCOUNTS') or 
                       os.environ.get('PHONES1') or "")
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
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB
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
        
        # 修复点：将 size_in_bytes 从属性调用改为方法调用：public_key.size_in_bytes()
        # RSA 加密分块处理，因为数据可能超过 RSA 密钥长度
        max_chunk = public_key.size_in_bytes() - 11 # 1024位密钥通常是 117字节
        
        encrypted_chunks = []
        data_bytes = data.encode('utf-8')
        
        for i in range(0, len(data_bytes), max_chunk):
            chunk = data_bytes[i:i + max_chunk]
            encrypted_chunk = cipher_rsa.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
            
        encrypted_data = b"".join(encrypted_chunks)
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        # 当 RSA Key 导入失败（如字符串格式不正确）或 size_in_bytes() 失败时，会在此处捕获
        logger.error(f"RSA 加密失败: {e}")
        return ""

# -----------------------------------------------------------------------------------------------------
# 工具函数 (脱敏、推送等)
# -----------------------------------------------------------------------------------------------------

def get_first_three(phone):
    """获取手机号前三位"""
    return phone[:3] if phone and len(phone) >= 3 else phone

def mask_middle_four(value):
    """只显示手机号的前两位和后两位，中间用星号替代"""
    if not value or len(value) < 4:
        return value
    
    first_two = value[:2]
    last_two = value[-2:]
    middle_stars_count = len(value) - 4
    
    return first_two + '*' * middle_stars_count + last_two

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

class CtClient:
    """中国电信客户端，处理登录和任务执行"""
    def __init__(self, phone, password):
        self.phone = phone
        self.password = password
        self.headers = {
            # 基础头信息
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Content-Type': 'application/json;charset=UTF-8',
        }
        # 使用 httpx.AsyncClient 并设置 base_url 如果需要
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
            "appId": "ACT_WAP"
        }
        try:
            # ⚠️ 这里需要使用您的原始脚本的登录逻辑
            response = await self.session.post(login_url, json=payload, headers=self.headers)
            
            # 新增：检查 HTTP 状态码
            if response.status_code == 404:
                 self.results['登录'] = f"✗(登录接口404，URL可能已失效: {login_url})"
                 logger.error(f"登录失败: URL返回404，请检查登录接口 {login_url} 是否已更新。")
                 return False

            result = response.json()
            if result.get('res_code') == '0':
                self.results['登录'] = '✓'
                # 提取必要的 token/cookie，并更新 session headers
                # 假设登录返回了 session token 或其他关键信息
                # self.headers['Authorization'] = result.get('data', {}).get('token')
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
        all_kl_results = []
        for kl in WELFARE_CODES:
            logger.info(f"尝试兑换口令: {kl}")
            exchange_url = "https://wapact.189.cn:9001/exchange/reward"
            payload = {"code": kl, "phone": self.phone}
            kl_result_key = f'兑换-{kl}'
            
            try:
                response = await self.session.post(exchange_url, json=payload, headers=self.headers)
                result = response.json()
                if result.get('status') == 'SUCCESS':
                    all_kl_results.append('✓')
                    success_count += 1
                else:
                    all_kl_results.append('✗')
                await asyncio.sleep(2) # 兑换之间暂停
            except Exception as e:
                all_kl_results.append('✗')
            
        self.results['口令兑换'] = f"成功({success_count}/{len(WELFARE_CODES)})" if success_count > 0 else "✗"


    async def run_all_tasks(self):
        """执行所有任务"""
        if await self.login():
            await self.run_sign_in_task()
            await self.run_exchange_task()
            # ... 其他任务
        await self.session.aclose()


async def main():
    """主执行函数"""
    if not PHONES:
        # 更新报错信息，明确指出所有可能的变量名
        logger.error("请在环境变量 chinaTelecomAccount, CHINA_TELECOM_ACCOUNTS 或 PHONES1 中配置手机号和服务密码!")
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
    
    # 清理并简化列名，以防口令兑换列过多
    df.columns = [col.replace('兑换-', 'KL-') for col in df.columns]

    # 统计结果
    stats_data = []
    for index, row in df.iterrows():
        # 统计成功的任务（标记为 '✓'）
        success_count = sum(1 for v in row.values if v == '✓')
        # 统计失败的任务（包含 '✗'）
        failure_count = sum(1 for v in row.values if '✗' in str(v))
        stats_data.append({
            '手机号': row['手机号'],
            '统计结果': f"成功:{success_count} 失败:{failure_count}"
        })
    stats_df = pd.DataFrame(stats_data)
    
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
