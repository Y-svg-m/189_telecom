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
import uuid # 导入用于生成设备ID的uuid模块
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

# --- START: 环境变量读取和初始化 ---
chinaTelecomAccount = (os.environ.get('chinaTelecomAccount') or 
                       os.environ.get('CHINA_TELECOM_ACCOUNTS') or 
                       os.environ.get('PHONES1') or "")
apptoken = os.environ.get('apptoken') or ""

WELFARE_CODE = os.environ.get('dx_kl') or "心有灵犀,绑定福利,事事如意,2025加油,草长莺飞,888,年末狂欢,年末回馈"
WELFARE_CODES = [code.strip() for code in WELFARE_CODE.split(',') if code.strip()]

if '&' in chinaTelecomAccount:
    phone_list = [line.strip() for line in chinaTelecomAccount.split('&') if line.strip()]
else:
    phone_list = [line.strip() for line in chinaTelecomAccount.split('\n') if line.strip()]

PHONES = '\n'.join(phone_list)
# --- END: 环境变量读取和初始化 ---

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

# 3. RSA 公钥 - 【重要】请替换为你实际需要的最新公钥字符串，并确保是 PEM 格式
# 注意：此公钥为占位符，请务必替换为有效的 key
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
        
        max_chunk = public_key.size_in_bytes() - 11 
        
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

# -----------------------------------------------------------------------------------------------------
# 工具函数 (脱敏、推送、辅助)
# -----------------------------------------------------------------------------------------------------

def get_first_three(phone):
    """获取手机号前三位 (用于日志打印，遵循原脚本片段)"""
    return phone[:3] if phone and len(phone) >= 3 else phone

def mask_middle_four(value):
    """只显示手机号的前两位和后两位，中间用星号替代"""
    if not value or len(value) < 4:
        return value
    
    first_two = value[:2]
    last_two = value[-2:]
    middle_stars_count = len(value) - 4
    
    return first_two + '*' * middle_stars_count + last_two

def get_uuid():
    """生成一个包含三个元素的 UUID 列表 (用于 deviceUid)"""
    # 生成一个完整的 UUID 字符串，并进行分段
    random_uuid = str(uuid.uuid4()).replace('-', '')
    return [random_uuid[:16], random_uuid[16:24], random_uuid[24:]]

def get_timestamp():
    """获取当前毫秒级时间戳字符串"""
    return str(int(time.time() * 1000))

def encode_phone(phone: str) -> str:
    """使用 DES3 加密手机号 (根据原脚本假设 phoneNum 字段为加密)"""
    return encrypt_des3(phone) 

def send(title, content):
    """发送推送消息到 WXPusher"""
    if not apptoken:
        logger.info("未配置 WXPUSHER_APPTOKEN，跳过推送.")
        return

    uids_str = os.environ.get('WXPUSHER_UIDS')
    if not uids_str:
        logger.warning("未配置 WXPUSHER_UIDS，无法推送.")
        return
    uids = [uid.strip() for uid in uids_str.split(',') if uid.strip()]

    if not uids:
        logger.warning("WXPUSHER_UIDS 配置为空，无法推送.")
        return

    push_url = "http://wxpusher.zjiecode.com/api/send/message"
    
    data = {
        "appToken": apptoken,
        "content": content.replace('\n', '<br>'), 
        "summary": title,
        "contentType": 2, 
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
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Content-Type': 'application/json;charset=UTF-8',
            'X-Requested-With': 'com.ct.client', 
            'Referer': 'https://wapact.189.cn/',
        }
        self.session = httpx.AsyncClient(timeout=30)
        self.results = {}
        # 登录成功后保存的关键状态
        self.sessionKey = None 
        self.token = None
        self.jf_total = 0
        
        # 新增：设备和时间相关参数
        self.uuid = get_uuid()

    async def login(self):
        """登录逻辑，使用真实的 client/userLoginNormal 接口和复杂 payload"""
        logger.info(f"正在尝试登录账号: {mask_middle_four(self.phone)}")
        
        # 1. 准备加密数据
        timestamp = get_timestamp()
        # 假设 loginAuthCipherAsymmertric 是 RSA 加密的服务密码
        login_auth_data = self.password
        loginAuthCipherAsymmertric = encrypt_rsa(login_auth_data)
        
        if not loginAuthCipherAsymmertric:
            self.results['登录'] = '✗(RSA加密失败)'
            return False

        login_url = "https://appgologin.189.cn:9031/login/client/userLoginNormal"
        
        # 2. 构建复杂的 JSON Payload
        payload = {
            "headerInfos": {
                "code": "userLoginNormal",
                "timestamp": timestamp,
                "broadAccount": "",
                "broadToken": "",
                # 遵循用户提供的 clientType
                "clientType": "#9.6.1#channel50#iPhone 14 Pro Max#", 
                "shopId": "20002",
                "source": "110003",
                "sourcePassword": "Sid98s",
                "token": "",
                "userLoginName": self.phone
            },
            "content": {
                "attach": "test",
                "fieldData": {
                    "loginType": "4",
                    "accountType": "",
                    "loginAuthCipherAsymmertric": loginAuthCipherAsymmertric, 
                    # 组合 UUID 
                    "deviceUid": self.uuid[0] + self.uuid[1] + self.uuid[2],
                    "phoneNum": encode_phone(self.phone), # DES3 加密手机号
                    "isChinatelecom": "0",
                    # 遵循用户提供的 systemVersion
                    "systemVersion": "15.4.0", 
                    "authentication": self.password # 保留原脚本片段中的明文 password
                }
            }
        }
        
        logger.info(f"开始登录请求 - 手机号: {get_first_three(self.phone)}...")

        try:
            response = await self.session.post(login_url, json=payload, headers=self.headers, verify=certifi.where())
            
            if response.status_code != 200:
                 self.results['登录'] = f"✗(接口HTTP错误: {response.status_code})"
                 logger.error(f"登录失败: URL返回 HTTP {response.status_code}，请检查登录接口 {login_url} 是否已更新。")
                 return False

            result = response.json()
            logger.info(f"登录响应: {result}")
            
            # 3. 解析响应
            res_code = result.get('res_code')
            res_message = result.get('res_message')
            
            if res_code == '0':
                # 登录成功，提取 token/sessionKey
                data = result.get('data', {}).get('content', {})
                self.token = data.get('token')
                self.sessionKey = data.get('sessionKey') 

                if self.token:
                    # 更新 session headers 以供后续任务使用
                    self.session.headers.update({
                        'Authorization': f'Bearer {self.token}',
                        'X-Request-Auth': self.token, 
                        'sessionKey': self.sessionKey or '', 
                        'X-Request-ID': get_timestamp(), 
                    })
                    self.results['登录'] = '✓'
                    return True
                else:
                    self.results['登录'] = f"✗(响应成功但缺少Token)"
                    logger.error(f"登录成功响应但缺少Token: {result}")
                    return False
            else:
                self.results['登录'] = f"✗({res_message or '登录失败'})"
                logger.error(f"登录失败: {res_message} | 响应: {result}")
                return False
        
        except httpx.RequestError as e:
            self.results['登录'] = f"✗(请求异常: {type(e).__name__})"
            logger.error(f"登录请求异常: {str(e)}")
            return False
        except Exception as e:
            self.results['登录'] = f"✗(处理异常: {str(e)})"
            return False
            
    async def get_total_points(self):
        """获取用户当前可用积分总数"""
        jf_url = "https://wapact.189.cn:9001/SignActivity-api/task/getIntegral"
        try:
            response = await self.session.post(jf_url, headers=self.session.headers)
            result = response.json()
            if result.get('status') == 'SUCCESS':
                self.jf_total = int(result.get('totalIntegral', 0))
                self.results['总积分'] = self.jf_total
            else:
                self.results['总积分'] = '获取失败'
        except Exception as e:
            self.results['总积分'] = f"获取失败({str(e)})"

    async def run_sign_in_task(self):
        """执行签到任务"""
        if not self.token:
            self.results['签到'] = '✗(未登录)'
            return

        logger.info(f"执行签到任务...")
        sign_url = "https://wapact.189.cn:9001/SignActivity-api/task/signIn"
        try:
            response = await self.session.post(sign_url, headers=self.session.headers)
            result = response.json()
            if result.get('status') == 'SUCCESS':
                self.results['签到'] = '✓'
            else:
                self.results['签到'] = f"✗({result.get('msg', '已签')})"
        except Exception as e:
            self.results['签到'] = f"✗(请求异常: {str(e)})"

    async def run_exchange_task(self):
        """执行口令兑换任务"""
        if not WELFARE_CODES:
            self.results['口令兑换'] = '跳过(未配置口令)'
            return
        if not self.token:
            self.results['口令兑换'] = '✗(未登录)'
            return

        success_count = 0
        
        for kl in WELFARE_CODES:
            logger.info(f"尝试兑换口令: {kl}")
            exchange_url = "https://wapact.189.cn:9001/exchange/reward"
            payload = {"code": kl, "phone": self.phone}
            
            try:
                response = await self.session.post(exchange_url, json=payload, headers=self.session.headers)
                result = response.json()
                if result.get('status') == 'SUCCESS':
                    success_count += 1
                
                await asyncio.sleep(1 + random.random() * 2) 
            except Exception:
                pass 
            
        self.results['口令兑换'] = f"✓({success_count}/{len(WELFARE_CODES)})" if success_count > 0 else "✗"


    async def run_all_tasks(self):
        """执行所有任务"""
        if await self.login():
            await self.run_sign_in_task()
            await self.run_exchange_task()
            await self.get_total_points() 
        await self.session.aclose()


async def main():
    """主执行函数"""
    if not PHONES:
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
    
    # 重新排列列顺序，将登录和积分放前面
    desired_cols = ['手机号', '登录', '签到', '总积分', '口令兑换']
    current_cols = df.columns.tolist()
    final_cols = [col for col in desired_cols if col in current_cols] + [col for col in current_cols if col not in desired_cols]
    df = df[final_cols]
    
    # 统计结果
    stats_data = []
    for index, row in df.iterrows():
        success_count = sum(1 for k, v in row.items() if k not in ['手机号', '总积分'] and '✓' in str(v))
        failure_count = sum(1 for k, v in row.items() if k not in ['手机号', '总积分'] and '✗' in str(v))
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
        
        asyncio.run(main())

except Exception as e:
    logger.error(f"任务执行出错: {str(e)}")
