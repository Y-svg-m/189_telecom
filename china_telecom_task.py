# -*- coding: utf-8 -*-
# 13454545457#123456
# 13454545457#456789
# `.trim();

'''
变量：chinaTelecomAccount (或 CHINA_TELECOM_ACCOUNTS)
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
import certifi # <-- 必须保留
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

# --- START: 环境变量读取和初始化 (与 china_telecom_task.py 一致) ---
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

# -----------------------------------------------------------------------------------------------------
# 密钥配置 - 使用 china_telecom_task.py 的配置
# -----------------------------------------------------------------------------------------------------

# 1. DES3 密钥和 IV (用于加密手机号)
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
# 加密和解密函数 (与 china_telecom_task.py 一致)
# -----------------------------------------------------------------------------------------------------

def encrypt_des3(data: str) -> str:
    """DES3 加密"""
    try:
        cipher = DES3.new(des3_key, DES3.MODE_CBC, des3_iv)
        padded_data = pad(data.encode('utf-8'), DES3.block_size)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"DES3 加密失败: {e}")
        return ""

def encrypt_rsa(data: str) -> str:
    """RSA 公钥加密"""
    try:
        key_content = rsa_public_key_str.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip().replace('\n', '')

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
# 工具函数 (与 china_telecom_task.py 一致)
# -----------------------------------------------------------------------------------------------------

def get_first_three(phone):
    """获取手机号前三位 (用于日志打印)"""
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
    random_uuid = str(uuid.uuid4()).replace('-', '')
    return [random_uuid[:16], random_uuid[16:24], random_uuid[24:]]

def get_timestamp():
    """获取当前毫秒级时间戳字符串"""
    return str(int(time.time() * 1000))

def encode_phone(phone: str) -> str:
    """使用 DES3 加密手机号"""
    return encrypt_des3(phone) 

def ascii_add_2(number_str):
    """用于口令任务的手机号编码: ASCII 值 + 2"""
    return ''.join(chr(ord(char) + 2) for char in number_str)

def format_exchange_message(msg):
    """格式化口令兑换的错误消息"""
    if "省编码校验失败" in msg:
        return "非本号省口令"
    elif "券码已使用" in msg:
        return "已使用"
    elif "失败" in msg:
         return "失败"
    return msg

def send(title, content):
    """发送推送消息到 WXPusher (与 china_telecom_task.py 一致)"""
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
        # 【修改点 1】：将 verify 参数移至 AsyncClient 初始化时
        self.session = httpx.AsyncClient(timeout=30, verify=certifi.where())
        self.results = {}
        # 登录成功后保存的关键状态
        self.token = None
        self.sessionKey = None 
        self.jf_total = 0
        self.userId = None # 用于口令兑换和投票
        self.ticket = None # 用于口令兑换和投票
        
        # 新增：设备和时间相关参数
        self.uuid = get_uuid()

    async def login(self):
        """登录逻辑，使用真实的 client/userLoginNormal 接口和复杂 payload (与 china_telecom_task.py 一致)"""
        logger.info(f"正在尝试登录账号: {mask_middle_four(self.phone)}")
        
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
                    "systemVersion": "15.4.0", 
                    "authentication": self.password 
                }
            }
        }
        
        try:
            # 【修改点 2】：移除 post 调用中的 verify 参数
            response = await self.session.post(login_url, json=payload, headers=self.headers)
            
            if response.status_code != 200:
                 self.results['登录'] = f"✗(接口HTTP错误: {response.status_code})"
                 logger.error(f"登录失败: URL返回 HTTP {response.status_code}")
                 return False

            result = response.json()
            logger.debug(f"登录响应: {result}")
            
            res_code = result.get('res_code')
            res_message = result.get('res_message')
            
            if res_code == '0':
                data = result.get('data', {}).get('content', {})
                self.token = data.get('token')
                self.sessionKey = data.get('sessionKey') 
                self.userId = data.get('userId')
                self.ticket = await self._get_sso_ticket(self.phone, self.userId, self.token)
                
                if self.token and self.ticket:
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
                    self.results['登录'] = f"✗(响应成功但缺少关键信息)"
                    logger.error(f"登录成功响应但缺少Token或Ticket: {result}")
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
            # 捕获可能由 JSON 解析等引起的其他异常
            self.results['登录'] = f"✗(处理异常: {type(e).__name__})"
            logger.error(f"登录处理异常: {str(e)}")
            return False

    async def _get_sso_ticket(self, phone, userId, token):
        """获取SSO Ticket (Ticket用于某些活动接口)"""
        # 由于 Ticket 逻辑复杂，这里暂时用 token 作为 ticket 占位符。
        return self.token 


    async def get_total_points(self):
        """获取用户当前可用积分总数 (与 china_telecom_task.py 一致)"""
        if not self.token:
            self.results['总积分'] = '✗(未登录)'
            return
            
        jf_url = "https://wapact.189.cn:9001/SignActivity-api/task/getIntegral"
        try:
            response = await self.session.post(jf_url, headers=self.session.headers)
            response.raise_for_status() # 抛出非 2xx 状态码的异常
            result = response.json()
            if result.get('status') == 'SUCCESS':
                self.jf_total = int(result.get('totalIntegral', 0))
                self.results['总积分'] = self.jf_total
            else:
                self.results['总积分'] = '获取失败'
        except Exception as e:
            self.results['总积分'] = f"获取失败({type(e).__name__})"

    async def run_sign_in_task(self):
        """执行签到任务 (与 china_telecom_task.py 一致)"""
        if not self.token:
            self.results['签到'] = '✗(未登录)'
            return

        logger.info(f"执行签到任务...")
        sign_url = "https://wapact.189.cn:9001/SignActivity-api/task/signIn"
        try:
            response = await self.session.post(sign_url, headers=self.session.headers)
            response.raise_for_status()
            result = response.json()
            if result.get('status') == 'SUCCESS':
                self.results['签到'] = '✓'
            else:
                self.results['签到'] = f"✗({result.get('msg', '已签')})"
        except Exception as e:
            self.results['签到'] = f"✗(请求异常: {type(e).__name__})"

    async def run_exchange_welfare_task(self):
        """
        执行口令兑换和奖券领取任务
        基于 189.cn.py 的 dxTask 逻辑
        """
        if not WELFARE_CODES:
            self.results['口令兑换'] = '跳过(未配置口令)'
            return
        if not self.ticket:
            self.results['口令兑换'] = '✗(未登录/Ticket缺失)'
            return

        exchange_results = []
        phone_ascii_add_2 = ascii_add_2(self.phone)
        
        # 1. 登录到兑换活动平台，获取 userId 和 sessionKey
        login_url = 'https://wapact.189.cn:9001/yzf1/dispatch/login'
        login_payload = {
            "appType": "02",
            "authCode": self.ticket, # 使用 login 获得的 Ticket/Token
            "loginType": "1"
        }
        
        temp_headers = self.session.headers.copy()
        temp_headers.update({
            'Accept': "application/json, text/plain, */*",
            'Cache-Control': "no-cache",
            'appType': "02",
            'userId': "", # 初始为空
            'Content-Type': "application/json;charset=UTF-8",
            'sessionKey': "", # 初始为空
            'Origin': "https://wapact.189.cn:9001",
            'Referer': "https://wapact.189.cn:9001/flcj1/",
        })

        try:
            response = await self.session.post(login_url, json=login_payload, headers=temp_headers)
            response.raise_for_status()
            login_result = response.json()
            
            if not login_result.get('success'):
                self.results['口令兑换'] = f"✗(活动登录失败: {login_result.get('errorMsg', '未知')})"
                return

            useridv = login_result["result"]["userId"]
            sessionKey = login_result["result"]["sessionKey"]

            temp_headers.update({
                'userId': useridv,
                'sessionKey': sessionKey,
            })
            
            # 2. 兑换口令
            for kl in WELFARE_CODES:
                kl_status = '✗'
                kl_msg = '兑换失败'
                logger.info(f"尝试兑换口令: {kl}")
                exchange_url = "https://wapact.189.cn:9001/yzf1/welfare/convert"
                exchange_payload = {
                    "userId": useridv,
                    "code": kl,
                    "telephone": phone_ascii_add_2,
                    "isNewUser": "0"
                }
                
                try:
                    response = await self.session.post(exchange_url, json=exchange_payload, headers=temp_headers)
                    response.raise_for_status()
                    convert = response.json()
                    
                    if convert.get('success'):
                        kl_status = '✓'
                        kl_msg = '成功'
                    else:
                        kl_msg = format_exchange_message(convert.get('errorMsg', '未知错误'))
                except Exception as e:
                    kl_msg = f"兑换请求异常: {type(e).__name__}"

                exchange_results.append((kl, kl_status, kl_msg))
                await asyncio.sleep(1 + random.random() * 1) # 简单限速

            # 3. 领取奖券
            # 打印信息，模仿原脚本的延迟等待
            logger.info("领取可能不及时到账, 延迟5秒再去奖券查找可领取的奖品...")
            await asyncio.sleep(5) 
            
            welfarelistUrl = f"https://wapact.189.cn:9001/yzf1/welfare/list?userId={useridv}&telephone={phone_ascii_add_2}&state=0&size=100&page=0"
            
            response = await self.session.get(welfarelistUrl, headers=temp_headers)
            response.raise_for_status()
            datavv = response.json()

            if datavv.get('success') and datavv.get('result') and datavv['result'][0] is not None:
                for item in datavv['result']:
                    if item.get('name') and '元' in item['name']: # 领取含有 '元' 的奖品
                        name = item['name']
                        taskId = item["id"]
                        logger.info(f"开始领取奖券: {name}")
                        
                        verifypayload = {
                            "userId": useridv,
                            "id": taskId,
                            "telephone": phone_ascii_add_2,
                            "source": "1"
                        }
                        
                        await asyncio.sleep(3) # 领取前的延迟
                        
                        try:
                            response = await self.session.post(
                                'https://wapact.189.cn:9001/yzf1/welfare/verify',  
                                json=verifypayload,
                                headers=temp_headers
                            )
                            response.raise_for_status()
                            verify = response.json()

                            status = '✓' if verify.get('success') else '✗'
                            msg = '成功' if verify.get('success') else format_exchange_message(verify.get('errorMsg', '领取失败'))
                            exchange_results.append((f"领取:{name}", status, msg))
                        except Exception as e:
                            exchange_results.append((f"领取:{name}", '✗', f"请求异常: {type(e).__name__}"))
            else:
                 logger.info("奖券列表无可领取奖品或列表为空。")

        except Exception as e:
            self.results['口令兑换'] = f"✗(任务异常: {type(e).__name__})"
            logger.error(f"口令兑换/领奖券任务异常: {e}")
            return
            
        # 结果汇总
        success_count = sum(1 for _, status, _ in exchange_results if status == '✓')
        total_count = len(exchange_results)
        
        # 将结果详情存储到 results
        detail_messages = [f"{name} -> {status} ({msg})" for name, status, msg in exchange_results]
        self.results['口令兑换'] = f"✓({success_count}/{total_count})" if success_count > 0 else f"✗(0/{total_count})"
        self.results['口令兑换详情'] = '\n'.join(detail_messages)
        
    async def _addVotingRecord(self):
        """执行 AI 投票任务的子步骤：发起投票请求"""
        # 瑞数请求需要复杂的 Cookie/加密处理，原脚本逻辑使用了同步 requests 和 re.findall，
        # 且依赖于特定的 Cookie 策略和密钥。在异步 httpx 中完全复现非常困难。
        # 这里仅提供一个简化版的投票请求。如果投票失败，则表明瑞数或鉴权逻辑需要更新。
        
        if not self.ticket:
             logger.error("投票任务失败：Ticket 缺失。")
             return False

        codeValue="ACTCODE20241212V8LHJF5Y"
        # 1. 尝试获取瑞数 SESSION（此步骤通常是难点）
        # 简化：跳过复杂的瑞数请求，依赖后续请求的鉴权
        
        # 2. 投票请求
        url = "https://wapact.189.cn:9001/mas-pub-web/component/addVotingRecord"
        payload = {
            "groupId": 2067,
            "contentId": "1b7b42c3a7824005bad832d3a2d925a5" # 固定的投票ID
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'activityCode': codeValue,
            'yxai': codeValue,
            'ticket': self.ticket, 
            'Host': "wapact.189.cn:9001",
            'User-Agent': "CtClient;11.3.0;Android;12;Redmi K30 Pro;MDM3NzE2!#!MTMxODk", # 尝试使用原脚本的 UA
            'activityId': "",
            'wyDataStr': "",
            'masEnv': "android",
            'wycorpId': "",
            'X-Requested-With': "com.ct.client",
            'Cookie': '' # 不设置或尝试使用 session 自身的 Cookie
        })
        
        try:
            response = await self.session.post(url, json=payload, headers=headers)
            response.raise_for_status()
            res = response.json()
            
            if res.get("code") == '0000' and '成功' in res.get("msg", ''):
                 logger.info("AI 投票任务成功。")
                 return True
            else:
                 logger.warning(f"AI 投票任务失败: {res.get('msg', '未知错误')}")
                 return False
        except Exception as e:
            logger.error(f"AI 投票请求异常: {e}")
            return False

    async def run_voting_task(self):
        """执行 AI 投票任务 (基于 189.cn.py 的 AI_Yun1 逻辑)"""
        if not self.ticket:
            self.results['AI投票'] = '✗(未登录/Ticket缺失)'
            return
            
        logger.info(f"执行 AI 投票任务...")
        
        # 限制时间：原脚本在 2025-02-21 00:00:00 后跳过。这里简化为直接运行。
        if await self._addVotingRecord():
            self.results['AI投票'] = '✓'
        else:
            self.results['AI投票'] = '✗'

    async def run_all_tasks(self):
        """执行所有任务"""
        # 登录
        if await self.login():
            # 基础任务 (来自 china_telecom_task.py)
            await self.run_sign_in_task()
            await self.get_total_points() 
            
            # 扩展任务 (来自 189.cn.py)
            await self.run_voting_task()
            await self.run_exchange_welfare_task()
            
        await self.session.aclose()


async def main():
    """主执行函数"""
    if not PHONES:
        logger.error("请在环境变量中配置账号: 手机号#服务密码!")
        return
        
    accounts = [line.split('#') for line in PHONES.split('\n') if '#' in line]
    if not accounts:
        logger.error("账号格式不正确，请确保格式为: 手机号#服务密码，并使用换行或 & 分隔.")
        return

    logger.info(f"共检测到 {len(accounts)} 个账号需要执行任务.")
    
    tasks = []
    all_results = []

    # 使用 Semaphore 限制并发，避免对服务器造成过大压力
    semaphore = asyncio.Semaphore(5)
    
    async def wrapped_run_tasks(client):
        async with semaphore:
            await client.run_all_tasks()

    for phone, password in accounts:
        client = CtClient(phone.strip(), password.strip())
        tasks.append(wrapped_run_tasks(client))
        all_results.append(client.results)

    # 并发执行所有账号任务
    await asyncio.gather(*tasks)

    # 结果整合与输出
    df = pd.DataFrame(all_results)
    df.insert(0, '手机号', [mask_middle_four(acc[0]) for acc in accounts])
    
    # 重新排列列顺序
    desired_cols = ['手机号', '登录', '签到', 'AI投票', '口令兑换', '总积分', '口令兑换详情']
    current_cols = df.columns.tolist()
    final_cols = [col for col in desired_cols if col in current_cols] + [col for col in current_cols if col not in desired_cols and col not in desired_cols]
    df = df[final_cols]
    
    # 统计结果
    stats_data = []
    for index, row in df.iterrows():
        # 统计 '✓' 和 '✗'
        success_count = sum(1 for k, v in row.items() if k not in ['手机号', '总积分', '口令兑换详情'] and '✓' in str(v))
        failure_count = sum(1 for k, v in row.items() if k not in ['手机号', '总积分', '口令兑换详情'] and '✗' in str(v))
        stats_data.append({
            '手机号': row['手机号'],
            '统计结果': f"成功:{success_count} 失败:{failure_count}"
        })
    stats_df = pd.DataFrame(stats_data)
    
    # 终端输出
    print("\n执行结果:")
    print(tabulate(df.drop(columns=['口令兑换详情'], errors='ignore'), headers='keys', tablefmt='grid', showindex=False))
    
    print("\n统计结果:")
    print(tabulate(stats_df, headers='keys', tablefmt='grid', showindex=False))
    
    # 发送推送
    push_title = f"中国电信任务执行报告 ({len(accounts)}个账号)"
    # 将结果转换为 HTML 表格以便 WXPusher 推送
    push_content = f"## {push_title}\n\n"
    push_content += "### 任务结果概览\n"
    # 概览表格：排除详情
    push_content += tabulate(df.drop(columns=['口令兑换详情'], errors='ignore'), headers='keys', tablefmt='html', showindex=False)
    push_content += "\n\n### 统计结果\n"
    push_content += tabulate(stats_df, headers='keys', tablefmt='html', showindex=False)
    push_content += "\n\n### 口令兑换详情 (仅展示结果)\n"
    
    # 提取并格式化口令兑换详情
    detail_rows = []
    for index, row in df.iterrows():
        if '口令兑换详情' in row and row['口令兑换详情']:
            details = row['口令兑换详情'].split('\n')
            for detail in details:
                 detail_rows.append([row['手机号'], detail])
        else:
             detail_rows.append([row['手机号'], row['口令兑换'] if '口令兑换' in row else '未执行'])
             
    detail_df = pd.DataFrame(detail_rows, columns=['手机号', '兑换/领取详情'])
    push_content += tabulate(detail_df, headers='keys', tablefmt='html', showindex=False)
    
    send(push_title, push_content)
    
try:
    if __name__ == "__main__":
        # 配置 pandas 避免输出被截断
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', None)
        pd.set_option('display.max_colwidth', None)
        
        asyncio.run(main())

except Exception as e:
    logger.error(f"任务执行出错: {str(e)}")
