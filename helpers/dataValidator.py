from base64 import b64encode, b64decode
from hashlib import sha1, md5
from json import dumps, loads
from fastapi import Request
from typing import Union
from os import listdir
from time import time
from math import ceil
from hmac import new
import ipaddress
import re

import sys
sys.path.append('../')
from objects import Errors
from helpers.config import Config
from helpers.dataGenerator import DataGenerator
from helpers.redisConnection import get as get_redis_connection

def json_len(json_obj):
    if isinstance(json_obj, str): return len(json_obj)
    elif isinstance(json_obj, bytes): return len(json_obj.decode('utf-8'))
    elif isinstance(json_obj, dict): return len(dumps(json_obj))
    else: return len(str(json_obj))

class DataValidator: 
    @staticmethod
    def paid_subscriber(status: Union[None, bool] = None):
        return 2 if not status else 1

    @staticmethod
    def check_email(email: str) -> bool:
        '''
            True if email is good, False if bad
        '''
        if "@" not in email or "." not in email: 
            return False
        with open("./files/disposables.txt", "r") as f:
            if email.partition("@")[2] in f.readlines():
                return False
        return True

    @staticmethod
    def check_timestamp(timestamp: int):
        '''
            True if timestamp is good, False if bad
        '''
        return ceil(time()) - ceil(timestamp/1000) <= 5

    @staticmethod
    def check_deviceId(deviceId: str) -> bool:
        '''
            True if deviceId is good, False if bad
        '''
        prefix, identifier, mac = deviceId[:2], deviceId[:-40], deviceId[-40:]
        if prefix != Config.PREFIX.hex(): return False
        calculated_mac = new(Config.DEVICE_KEY, bytes.fromhex(identifier), sha1).hexdigest()
        return mac.upper() == calculated_mac.upper()

    @staticmethod
    def check_signature(signature: str, data: Union[str, bytes, dict]) -> bool:
        '''
            True if signature is good, False if bad
        '''

        signature = signature.strip()

        if isinstance(data, dict):
            data_repl = dumps(data).replace(" ", "").encode('utf-8')
            data_clean = dumps(data).encode('utf-8')
        elif isinstance(data, str):
            data_repl = data.replace(" ", "").encode('utf-8')
            data_clean = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_repl = data_clean = data
        else:
            raise Exception(f"Invalid type of data (expected str, bytes or dict, but recieved {type(data)} instead)")

        return (
            signature == b64encode(Config.PREFIX + new(Config.SIG_KEY, data_repl, sha1).digest()).decode("utf-8")
        ) or (
            signature == b64encode(Config.PREFIX + new(Config.SIG_KEY, data_clean, sha1).digest()).decode("utf-8")
        )

    @staticmethod
    def check_sid(sid: Union[str, bytes, None]):
        '''
            True if sessionid is good, False if bad
        '''
        if not isinstance(sid, Union[str, bytes]):
            return [False, Errors.InvalidSession()]

        t1 = time()
        if isinstance(sid, bytes):
            sid = sid.decode('utf-8')
        # trying decode
        if sid.startswith("sid="):
            sid = sid[4:]
        decoded = b64decode(sid)
        js = decoded[1:-20].decode('utf-8')
        try: data = loads(js)
        except: 
            return [False, Errors.InvalidSession()]

        # checking prefix
        pre, post = decoded[:1], decoded[-20:]
        if pre != Config.PREFIX:
            return [False, Errors.InvalidSession(time()-t1)]

        # checking postfix
        seeds = [sum(map(int, re.findall(r'\d+', js))), Config.PREFIX_INT*data['5'], len(js)*data['5']]
        seeds.append(seeds[0]*data['6']*data['5'])
        rb = b""
        for seed in seeds:
            rb += DataGenerator.generate_random_bytes(seed)
        if rb != post:
            return [False, Errors.InvalidSession(time()-t1)]

        # checking timestamp
        if abs(int(data['5']) - ceil(time())) > 86400:
            return [False, Errors.ExpiredSession(time()-t1)]

        # checking user
        # ...

        # checking client type
        

        return [True, data['2']]
    
    @staticmethod
    def from_sid_to_uid(request: Request):
        sid = request.headers.get("NDCAUTH", "")
        result = DataValidator.check_sid(sid)
        return None if not isinstance(result[1], str) else result[1]

    @staticmethod
    def is_client_type_valid(client_type: int, user_id: str):
        if client_type == 100: return True
        elif client_type == 300:
            # check for TAA (team altamino) account lmao
            return True
        else: return False

    @staticmethod
    def if_ip_in_range(ip: str, ip_range: str):
        '''
            True if ip in range, False if not
        '''
        return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)

    @staticmethod
    def is_ip_address_is_good(request: Request | str):
        '''
            True if ip is good, False if bad
        '''
        if isinstance(request, Request):
            ip = request.headers.get("X-Forwarded-For") or request.headers.get("x-envoy-external-address") or request.client.host or "1.1.1.1"
        elif isinstance(request, str):
            ip = request
        else:
            raise Exception(f"Invalid type for IP (need: fastapi.Request, str; got: {type(request)})")
    
        #ip_lists_folder = "./files/cloudip_ranges/"
        #for ip_list in listdir(ip_lists_folder):
        #    ip_ranges = loads(open(ip_lists_folder+ip_list).read())
        #    for ip_range in ip_ranges:
        #        if DataValidator.if_ip_in_range(ip, ip_range):
        #            return False
        
        return True
    
    @staticmethod
    async def freeze_ip(request: Request | str):
        '''
            Freezing IP to prevent doin bad stuff from IP
        '''
        if isinstance(request, Request):
            ip = request.headers.get("X-Forwarded-For") or request.headers.get("x-envoy-external-address") or request.client.host or "1.1.1.1"
        elif isinstance(request, str):
            ip = request
        else:
            raise Exception(f"Invalid type for IP (need: fastapi.Request, str; got: {type(request)})")

        ip_hash = md5(ip.encode() if isinstance(ip, str) else ip).hexdigest()

        try:
            redis = get_redis_connection()
            await redis.set(
                ip_hash,
                5,
                ex=60*5
            )
            return True
        except Exception as e:
            print("Problem with freezing:", str(e))
            return False

    @staticmethod
    def is_user_agent_valid(request: Request | str):
        '''
            True if user agent is good, False if bad
        '''
        if isinstance(request, Request):
            header = request.headers.get("user-agent")
        elif isinstance(request, str):
            header = request
        else:
            raise Exception(f"Invalid type for user-agent (need: fastapi.Request, str; got: {type(request)})")
        pattern = r"Apple iPhone([^ ]+) iOS v([^ ]+) ([^/]+)/([^ ]+)"
        ios_versions = ['14.0', '14.0.1', '14.1', '14.2', '14.2.1', '14.3', '14.4', '14.4.1', '14.4.2', '14.5', '14.5.1', '14.6', '14.7', '14.7.1', '14.8', '14.8.1', '15.0', '15.0.1', '15.0.2', '15.1', '15.1.1', '15.2', '15.2.1', '15.3', '15.3.1', '15.4', '15.4.1', '15.5', '15.6', '15.6.1', '15.7', '15.7.1', '15.7.2', '15.7.3', '15.7.4', '15.7.5', '15.7.6', '15.7.7', '15.7.8', '15.7.9', '15.8', '16.0', '16.0.1', '16.0.2', '16.0.3', '16.1', '16.1.2', '16.2', '16.3', '16.3', '16.3.1', '16.4', '16.4.1', '16.5', '16.5.1', '16.6', '16.6.1', '16.7', '16.7.1', '16.7.2', '16.7.3', '16.7.4', '17.0', '17.0.1', '17.0.2', '17.0.3', '17.1', '17.1.1', '17.1.2', '17.2', '17.2.1']

        iphone_codes = ['8,1', '8,2', '8,4', '9,1', '9,2', '9,3', '9,4', '10,1', '10,2', '10,3', '10,4', '10,5', '10,6', '11,2', '11,4', '11,6', '11,8', '12,1', '12,3', '12,5', '12,8', '13,1', '13,2', '13,3', '13,4', '14,2', '14,3', '14,4', '14,5', '14,6', '14,7', '14,8', '15,2', '15,3', '15,4', '15,5', '16,1', '16,2']
        app_names = ["Main", "AltAmino", "Amino"]

        match = re.match(pattern, header)
        if match:
            iphone_code, ios_version, app_name, app_version = match.groups()
            if iphone_code not in iphone_codes:
                return False
            if ios_version not in ios_versions:
                return False
            if app_version:
                app_ver_array = app_version.split(".")
                ava_int = [int(i) for i in app_ver_array]
                if ava_int[0] == 3 and 18 < ava_int[1] <= 22: pass
                else: return False
            if app_name not in app_names:
                return False
            
            return True
        else:
            return False



    @staticmethod
    async def is_request_valid(request: Request, is_post: bool = False, need_auth: bool = False, is_upload_media: bool = False):
        '''
            True if request is good, False if bad
        '''
        headers = request.headers
        data = await request.body() or bytes()
        content_type = headers.get("Content-Type", "")
        ua = headers.get("user-agent", "INVALIDUSERAGENT")

        if ua in [None, ""]:
            print(0, 1)
            return False
        elif is_post and content_type in [None, ""]:
            print(0, 2)
            return False
        else:
            if not DataValidator.is_user_agent_valid(ua):
                print(0, 3)
                raise Exception(Errors.OutdatedDevice())
                return False
            
        if not DataValidator.is_ip_address_is_good(request):
            print("403 bot ip, details:", headers)
            if await DataValidator.freeze_ip(request):
                raise Exception(Errors.IpFrozen())

        if headers.get("Accept-Language") in [None, ""] or headers.get("Host") not in ["service.narvii.com", "service.aminoapps.com", "service.altamino.top"]:
            print(1)
            return False
        if (is_upload_media and is_post and headers.get("Content-Type") not in ["image/jpg", "image/jpeg", "image/png", "image/webp", "image/gif"]):
            print(2)
            return False
        if (not is_upload_media and is_post and 'application/json' not in content_type and 'application/x-www-form-urlencoded' not in content_type and 'application/octet-stream' not in content_type):
            print(3)
            return False
        if (need_auth and not DataValidator.check_sid(headers.get("NDCAUTH"))[0]):
            print(4)
            raise Exception(Errors.InvalidSession())
            return False
        if not DataValidator.check_deviceId(headers.get("NDCDEVICEID", "")):
            print(5)
            return False
        if is_post:
            try: content_length = int(headers.get("Content-Length", ""))
            except:
                print(6, None)
                return False

            def ccl(cl, data):
                return cl == len(data) or cl == json_len(data) or cl == json_len(data, True)

            if not ccl(content_length, data):
                print(6, len(data), json_len(data), json_len(data, True), type(data), content_length)
                return False

            if not is_upload_media and headers.get("NDC-MSG-SIG") in [None, ""]:
                print(7)
                return False

            if not is_upload_media and not DataValidator.check_signature(headers.get("NDC-MSG-SIG", ""), data):
                print(8)
                return False
        return True