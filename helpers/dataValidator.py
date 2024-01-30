from base64 import b64encode, b64decode
from json import dumps, loads
from typing import Union
from hashlib import sha1
from time import time
from math import ceil
from hmac import new
import re

import sys
sys.path.append('../')
from helpers.config import Config
from helpers.dataGenerator import DataGenerator

def json_len(json_obj):
    if isinstance(json_obj, str): return len(json_obj)
    elif isinstance(json_obj, bytes): return len(json_obj.decode('utf-8'))
    elif isinstance(json_obj, dict): return len(dumps(json_obj))
    else: return len(str(json_obj))

class DataValidator: 
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
            return False

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
            return False

        # checking prefix
        pre, post = decoded[:1], decoded[-20:]
        if pre != Config.PREFIX:
            return False

        # checking postfix
        seeds = [sum(map(int, re.findall(r'\d+', js))), Config.PREFIX_INT*data['5'], len(js)*data['5']]
        seeds.append(seeds[0]*data['6']*data['5'])
        rb = b""
        for seed in seeds:
            rb += DataGenerator.generate_random_bytes(seed)
        if rb != post:
            return False

        # checking timestamp
        if abs(int(data['5']) - ceil(time())) > 86400:
            return False

        # checking user
        # ...

        # checking client type
        

        return data['2']
    
    @staticmethod
    def from_sid_to_uid(sid: str | bytes | None = None):
        result = DataValidator.check_sid(sid)
        return None if not isinstance(result, str) else result

    @staticmethod
    def is_client_type_valid(client_type: int, user_id: str):
        if client_type == 100: return True
        elif client_type == 300:
            return True
        else: return False