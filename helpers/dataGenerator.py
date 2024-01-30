from string import ascii_letters, digits
from base64 import b64encode
from hashlib import sha1
from typing import Union
from json import dumps
from os import urandom
from hmac import new
import random
import re

import sys
sys.path.append('../')
from objects import Errors
from helpers.config import Config

class DataGenerator:
    @staticmethod
    def generate_random_bytes(seed: int, length: int = 5) -> bytes:
        r = random.Random()
        r.seed(seed)
        return bytes([r.randint(0, 255) for _ in range(length)])

    @staticmethod
    def generate_random_string(length: int = 16):
        return ''.join(random.choices(ascii_letters+digits, k=length))

    @staticmethod
    def generate_sid(data: dict, as_string: bool = False) -> Union[bytes, str]:
        js = dumps(data)
        seeds = [sum(map(int, re.findall(r'\d+', js))), Config.PREFIX_INT*data['5'], len(js)*data['5']]
        seeds.append(seeds[0]*data['6']*data['5'])
        rb = b""
        for seed in seeds:
            rb += DataGenerator.generate_random_bytes(seed)
        result = b64encode(Config.PREFIX + js.encode('utf-8') + rb)
        return result if not as_string else result.decode('utf-8')
    
    @staticmethod
    def generate_deviceId(data: Union[None, bytes] = None) -> str:
        if isinstance(data, str): data = bytes(data, 'utf-8')
        identifier = Config.PREFIX + (data or urandom(20))
        mac = new(Config.DEVICE_KEY, identifier, sha1)
        return f"{identifier.hex()}{mac.hexdigest()}".upper()