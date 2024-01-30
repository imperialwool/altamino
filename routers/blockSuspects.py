from fastapi.responses import ORJSONResponse
from fastapi import APIRouter, Request
from orjson import loads
from hashlib import md5
from os import listdir

import sys
sys.path.append('../')
from objects import *
from helpers.database import *
from helpers.cacheRouter import CachableRoute
from helpers.dataValidator import DataValidator
from helpers.redisConnection import get as get_redis_connection

blockSuspects = APIRouter()
blockSuspects.route_class = CachableRoute

async def is_sus_in_cage(request: Request):
    ip = request.headers.get("X-Forwarded-For") or request.client.host or "1.1.1.1"
    ip_hash = md5(ip.encode() if isinstance(ip, str) else ip).hexdigest()

    redis = get_redis_connection()
    ip_info = await redis.get(ip_hash)
    if ip_info:
        await redis.set(
            ip_hash,
            5,
            ex=60*5
        )
        
        return ORJSONResponse(
            {
                "api:statuscode": 403,
                "api:duration": f"-99.999s",
                "api:message": "Your client and IP is frozen due trying find vulnerabilities or doing sus things.",
                "api:timestamp": "1970-01-01T00:00:00Z"
            },
            403
        )
    return

async def block_sus_users(request: Request, param: str | None = None, canary: str | None = None, response: ORJSONResponse | None = None):
    print(request.headers)
    freeze = False

    if request.scope['path'] == "/" and canary != None:
        freeze = True

    if request.headers.get("host", "") not in ["service.aminoapps.com", "service.altamino.top", "service.narvii.com"]:
        freeze = True

    if request.headers.get('sec-ch-ua'):
        freeze = True

    ua = request.headers.get('user-agent', "NOVALIDUSERAGENT")
    if (not ua) or (ua and not DataValidator.is_user_agent_valid(ua)):
        freeze = True

    ip = request.headers.get("X-Forwarded-For") or request.client.host or "1.1.1.1"
    ip_lists_folder = "./files/cloudip_ranges/"
    for ip_list in listdir(ip_lists_folder):
        ip_ranges = loads(open(ip_lists_folder+ip_list).read())
        if ip in ip_ranges: 
            freeze = True
            break

    if freeze:
        if await DataValidator.freeze_ip(request):
            return Errors.IpFrozen()
        else:
            return Errors.InternalServerError()
    else:
        return response or Errors.InvalidPath()

@blockSuspects.get("/{param}/.git/config")
@blockSuspects.get("/.git/config")
@blockSuspects.get("/{param}/security.txt")
@blockSuspects.get('/wp-login.php')
@blockSuspects.get('/clientaccesspolicy.xml')
@blockSuspects.get('/robots.txt')
@blockSuspects.get('/crossdomain.xml')
@blockSuspects.get('/pma/{param}')
@blockSuspects.get('/pma')
@blockSuspects.get('/phpmyadmin/{param}')
@blockSuspects.get('/phpmyadmin')
@blockSuspects.get('/adminer.php')
@blockSuspects.get('/')
async def block_sus_users_by_route(request: Request, param: str | None = None, canary: str | None = None):
    return await block_sus_users(request, param, canary)