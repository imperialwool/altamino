from re import findall
from hashlib import md5
from typing import Callable
from fastapi import Request
from helpers.config import *
from orjson import loads, dumps
from fastapi.routing import APIRoute
from fastapi import Request, Response
from fastapi.responses import ORJSONResponse
from helpers.redisConnection import get as get_redis_connection

class CachableRoute(APIRoute):
    main_headers = {
        "content-type": "application/json; charset=utf-8",
        "connection": "keep-alive",
        "server": "AltAmino Proprietary Server"
    }
    
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()
        
        async def custom_route_handler(request: Request) -> Response:
            if "verification-code" in request.scope['path']:
                return await original_route_handler(request)
            
            if request.scope['method'] == "POST":
                key = md5(
                    request.scope['method'].encode() +
                    request.scope['raw_path'] +
                    str(request.headers).encode() +
                    await request.body()
                ).hexdigest()
            else: 
                key = md5(
                    request.scope['method'].encode() +
                    request.scope['raw_path'] +
                    request.scope['query_string'] +
                    str(request.headers).encode()
                ).hexdigest()

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
                    403,
                    self.main_headers
                )
            result = await redis.get(key)
            if result:
                result = loads(result)
                
                return ORJSONResponse(
                    loads(result['response']),
                    result['status_code'],
                    self.main_headers,
                    result['media_type']
                )
            else:
                response = await original_route_handler(request)
                response_body = response.body.decode()
                await redis.set(
                    key,
                    dumps({
                        "response": response_body,
                        "status_code": response.status_code,
                        "media_type": response.media_type
                    }),
                    ex=2 if findall(r"(chat|thread)", request.scope['raw_path'].decode()) else 60
                )
                
                return ORJSONResponse(
                    loads(response_body),
                    response.status_code,
                    self.main_headers,
                    response.media_type
                )

        return custom_route_handler