from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import ORJSONResponse
from datetime import datetime
from uuid import uuid4

from orjson import dumps, loads
from helpers.config import Config
from helpers.database import Database
from helpers.dataValidator import DataValidator

app = FastAPI()

clients = {}

@app.get("/")
async def lol():
    return ORJSONResponse({
        "api:statuscode": 104,
        "api:duration": "0.001s",
        "api:message": "Invalid G-SEC-WS.",
        "api:timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }, 400, {"server": "AltAmino Proprietary Server"})

@app.websocket("/")
async def websocket_endpoint(websocket: WebSocket):
    accept = True
    admin = False
    if websocket.headers.get("S-A-KEY") and websocket.headers.get("S-A-CALC"):
        key = websocket.headers['S-A-KEY']
        calc = str(websocket.headers['S-A-CALC'])
        if key == Config.ADMIN_KEY and calc == Config.ADMIN_VERIFY:
            admin = True
        else:
            accept = False
        
        uid = "admin"
    else:
        try:
            body = websocket.query_params["signbody"].split("|")
            auth = websocket.headers['NDCAUTH']
            device = websocket.headers['NDCDEVICEID']
            signature = websocket.headers['NDC-MSG-SIG']

            if len(body) != 2:
                raise Exception()
            
            if body[0] != device:
                raise Exception()
            
            data_time = body[1]
        except:
            answer = {
                "api:statuscode": 104,
                "api:duration": "0.001s",
                "api:message": "Invalid G-SEC-WS.",
                "api:timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            await websocket.close(1013, dumps(answer))
            return answer, 400
        
        if not DataValidator.check_deviceId(device):
            accept = False
        if not DataValidator.check_signature(data=f"{device}|{data_time}", signature=signature):
            accept = False
        if not DataValidator.check_sid(auth):
            accept = False

        uid = DataValidator.from_sid_to_uid(auth)

    if not accept:
        answer = {
            "api:statuscode": 105,
            "api:duration": "0.001s",
            "api:message": "Invalid G-SEC-WS.",
            "api:timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        await websocket.close(1013, dumps(answer))
        return answer, 400
    
    await websocket.accept()
    if not admin:
        clients.update({uid: websocket})

    try:
        while True:
            data = await websocket.receive_json()
            print(uid)
            
            if data.get("t") and data.get("o"):
                if data['t'] == 116:
                    await websocket.send_json({
                        "t": 117,
                        "o": {
                            "id": data['o'].get('id', str(uuid4())),
                            "threadChannelUserInfoList": []
                        }
                    })
                if data['t'] == 1001 and data['o'].get('markHasRead', None) != None:
                    if data['o']['markHasRead'] == True:
                        ndcId = data['o']['ndcId']
                        chatId = data['o']['threadId']
                        readTimestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                        
                        db = await Database().init()
                        chat = await db.get(f"x{ndcId}", "Chats")
                        await chat.update_one(
                            {"id": chatId},
                            {"$set": { f"lastReadedList.{uid}": readTimestamp }}
                        )
                        await db.close()

            if data.get("ADMIN-SAYS") and admin:
                try:
                    js = data['ADMIN-SAYS']
                    users = js['VICTIMS']
                    payload = js['WEAPON']

                    if users == "ALL":
                        for _, ws in clients.items():
                            await ws.send_json(payload)
                    
                    else:
                        for user, ws in clients.items():
                            if user in users:
                                await ws.send_json(payload)
                    
                    await websocket.send_json({"status": "ok", "clients": len(clients)})
                except Exception as e:
                    await websocket.send_json({"status": "error", "reason": str(e)})
    except WebSocketDisconnect:
        if not admin:
            clients.pop(uid)
