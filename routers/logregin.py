from fastapi.responses import StreamingResponse
from base64 import b64decode, b64encode
from fastapi import APIRouter, Request
from time import time as timestamp
from redmail import EmailSender
from hashlib import blake2b
from uuid import uuid4
from math import ceil

import sys
sys.path.append('../')
from objects import *
from helpers.config import Config
from helpers.database import *
from helpers.imageTools import ImageTools
from helpers.cacheRouter import CachableRoute
from helpers.dataValidator import DataValidator
from helpers.dataGenerator import DataGenerator

logregin = APIRouter()
logregin.route_class = CachableRoute

@logregin.get("/verification-code/{code}")
async def seeVerificationCode(code):
    t1 = timestamp()
    db = await Database().init()
    table = await db.get(table="VerificationCodes")
    row = await table.find_one({"uniqueCode": code})
    await db.close()
    if row == None: return Errors.InvalidVerificationCode()
    if ceil(timestamp()) - row['timestamp'] > 3600:
        return Errors.ExpiredVerificationCode(timestamp()-t1) 
    img, _, __ = ImageTools.generate_captcha(row['captchaAnswer'])
    return StreamingResponse(img)

'''
    if resetPassword is True:
        data["level"] = 2
        data["purpose"] = "reset-password"
'''

@logregin.post('/g/s/auth/request-security-validation')
async def requestCode(request: Request):
    t1 = timestamp()
    try:
        data = await request.json()
        reciever = data['identity']
        if ( 
            not DataValidator.check_deviceId(data['deviceID'])
        ) or (
            data['deviceID'] != request.headers['NDCDEVICEID']
        ) or (
            data['type'] != 1
        ) or (
            not DataValidator.check_email(reciever)
        ):
            raise Exception()
    except:
        return Errors.InvalidRequest(timestamp()-t1)

    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    db = await Database().init()
    table = await db.get(table="VerificationCodes")
    row = await table.find_one({
        "$or": [
            { "deviceId": data['deviceID'] },
            { "email": reciever }
        ]
    })
    if row != None:
        if ceil(timestamp()) - row['timestamp'] <= 3600:
            return Errors.VerificationCodeAlreadySent(timestamp()-t1)
        else:
            await table.delete_many({
                "$or": [
                    { "deviceId": data['deviceID'] },
                    { "email": reciever }
                ]
            })
    
    uniqueCode = blake2b(
        data['deviceID'].encode("utf-8"),
        key="AltAmino".encode("utf-8"),
        salt=str(ceil(timestamp())).encode("utf-8"),
        digest_size=32
    ).hexdigest()

    c_img, c_answer, _ = ImageTools.generate_captcha() 

    await table.insert_one( ModelFabric.Construct(
        Global.VerificationCodes,
        uniqueCode=uniqueCode, deviceId=data['deviceID'], captchaAnswer=c_answer, email=reciever
    ) )
    await db.close()

    text = '''<h3>You have requested a confirmation code for AltAmino. Please enter this code.</h3>{{ IMAGE }}<p>Can't see the code? Please click on the link below to see the code.</p>[LINK]<br><p>If this is not your AltAmino account, don't worry. Someone may have misspelled their email address.</p><p>If you have any difficulties or questions, please email us: support@altamino.top</p><br><p>Thanks,<br>Team AltAmino</p>'''
    try:
        email = EmailSender(
            host=Config.SMTP_SERVER,
            port=Config.SMTP_PORT,
            username=Config.SMTP_USER,
            password=Config.SMTP_PSWD,
            use_starttls=True
        )
        email.send(
            #sender="AltAmino Team",
            subject="Confirmation code for AltAmino",
            receivers=[reciever],
            html=text.replace("[LINK]", f"{Config.API_DOMAIN}/api/v1/verification-code/{uniqueCode}"),
            body_images={"IMAGE": c_img}
        )
    except Exception as e:
        print(e)
        return Errors.MailError(timestamp()-t1)
    return Base.Answer(spent_time=timestamp()-t1)

'''
    "secret": f"0 {password}",
    "deviceID": deviceId,
    "email": email,
    "clientType": 100,
    "nickname": nickname,
    "clientCallbackURL": "narviiapp://relogin",
    "validationContext": {
        "data": {
            "code": verificationCode
        },
        "type": 1,
        "identity": email
    },
    "type": 1,
    "identity": email,
    "timestamp": int(timestamp() * 1000)
'''

@logregin.post('/g/s/auth/check-security-validation')
async def check_code(request: Request):
    data = await request.json()
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request, is_post=True):
        return Errors.InvalidRequest(timestamp()-t1)

    try:
        if ( 
            not DataValidator.check_deviceId(data['deviceID']) or data['deviceID'] != request.headers['NDCDEVICEID']
        ) or (
            not DataValidator.check_timestamp(data['timestamp'])
        ) or (
            not DataValidator.check_email(data['validationContext']['identity'])
        ) or (
            data['validationContext']['type'] != 1 or len(data['validationContext']['data']['code']) != 6
        ):
            raise Exception()
    except:
        return Errors.InvalidRequest(timestamp()-t1)

    email = data['validationContext']['identity']

    db = await Database().init()
    table = await db.get(table="VerificationCodes")
    row = await table.find_one({"deviceId": data['deviceID'], "email": email})
    if row == None:
        return Errors.UnverifiedEmail(timestamp()-t1)
    if str(data['validationContext']['data']['code']) != str(row['captchaAnswer']):
        return Errors.InvalidVerificationCode(timestamp()-t1)

    print(await table.update_many(
        {"deviceId": data['deviceID'], "email": email},
        {"$set": {"codeVerified": True}}
    ))

    await db.close()
    return Base.Answer(spent_time=timestamp()-t1)

@logregin.post('/g/s/auth/register')
async def register(request: Request):
    data = await request.json()
    
    ### BASE CHECK START
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request, is_post=True):
        return Errors.InvalidRequest(timestamp()-t1)
    ### BASE CHECK END

    try:
        reciever = data.get('identity') or data.get('email')
        if ( 
            not DataValidator.check_deviceId(data['deviceID']) or data['deviceID'] != request.headers['NDCDEVICEID']
        ) or (
            not DataValidator.check_timestamp(data['timestamp'])   
        ) or (
            not DataValidator.check_email(reciever)
        ) or (
            data['secret'][:2] != "0 " or data['nickname'].strip() in [None, ""] or data['clientCallbackURL'].strip() != "narviiapp://relogin"
        ):
            raise Exception()

        if data.get("validationContext"):
            if reciever != data['validationContext']['identity'] or data['validationContext']['type'] != 1:
                raise Exception()
    except Exception as e:
        print(e)
        return Errors.InvalidRequest(timestamp()-t1)

    db = await Database().init()
    codes = await db.get(table="VerificationCodes")
    codes_row = await codes.find_one({"deviceId": data['deviceID'], "email": reciever})
    if codes_row == None:
        print("No codes")
        return Errors.UnverifiedEmail(timestamp()-t1)
    if data.get("validationContext"):
        if str(data['validationContext']['data']['code']) != str(codes_row['captchaAnswer']):
            print("Invalid code (somehow)")
            return Errors.InvalidVerificationCode(timestamp()-t1)
        else:
            codes_row['codeVerified'] = True

    if not codes_row['codeVerified']:
        print("Code not verified")
        return Errors.InvalidRequest(timestamp()-t1)

    users = await db.get(table="Users")
    row = await users.find_one({"email": data['email']})
    if row != None:
        await db.close()
        return Errors.EmailWasTaken(timestamp()-t1)

    uid = str(uuid4())
    passwordHash = blake2b(data['secret'].encode("utf-8"), key="AltAmino".encode("utf-8")).hexdigest()
    await users.insert_one( ModelFabric.Construct(
        Global.Users,
        id=uid,
        nickname=data['nickname'],
        email=data['email'],
        passwordHash=passwordHash,
        aminoId=data['email'].partition("@")[0] + DataGenerator.generate_random_string()
    ) )
    row1 = await users.find_one({"id": uid})
    table = await db.get(database="x0", table="Users")
    await table.insert_one( ModelFabric.Construct(
        Community.Users,
        id=uid,
        nickname=data['nickname']
    ) )
    row2 = await table.find_one({"id": uid})
    await codes.delete_one({"deviceId": data['deviceID'], "email": reciever})
    await db.close()

    return Base.Answer({
        "newAccount": True,
        "auid": uid,
        "sid": DataGenerator.generate_sid({
            "1": None,
            "0": 2,
            "3": 0,
            "2": uid,
            "5": ceil(timestamp()),
            "4": request.headers.get("X-Forwarded-For") or request.client.host or "1.1.1.1",
            "6": data['clientType']
        }, True),
        "account": User.OwnSensetiveProfile(row1),
        "userProfile": User.OwnNonSensetiveProfile(row1 | row2),
        "secret": data['secret'],

    }, spent_time=timestamp()-t1)

@logregin.post('/g/s/auth/register-check')
async def register_check(request: Request):
    data = await request.json()
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request, is_post=True): return Errors.InvalidRequest(timestamp()-t1)

    try:
        if ( 
            not DataValidator.check_deviceId(data['deviceID']) or data['deviceID'] != request.headers['NDCDEVICEID']
        ) or (
            not DataValidator.check_timestamp(data['timestamp'])
        ):
            raise Exception()
        if (data.get("email")):
            if (not DataValidator.check_email(data.get("email"))):
                raise Exception()
        elif (data.get("secret")):
            if (data['secret'][:2] != "0 "):
                raise Exception()
        else:
            raise Exception()
    except:
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer(spent_time=timestamp()-t1)

@logregin.post('/g/s/auth/login')
async def login(request: Request):
    t1 = timestamp()
    data = await request.json()
    if not await DataValidator.is_request_valid(request, is_post=True):
        return Errors.InvalidRequest(timestamp()-t1)

    try:
        if str(data['email']).strip() in ["None",""] or str(data['secret']).strip() in ["None",""]:
            return Errors.InvalidLogin(timestamp()-t1)
        
        if ( 
            not DataValidator.check_deviceId(data['deviceID']) or data['deviceID'] != request.headers['NDCDEVICEID']
        ) or (
            not DataValidator.check_timestamp(data['timestamp'])
        ) or (
            not DataValidator.check_email(data['email'])
        ):
            raise Exception()
    except Exception as e:
        print(e)
        return Errors.InvalidRequest(timestamp()-t1)

    secretSplitted = data['secret'].split()
    if len(secretSplitted) == 2 and secretSplitted[0] == "0":
        passwordHash = blake2b(data['secret'].encode("utf-8"), key="AltAmino".encode("utf-8"), digest_size=64).hexdigest()
        
        db = await Database().init()
        table = await db.get(table="Users")
        row = await table.find_one({"passwordHash": passwordHash, "email": data['email']})
        if row['status'] == 9:
            await db.close()
            return Errors.UserBanned(timestamp()-t1)

        if row == None:
            await db.close()
            return Errors.InvalidLogin(timestamp()-t1)
        else:
            if not DataValidator.is_client_type_valid(data['clientType'], row['id']):
                return Errors.UnsupportedClient(timestamp()-t1)

            table = await db.get(database="x0", table="Users")
            additionalRow = await table.find_one({"id": row['id']})
            await db.close()
            
            ip = request.headers.get("X-Forwarded-For") or request.client.host or "1.1.1.1"
            tmstmp = ceil(timestamp())
            return Base.Answer({
                "auid": row['id'],
                "account": User.OwnSensetiveProfile(row),
                "userProfile": User.OwnNonSensetiveProfile(additionalRow | row),
                "secret": f"31 {row['id']} {ip} {b64encode(passwordHash.encode()).decode()} {tmstmp} {31*tmstmp}",
                "sid": DataGenerator.generate_sid({
                    "1": None, "0": 2, "3": 0, "2": row['id'], "5": tmstmp, "4": ip, "6": data['clientType']
                }, True)
            }, spent_time=timestamp()-t1)
    elif len(secretSplitted) == 6:
        if (
            not secretSplitted[0] == "31"
        ) or (
            int(secretSplitted[0]) * int(secretSplitted[4]) != int(secretSplitted[5])
        ):
            return Errors.InvalidRequest(spent_time=timestamp()-t1)
        decodedPswdHash = b64decode(secretSplitted[3]).decode()
        db = await Database().init()
        table = await db.get(table="Users")
        row = await table.find_one({"id": secretSplitted[1]})
        if row == None:
            await db.close()
            return Errors.InvalidRequest(spent_time=timestamp()-t1)
        if row['passwordHash'] != decodedPswdHash:
            await db.close()
            return Errors.InvalidRequest(spent_time=timestamp()-t1)
        if row['status'] == 9:
            await db.close()
            return Errors.UserBanned(timestamp()-t1)

        table = await db.get(database="x0", table="Users")
        additionalRow = await table.find_one({"id": row['id']})
        await db.close()

        ip = request.headers.get("X-Forwarded-For") or request.client.host or "1.1.1.1"
        tmstmp = ceil(timestamp())
        return Base.Answer({
            "auid": row['id'],
            "account": User.OwnSensetiveProfile(row),
            "userProfile": User.OwnNonSensetiveProfile(additionalRow | row),
            "sid": DataGenerator.generate_sid({
                "1": None, "0": 2, "3": 0, "2": row['id'], "5": tmstmp, "4": ip, "6": data['clientType']
            }, True)
        }, spent_time=timestamp()-t1)
    else:
        return Errors.InvalidRequest(spent_time=timestamp()-t1)

@logregin.post('/g/s/auth/logout')
async def logout(request: Request):
    checkSid, t1 = DataValidator.check_sid(request.headers.get('NDCAUTH')), timestamp()
    data = await request.json()
    if not checkSid[0]:
        return checkSid[1]
    if not await DataValidator.is_request_valid(request, is_post=True, need_auth=True):
        return Errors.InvalidRequest(timestamp()-t1)

    try:
        if (
            not DataValidator.check_timestamp(data['timestamp'])
        ):
            raise Exception()
    except Exception as e:
        print(e)
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "auid": checkSid[1]
    }, spent_time=timestamp()-t1)

@logregin.get('/g/s/device/dev-options')
async def dev_device(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request): return Errors.InvalidRequest(timestamp()-t1)
    
    uid = DataValidator.from_sid_to_uid(request)
    if uid:
        db = await Database().init()
        table = await db.get(table="Users")
        row = await table.find_one({"id": uid})
        await db.close()
        if row['status'] == 9:
            return Errors.UserBanned(timestamp()-t1)
    
    return Base.Answer({"devOptions": None}, timestamp()-t1)

@logregin.post('/g/s/device')
async def device(request: Request):
    t1 = timestamp()
    try: await request.json()
    except: return Errors.InvalidRequest(timestamp()-t1)
    if not await DataValidator.is_request_valid(request, is_post=True): return Errors.InvalidRequest(timestamp()-t1)

    uid = DataValidator.from_sid_to_uid(request)
    if uid:
        db = await Database().init()
        table = await db.get(table="Users")
        row = await table.find_one({"id": uid})
        await db.close()
        if row['status'] == 9:
            return Errors.UserBanned(timestamp()-t1)

    return Base.Answer({"devOptions": None}, timestamp()-t1)