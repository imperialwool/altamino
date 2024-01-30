from fastapi import APIRouter, Request
from time import time as timestamp

import sys
sys.path.append('../')
from objects import *
from helpers.cacheRouter import CachableRoute
from helpers.dataValidator import DataValidator

mock = APIRouter()
mock.route_class = CachableRoute

@mock.get("/g/s/topic/0/feed/community")
@mock.get("/g/s/community/trending")
@mock.get("/g/s/community/suggested")
@mock.get("/g/s/community/search")
async def recommended_communities_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "communityList": [],
        "paging": {},
        "allItemCount": 0
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/search/amino-id-and-link")
async def shitty_search_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "resultList": []
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/chat/thread/search")
async def useless_chat_search_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "threadList": [],
        "communityInfoMapping": {},
        "threadCount": 0,
        "paging": {}
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/sticker-collection")
async def stickers_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "stickerCollectionCount": 0,
        "stickerCollectionList": []
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/persona/profile/basic")
async def personabasic_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    uid = DataValidator.from_sid_to_uid(request)

    return Base.Answer({
        "basicProfile": {
            "auid": uid,
            "age": 20,
            "gender": 1,
            "country_code": "UK",
            "dateOfBirth": 731589
        }
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/store/sections")
async def storesections_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "storeSectionList": []
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/coupon/new-user-coupon")
async def newusercoupon_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer({
        "couponMappingList": []
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/chat/thread-check/human-readable")
async def humanreadable_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    return Base.Answer({
        "treatedNdcIds": [
            0
        ],
        "threadCheckResultInCommunities": {
            "0": []
        }

    }, spent_time=timestamp()-t1)

@mock.get("/g/s/announcement")
async def announcement_mock(request: Request, size: int = 1, language: str = "en"):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    return Base.Answer({
        "blogList": []
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/block/full-list")
async def blockedandblocker_mock(request: Request, size: int = 1, language: str = "en"):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    return Base.Answer({
        "blockedUidList": [
        ],
        "blockerUidList": [
        ]
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/account/{userId}/mission-set")
async def mission_set_mock(request: Request):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    return Base.Answer({
        "missionSet": {
            "reviewUs": {
                "completedTime": "2023-09-11T12:37:12Z"
            },
            "checkInTwoWeeks": {
                "completedTime": "2023-09-11T12:36:39Z"
            },
            "invitedOneFriend": {
                "completedTime": "2023-09-11T12:36:39Z"
            },
            "followInstagram": {
                "completedTime": "2023-09-11T12:36:39Z"
            },
            "downloadAminoMaster": {
                "completedTime": "2023-09-11T12:36:39Z"
            }
        }
    }, spent_time=timestamp()-t1)

@mock.get("/g/s/user-profile/{userId}/compose-eligible-check")
async def compose_eligible_check_mock(request: Request, objectType: str | None = None, objectSubtype: str | None = None):
    t1 = timestamp()
    if not await DataValidator.is_request_valid(request):
        return Errors.InvalidRequest(timestamp()-t1)
    
    if not isinstance(objectType, str) and not isinstance(objectSubtype, str):
        return Errors.InvalidRequest(timestamp()-t1)

    oT_allowed = ["chat-thread"]
    osT_allowed = ["public"]
    if objectType not in oT_allowed or objectSubtype not in osT_allowed:
        return Errors.InvalidRequest(timestamp()-t1)

    return Base.Answer(spent_time=timestamp()-t1)