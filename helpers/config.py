class Config:
    MONGODB_PROD_CONNECTION_STRING = "mongodb://"
    MONGODB_DEV_CONNECTION_STRING = "mongodb+srv://"
    MONGODB_MAIN_DB = "global"

    REDIS_PROD_CONNECTION_STRING = "redis://127.0.0.1"
    REDIS_DEV_CONNECTION_STRING = "redis://127.0.0.1:32768"

    S3_SERVICE_NAME = 's3'
    S3_ACCESS_KEY = ''
    S3_SECRET_ACCESS_KEY = ''
    S3_ENDPOINT_URL = ''
    S3_BUCKET_NAME = ''
    MEDIA_BASE_URL = ''
    MAX_FILE_SIZE = 5242880
    MAX_TEXT_SIZE = 2345

    SMTP_SERVER = ''
    SMTP_PORT = 587
    SMTP_USER = ''
    SMTP_PSWD = ''

    API_DOMAIN = "https://service.altamino.top"
    SITE_DOMAIN = "http://altamino.top"

    PREFIX_INT = 19
    PREFIX = bytes.fromhex(str(PREFIX_INT))
    DEVICE_KEY = bytes.fromhex("E7309ECC0953C6FA60005B2765F99DBBC965C8E9")  
    SIG_KEY = bytes.fromhex("DFA5ED192DDA6E88A12FE12130DC6206B1251E44") 

    WS_ADMIN_KEY = ""
    WS_ADMIN_VERIFY = ""
    WS_ADMIN_DEV = "wss://ws1.altamino.top"
    WS_ADMIN_PROD = "ws://websocket:80"