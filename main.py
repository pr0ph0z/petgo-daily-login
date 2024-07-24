import requests
import json
import uuid
import hashlib
import base64
import time
import os
from urllib.parse import quote_plus
import py3rijndael
import gzip
import msgpack
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import binascii
from Crypto.Cipher import DES3
from datetime import datetime, timedelta, timezone
tz_utc_8 = timezone(timedelta(hours=8))

def get_ver_code(REGION):
    response = requests.get(f"https://raw.githubusercontent.com/O-Isaac/FGO-VerCode-extractor/{REGION}/VerCode.json").json()
    return response["appVer"], response["verCode"]

# Constants
REGION = os.environ.get("FATE_REGION", "JP")
APP_VER = get_ver_code(REGION)[0]
VER_CODE = get_ver_code(REGION)[1]
USER_AGENT = os.environ.get("USER_AGENT_SECRET_2", "Dalvik/2.1.0 (Linux; U; Android 9 Build/PQ3A.190605.09261202)")
DEVICE_INFO = os.environ.get("DEVICE_INFO_SECRET", "  / Android OS 9 / API-28 (PQ3A.190605.09261202 release-keys/3793265)")
SERVER_ADDR = "https://game.fate-go.jp"  if REGION == "JP" else "https://game.fate-go.us"


def GetNowTimeHour():
    return datetime.now(tz=tz_utc_8).hour


def GetNowTime():
    return datetime.now(tz=tz_utc_8)


def GetFormattedNowTime():
    return datetime.now(tz=tz_utc_8).strftime('%Y-%m-%d %H:%M:%S')


def GetTimeStamp():
    return (int)(datetime.now(tz=tz_utc_8).timestamp())


def TimeStampToString(timestamp):
    return datetime.fromtimestamp(timestamp)


def GetNowTimeFileName():
    return datetime.now(tz=tz_utc_8).strftime('%Y/%m/%d.log')

def get_time_stamp():
    return str(int(time.time()))

def get_asset_bundle(assetbundle):
    data = base64.b64decode(assetbundle)
    key = b'nn33CYId2J1ggv0bYDMbYuZ60m4GZt5P'  # NA key
    if REGION == "JP":
        key = b'W0Juh4cFJSYPkebJB9WpswNF51oa6Gm7'  # JP key
    iv = data[:32]
    array = data[32:]

    cipher = py3rijndael.RijndaelCbc(
        key,
        iv,
        py3rijndael.paddings.Pkcs7Padding(16),
        32
    )

    data = cipher.decrypt(array)
    gzip_data = gzip.decompress(data)
    data_unpacked = msgpack.unpackb(gzip_data)

    return data_unpacked

def get_folder_data(assetbundle):
    folder_name = assetbundle['folderName']
    folder_crc = binascii.crc32(folder_name.encode('utf8'))
    return folder_name, folder_crc

def get_latest_game_data():
    response = requests.get(f"{SERVER_ADDR}/gamedata/top?appVer={APP_VER}").json()
    data = response["response"][0]["success"]
    asset_bundle = get_asset_bundle(data['assetbundle'])
    folder_name, folder_crc = get_folder_data(asset_bundle)
    return {
        "data_ver": data['dataVer'],
        "date_ver": data['dateVer'],
        "asset_bundle": {
            "folderName": folder_name,
            "folderCrc": folder_crc
        }
    }

class ParameterBuilder:
    def __init__(self, uid, auth_key, secret_key):
        self.uid = uid
        self.auth_key = auth_key
        self.secret_key = secret_key
        self.content = ''
        self.parameter_list = []

    def add_parameter(self, key, value):
        self.parameter_list.append((key, value))

    def build(self):
        self.parameter_list.sort(key=lambda tup: tup[0])
        temp = ''
        for first, second in self.parameter_list:
            if temp:
                temp += '&'
                self.content += '&'
            escaped_key = quote_plus(first)
            if not second:
                temp += first + '='
                self.content += escaped_key + '='
            else:
                escaped_value = quote_plus(second)
                temp += first + '=' + second
                self.content += escaped_key + '=' + escaped_value

        temp += ':' + self.secret_key
        self.content += '&authCode=' + \
            quote_plus(base64.b64encode(
                hashlib.sha1(temp.encode('utf-8')).digest()).decode())

        return self.content

def top_login(user_id, auth_key, secret_key):
    game_data = get_latest_game_data()
    
    builder = ParameterBuilder(user_id, auth_key, secret_key)
    builder.add_parameter('appVer', APP_VER)
    builder.add_parameter('authKey', auth_key)
    builder.add_parameter('dataVer', str(game_data['data_ver']))
    builder.add_parameter('dateVer', str(game_data['date_ver']))
    builder.add_parameter('idempotencyKey', str(uuid.uuid4()))
    builder.add_parameter('lastAccessTime', get_time_stamp())
    builder.add_parameter('userId', user_id)
    builder.add_parameter('verCode', VER_CODE)
    if REGION == "NA":
        builder.add_parameter('country', '36')

    # Load private key
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())

    # Sign idempotency key
    idk = builder.parameter_list[4][1]
    input_string = f"{user_id}{idk}"
    signature = private_key.sign(
        input_string.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    idempotency_key_signature = base64.b64encode(signature).decode('utf-8')
    #print(f"Signature: {idempotency_key_signature}")

    # Add additional parameters
    last_access_time = builder.parameter_list[5][1]
    user_state = (-int(last_access_time) >> 2) ^ int(user_id) & game_data['asset_bundle']['folderCrc']

    builder.add_parameter('assetbundleFolder', game_data['asset_bundle']['folderName'])
    
    builder.add_parameter('deviceInfo', DEVICE_INFO)
    builder.add_parameter('isTerminalLogin', '1')
    builder.add_parameter('userState', str(user_state))
    if REGION == "JP":
        builder.add_parameter('idempotencyKeySignature', idempotency_key_signature)

    # Prepare request
    url = f'{SERVER_ADDR}/login/top?_userId={user_id}'
    data = builder.build()
    #print(f"Constructed Payload: {data}")  # Print the payload
    headers = {
        'User-Agent': USER_AGENT,
        'Accept-Encoding': "deflate, gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2022.3.28f1"
    }

    # Send request
    response = requests.post(url, data=data, headers=headers, verify=True)
    return response.json()


def decode_certificate(certificate):
    cert_byte = base64.b64decode(certificate)
    
    key = "b5nHjsMrqaeNliSs3jyOzgpD".encode('utf-8')
    iv = "wuD6keVr".encode('utf-8')
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    result = cipher.decrypt(cert_byte)
    
    # Find the end of the JSON data
    json_end = result.rfind(b'}') + 1
    json_data = result[:json_end].decode('utf-8')
    
    try:
        parsed_json = json.loads(json_data)
        user_id = parsed_json["userId"]
        auth_key = parsed_json["authKey"]
        secret_key = parsed_json["secretKey"]
        
        return user_id, auth_key, secret_key
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None, None, None
def login(cert):
    user_id, auth_key, secret_key = decode_certificate(cert)
    if user_id and auth_key and secret_key:
        data = top_login(user_id, auth_key, secret_key)
        name = data['cache']['replaced']['userGame'][0]['name']
        stone = data['cache']['replaced']['userGame'][0]['stone']
        lv = data['cache']['replaced']['userGame'][0]['lv']
        ticket = 0
        goldenfruit = 0
        silverfruit = 0
        bronzefruit = 0
        bluebronzesapling = 0
        bluebronzefruit = 0
        pureprism = 0
        sqf01 = 0
        holygrail = 0

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 4001:
                ticket = item['num']
                break
        
        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 100:
                goldenfruit = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 101:
                silverfruit = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 102:
                bronzefruit = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 103:
                bluebronzesapling = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 104:
                bluebronzefruit = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 46:
                pureprism = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 16:
                sqf01 = item['num']
                break

        for item in data['cache']['replaced']['userItem']:
            if item['itemId'] == 7999:
                holygrail = item['num']
                break
        
        login_days = data['cache']['updated']['userLogin'][0]['seqLoginCount']
        total_days = data['cache']['updated']['userLogin'][0]['totalLoginCount']
        fpids1 = data['cache']['replaced']['userGame'][0]['friendCode']
        act_max = data['cache']['replaced']['userGame'][0]['actMax']
        act_recover_at = data['cache']['replaced']['userGame'][0]['actRecoverAt']
        carryOverActPoint = data['cache']['replaced']['userGame'][0]['carryOverActPoint']
        serverTime = data['cache']['serverTime']
        ap_points = act_recover_at - serverTime
        remaining_ap = 0

        if ap_points > 0:
            lost_ap_point = (ap_points + 299) // 300
            if act_max >= lost_ap_point:
                remaining_ap_int = act_max - lost_ap_point
                remaining_ap = int(remaining_ap_int)
        else:
            remaining_ap = act_max + carryOverActPoint
        
        now_act = (act_max - (act_recover_at - GetTimeStamp()) / 300)

        add_fp = data['response'][0]['success']['addFriendPoint']
        total_fp = data['cache']['replaced']['tblUserGame'][0]['friendPoint']

        result = {
            "Name": name,
            "Level": lv,
            "Stone": stone,
            "Ticket": ticket,
            "Golden Fruit": goldenfruit,
            "Silver Fruit": silverfruit,
            "Bronze Fruit": bronzefruit,
            "Blue Bronze Sapling": bluebronzesapling,
            "Blue Bronze Fruit": bluebronzefruit,
            "Pure Prism": pureprism,
            "SQ Fragments": sqf01,
            "Holy Grail": holygrail,
            "Login Days": login_days,
            "Total Days": total_days,
            "Friend Code": fpids1,
            "Max Action Points": act_max,
            "Action Points Recovery Time": act_recover_at,
            "Carry Over Action Points": carryOverActPoint,
            "Server Time": serverTime,
            "Remaining Action Points": remaining_ap,
            "Current Action Points": now_act,
            "Additional Friend Points": add_fp,
            "Total Friend Points": total_fp
        }
        return result
    else:
        print("Failed to decode certificate.")
        return None

def main():
    #print("You can get the certificate from `Android/data/com.aniplex.fategrandorder/files/data/54cc790bf952ea710ed7e8be08049531`")
    your_certificate = os.environ.get("CERT")
    try_login = login(your_certificate)
    # print Name and Login Days
    print(f"Name: {try_login['Name']}")
    print(f"Login Days: {try_login['Login Days']}")

if __name__ == "__main__":
    main()