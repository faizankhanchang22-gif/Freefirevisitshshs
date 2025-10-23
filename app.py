# api/index.py — fixed for Vercel 500s; Redis optional (falls back to memory). /remain needs no key.

import os
from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

# --- Optional Redis (for truly global quota) ---
USE_REDIS = False
r = None
try:
    import redis  # type: ignore
    REDIS_URL = os.getenv("REDIS_URL", "").strip()
    if REDIS_URL:
        r = redis.from_url(REDIS_URL, decode_responses=True, ssl=REDIS_URL.startswith("rediss://"))
        # quick probe; if this fails we fall back to in-memory
        r.ping()
        USE_REDIS = True
except Exception:
    USE_REDIS = False
# ------------------------------------------------

app = Flask(__name__)

# === Global rate limit (per API key) ===
KEY_LIMIT = 500
GLOBAL_KEY = "ArafatCodex"

# in-memory fallback store: key -> [used_count, last_reset_ts]
key_tracker = defaultdict(lambda: [0, time.time()])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_json(name):
    with open(os.path.join(BASE_DIR, name), "r") as f:
        return json.load(f)

def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()

def seconds_until_midnight_utc():
    now = datetime.now(timezone.utc)
    nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((nxt - now).total_seconds())

def usage_key(api_key: str) -> str:
    return f"usage:{api_key}:{datetime.now(timezone.utc):%Y%m%d}"

def get_used_count(api_key: str) -> int:
    if USE_REDIS and r is not None:
        return int(r.get(usage_key(api_key)) or 0)
    # in-memory fallback with daily reset
    today_midnight = get_today_midnight_timestamp()
    used, last_reset = key_tracker[api_key]
    if last_reset < today_midnight:
        key_tracker[api_key] = [0, time.time()]
        used = 0
    return int(used)

def consume_one(api_key: str) -> int:
    """Increment usage by 1 and return the new used count."""
    if USE_REDIS and r is not None:
        k = usage_key(api_key)
        pipe = r.pipeline()
        pipe.incr(k)
        pipe.expire(k, seconds_until_midnight_utc(), nx=True)
        used, _ = pipe.execute()
        return int(used)
    # in-memory fallback
    used = get_used_count(api_key) + 1
    key_tracker[api_key][0] = used
    key_tracker[api_key][1] = time.time()
    return used

def load_tokens(server_name):
    if server_name == "IND":
        return _load_json("token_ind.json")
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return _load_json("token_br.json")
    else:
        return _load_json("token_bd.json")

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv  = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as response:
            return response.status

async def send_multiple_requests(uid, server_name, url):
    protobuf_message = create_protobuf_message(uid, server_name)
    encrypted_uid = encrypt_message(protobuf_message)
    tokens = load_tokens(server_name)
    tasks = [send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url) for i in range(100)]
    return await asyncio.gather(*tasks)

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

def enc(uid):
    return encrypt_message(create_protobuf(uid))

def make_request(encrypted, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    resp = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
    binary = bytes.fromhex(resp.content.hex())
    try:
        obj = like_count_pb2.Info()
        obj.ParseFromString(binary)
        return obj
    except Exception:
        return None

# === Public remain endpoint (no key required) ===
@app.get("/remain")
def get_remain():
    used = get_used_count(GLOBAL_KEY)
    remaining = max(0, KEY_LIMIT - used)
    return jsonify({
        "limit": KEY_LIMIT,
        "used": used,
        "remaining": remaining,
        "remains": f"({remaining}/{KEY_LIMIT})"
    })

# === Main like endpoint ===
@app.get("/like")
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    api_key = request.args.get("key")

    if api_key != GLOBAL_KEY:
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    # Pre-check quota
    used_now = get_used_count(api_key)
    if used_now >= KEY_LIMIT:
        return jsonify({
            "error": "Daily request limit reached for this key.",
            "status": 429,
            "remains": f"(0/{KEY_LIMIT})"
        }), 429

    # Prepare requests
    tokens = load_tokens(server_name)
    token = tokens[0]["token"]
    encrypted = enc(uid)

    before = make_request(encrypted, server_name, token)
    js = json.loads(MessageToJson(before))
    before_like = int(js["AccountInfo"].get("Likes", 0))

    # Like endpoint per region
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        url = "https://clientbp.ggblueshark.com/LikeProfile"

    asyncio.run(send_multiple_requests(uid, server_name, url))

    after = make_request(encrypted, server_name, token)
    js = json.loads(MessageToJson(after))
    after_like = int(js["AccountInfo"]["Likes"])
    id_ = int(js["AccountInfo"]["UID"])
    name = str(js["AccountInfo"]["PlayerNickname"])

    like_given = after_like - before_like
    status = 1 if like_given != 0 else 2

    # Consume 1 quota for any valid result (1 or 2)
    new_used = consume_one(api_key)
    if new_used > KEY_LIMIT:
        # roll back if overflow (redis case)
        if USE_REDIS and r is not None:
            r.decr(usage_key(api_key))
        return jsonify({
            "error": "Daily request limit reached for this key.",
            "status": 429,
            "remains": f"(0/{KEY_LIMIT})"
        }), 429

    remaining = max(0, KEY_LIMIT - new_used)
    return jsonify({
        "LikesGivenByAPI": like_given,
        "LikesafterCommand": after_like,
        "LikesbeforeCommand": before_like,
        "PlayerNickname": name,
        "UID": id_,
        "status": status,
        "remains": f"({remaining}/{KEY_LIMIT})"
    })

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
