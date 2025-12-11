# filename: app_queue_flask_prod.py
import os
import re
import time
import base64
import random
import logging
import threading
import hashlib
from queue import Queue, Empty
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify # type: ignore
from flask_cors import CORS # type: ignore
import mysql.connector # type: ignore
from mysql.connector import pooling, errors as mysql_errors # type: ignore
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore

# -------------------- APP --------------------
app = Flask(__name__)
CORS(app)

# -------------------- DEFAULT CONFIG --------------------
DEFAULT_CONFIG = {
    "is_cache": "1",
    "async_audit": "1",
    "log_level": "INFO",
    "cache_ttl": "300",
    "config_refresh_interval": "3600",
    "pool_size": "32",
}

# -------------------- LOGGER --------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger_lock = threading.Lock()
def log_debug(step, msg): 
    with logger_lock: logging.debug(f"[{step}] {msg}")
def log_info(step, msg): 
    with logger_lock: logging.info(f"[{step}] {msg}")
def log_error(step, msg): 
    with logger_lock: logging.error(f"[{step}] {msg}")

# -------------------- MASTER KEYS --------------------
MASTER_KEYS = {
    "K01": bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    "K02": bytes.fromhex("a54ff53a6b1db8bf62a27db8228b9e47379b24b977b391a29fb1045db99f057e"),
    "K03": bytes.fromhex("4f3c2b1a0d1e9f8a7b6c5d4e3f2a190817263544332211009988776655443322")
}
for kid, key in MASTER_KEYS.items():
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError(f"MASTER_KEYS[{kid}] must be 32 bytes (hex 64 chars)")
def choose_master_key():
    key_id = random.choice(list(MASTER_KEYS.keys()))
    return key_id, MASTER_KEYS[key_id]

# -------------------- THREAD POOL & CACHE --------------------
executor = ThreadPoolExecutor(max_workers=20)
cache = {}
cache_meta = {}
cache_lock = threading.Lock()

# -------------------- DB POOL --------------------
dbconfig = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASS", "Srj@1304"),
    "database": os.environ.get("DB_NAME", "test")
}
POOL_SIZE = int(DEFAULT_CONFIG["pool_size"])
connection_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=POOL_SIZE, **dbconfig)

def safe_get_db_connection(retries=3, delay=0.02) -> Optional[mysql.connector.connection.MySQLConnection]:
    for attempt in range(retries):
        try:
            return connection_pool.get_connection()
        except mysql_errors.PoolError:
            if attempt == retries - 1: return None
            time.sleep(delay)
    return None

# -------------------- CONFIG --------------------
CONFIG = DEFAULT_CONFIG.copy()
config_lock = threading.Lock()

def load_configurations():
    conn = safe_get_db_connection()
    if conn is None:
        log_error("CONFIG", "DB pool exhausted while loading configurations")
        return
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT config_key, config_value FROM configurations")
        rows = cursor.fetchall()
        new_config = DEFAULT_CONFIG.copy()
        for r in rows:
            key = r.get('config_key')
            val = r.get('config_value')
            if key:
                new_config[key] = str(val) if val is not None else ""
        with config_lock:
            CONFIG.clear()
            CONFIG.update(new_config)
        level_name = CONFIG.get("log_level", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        logging.getLogger().setLevel(level)
        log_info("CONFIG", f"Loaded configurations: {CONFIG}")
    except Exception as e:
        log_error("CONFIG", f"Failed to load configurations: {e}")
    finally:
        try: cursor.close()
        except: pass
        try: conn.close()
        except: pass

def config_refresh_loop(interval_seconds: int = 3600):
    while True:
        time.sleep(interval_seconds)
        load_configurations()

# -------------------- UTILITIES --------------------
def sha256_key(value: str) -> str:
    return "pii::" + hashlib.sha256(value.encode()).hexdigest().upper()

def mask_mobile(mobile: str) -> str:
    digits = re.sub(r'\D', '', mobile)
    return digits[:3] + "****" + digits[-3:] if len(digits)>=6 else mobile

def mask_email(email: str) -> str:
    try: local, domain = email.split("@",1); return local[0]+"****"+local[-1]+"@"+domain if len(local)>2 else "*@"+domain
    except: return "***@***"

def mask_pan(pan: str) -> str: return "****" + pan[-4:] if len(pan)==10 else pan
def mask_aadhaar(aad: str) -> str: return "********" + re.sub(r'\D','',aad)[-4:] if len(re.sub(r'\D','',aad))==12 else aad
def mask_gstin(gst: str) -> str: return gst[:2]+"****"+gst[-4:] if len(gst)==15 else gst

def generate_dek() -> bytes:
    dek = os.urandom(32)
    log_debug("DEK", "Generated DEK")
    return dek

def wrap_dek_ecb(dek: bytes, master_key: bytes) -> str:
    cipher = AES.new(master_key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(dek,16))).decode()

def unwrap_dek_ecb(enc_dek: str, master_key: bytes) -> bytes:
    cipher = AES.new(master_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(enc_dek)),16)

def encrypt_data_with_dek(dek: bytes, plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = AES.new(dek, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(plaintext.encode(),16))).decode()

def decrypt_data_with_dek(dek: bytes, enc_data: str) -> str:
    raw = base64.b64decode(enc_data)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(dek, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct),16).decode()

# -------------------- CACHE --------------------
def cache_key(prefix: str, key: str) -> str: return f"{prefix}::{key}"
def cache_get(prefix: str, key: str):
    with config_lock:
        is_cache = CONFIG.get("is_cache","1")=="1"
        ttl = int(CONFIG.get("cache_ttl",300))
    if not is_cache: return None
    k = cache_key(prefix,key)
    with cache_lock:
        if k in cache:
            ts = cache_meta.get(k,0)
            if time.time()-ts < ttl:
                log_info("CACHE", f"HIT {k}")
                return cache[k]
            cache.pop(k,None)
            cache_meta.pop(k,None)
    return None
def cache_set(prefix: str, key: str, value):
    with config_lock:
        if CONFIG.get("is_cache","1")!="1": return
    k = cache_key(prefix,key)
    with cache_lock:
        cache[k]=value
        cache_meta[k]=time.time()
        log_info("CACHE","SET "+k)

# -------------------- AUTH --------------------
def get_token_from_db(token: str) -> Optional[str]:
    conn = safe_get_db_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_name FROM api_tokens WHERE token=%s AND is_active=1 LIMIT 1",(token,))
        row = cursor.fetchone()
        return row['user_name'] if row else None
    except Exception as e:
        log_error("AUTH", f"Token lookup error: {e}")
        return None
    finally:
        try: cursor.close()
        except: pass
        try: conn.close()
        except: pass

# -------------------- PII DETECTION --------------------
PAN_REGEX = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$', re.I)
AADHAAR_REGEX = re.compile(r'^\d{12}$')
GSTIN_REGEX = re.compile(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', re.I)
EMAIL_REGEX = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
MOBILE_DIGITS_ONLY = re.compile(r'^\+?\d{10,13}$')

def detect_pii_type_and_confidence(value: str):
    v = value.strip()
    if PAN_REGEX.match(v.replace(" ","").upper()): return "pan",0.98
    digits = re.sub(r'\D','',v)
    if AADHAAR_REGEX.match(digits): return "aadhaar",0.99
    if GSTIN_REGEX.match(v.replace(" ","").upper()): return "gst",0.98
    if EMAIL_REGEX.match(v): return "email",0.97
    if MOBILE_DIGITS_ONLY.match(v) or len(digits)==10: return "mobile",0.95
    return "address",0.3

def redact_value_by_type(value: str, pii_type: str) -> str:
    if pii_type=="email": return mask_email(value)
    if pii_type=="mobile": return mask_mobile(value)
    if pii_type=="pan": return mask_pan(value)
    if pii_type=="aadhaar": return mask_aadhaar(value)
    if pii_type=="gst": return mask_gstin(value)
    return value if len(value)<=40 else value[:20]+"..."

# -------------------- ENCRYPT QUEUE --------------------
encrypt_queue = Queue(maxsize=10000)

def log_detection_async(pii_key, redacted, pii_type, confidence, detected_from, related_id, user_name):
    conn2 = safe_get_db_connection()
    if not conn2: return
    try:
        cur2 = conn2.cursor()
        cur2.execute(
            "INSERT INTO pii_detection_log "
            "(pii_key, pii_redacted_value, pii_type, confidence_score, detected_from, related_record_id, requested_by, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())",
            (pii_key, redacted, pii_type, int(confidence*100), detected_from, related_id, user_name)
        )
        conn2.commit()
    except Exception as e:
        log_debug("DETECT_LOG", f"Async detection log failed: {e}")
    finally:
        try: cur2.close()
        except: pass
        try: conn2.close()
        except: pass

# -------------------- SERVICE ERROR & AUDIT --------------------
def log_service_error(api_name: str, error_message: str, raw_value: str = None, user_name: str = None):
    try:
        masked_value = redact_value_by_type(raw_value, detect_pii_type_and_confidence(raw_value)[0]) if raw_value else None
        conn = safe_get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO service_error_log (api_name, error_message, pii_value_masked, requested_by, created_at) "
                    "VALUES (%s,%s,%s,%s,NOW())",
                    (api_name, error_message[:1000], masked_value, user_name)
                )
                conn.commit()
            finally:
                cursor.close()
                conn.close()
        with logger_lock:
            logging.error(f"[SERVICE_ERROR] API:{api_name}, Error:{error_message}, User:{user_name}, MaskedValue:{masked_value}")
    except Exception as e:
        with logger_lock:
            logging.error(f"[SERVICE_ERROR][FAILSAFE] {e}")


def audit_log(user_name: str, pii_key: str, action: str):
    try:
        conn = safe_get_db_connection()
        if not conn: return
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO pii_audit_log (pii_key, action_type, requested_by, created_at) VALUES (%s,%s,%s,NOW())",
            (pii_key, action, user_name)
        )
        conn.commit()
    except Exception as e:
        log_debug("AUDIT_LOG", f"Failed: {e}")
    finally:
        try: cursor.close()
        except: pass
        try: conn.close()
        except: pass

# Encrypt worker code goes here — same as previous snippet with redacted-only insert

# -------------------- FLASK ENDPOINTS --------------------
# /encrypt, /decrypt/<pii_key>, /cache/clear, /cache/status, /config/reload
# Use same logic as previous worker snippet with masked/redacted everywhere


def encrypt_worker():
    while True:
        try:
            task = encrypt_queue.get(timeout=0.1)
        except Empty:
            continue

        raw_value, user_name, runtime_cfg, result_holder = task
        conn = safe_get_db_connection()
        if conn is None:
            encrypt_queue.put(task)
            time.sleep(0.01)
            continue

        try:
            cursor = conn.cursor(dictionary=True)
            pii_key = sha256_key(raw_value)
            detected_type, confidence = detect_pii_type_and_confidence(raw_value)
            redacted = redact_value_by_type(raw_value, detected_type)

            # check cache
            cached = cache_get("enc", raw_value) if runtime_cfg.get("is_cache", "1") == "1" else None
            if cached:
                result_holder.append({
                    "pii_key": cached,
                    "status": "already_exists",
                    "pii_type": detected_type,
                    "confidence": confidence,
                    "display_data": redacted
                })
                executor.submit(audit_log, user_name, cached, "encrypt")
                continue

            # check DB
            cursor.execute("SELECT id FROM pii_vault WHERE pii_key=%s LIMIT 1", (pii_key,))
            row = cursor.fetchone()
            if row:
                if runtime_cfg.get("is_cache", "1") == "1":
                    executor.submit(cache_set, "enc", raw_value, pii_key)
                    executor.submit(cache_set, "dec", pii_key, raw_value)
                result_holder.append({
                    "pii_key": pii_key,
                    "status": "already_exists",
                    "pii_type": detected_type,
                    "confidence": confidence,
                    "display_data": redacted
                })
                executor.submit(audit_log, user_name, pii_key, "encrypt")
                continue

            # generate DEK & encrypt
            dek = generate_dek()
            key_id, master_key = choose_master_key()
            encrypt_key = wrap_dek_ecb(dek, master_key)
            encrypt_value = encrypt_data_with_dek(dek, raw_value)

            cursor.execute(
                "INSERT INTO pii_vault (pii_key, pii_type, display_data, encrypt_data, encrypt_key, key_id) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (pii_key, detected_type, redacted, encrypt_value, encrypt_key, key_id)
            )
            conn.commit()
            new_id = cursor.lastrowid

            # set cache async
            if runtime_cfg.get("is_cache", "1") == "1":
                executor.submit(cache_set, "enc", raw_value, pii_key)
                executor.submit(cache_set, "dec", pii_key, raw_value)

            result_holder.append({
                "pii_key": pii_key,
                "status": "created",
                "key_id": key_id,
                "pii_type": detected_type,
                "confidence": confidence,
                "display_data": redacted
            })

            # async logging
            executor.submit(audit_log, user_name, pii_key, "encrypt")
            executor.submit(log_detection_async, raw_value, redacted, detected_type,
                            confidence, "encrypt", new_id, user_name)

        except Exception as e:
            log_service_error("encrypt", str(e), raw_value, user_name)
            result_holder.append({"pii_key": pii_key, "status": "error"})
        finally:
            try: cursor.close()
            except: pass
            try: conn.close()
            except: pass
        encrypt_queue.task_done()


@app.route("/encrypt", methods=["POST"])
def encrypt_api_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Missing payload"}), 400

    values = data.get("values")
    token = data.get("token")
    if not values or not isinstance(values, list):
        return jsonify({"status": "error", "message": "Provide 'values' as list"}), 400
    if not token:
        return jsonify({"status": "error", "message": "Missing API token"}), 401

    user_name = get_token_from_db(token)
    if not user_name:
        return jsonify({"status": "error", "message": "Invalid token"}), 401

    with config_lock:
        runtime_cfg = CONFIG.copy()

    results = []
    for val in values:
        result_holder = []
        encrypt_queue.put((val, user_name, runtime_cfg, result_holder))
        # wait for worker to complete
        while not result_holder:
            time.sleep(0.005)
        results.append(result_holder[0])

    return jsonify({"status": "success", "data": results}), 200


# -------------------- DECRYPT API --------------------
@app.route("/decrypt/<pii_key>", methods=["GET"])
def decrypt_api(pii_key):
    cached = cache_get("dec", pii_key)
    if cached:
        return jsonify({"status": "success", "pii_key": pii_key, "value": cached}), 200

    conn = safe_get_db_connection()
    if conn is None:
        return jsonify({"status": "error", "message": "DB busy"}), 503

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT encrypt_data, encrypt_key, key_id FROM pii_vault WHERE pii_key=%s LIMIT 1", (pii_key,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Not found"}), 404

        key_id = row["key_id"]
        master_key = MASTER_KEYS.get(key_id)
        dek = unwrap_dek_ecb(row["encrypt_key"], master_key)
        value = decrypt_data_with_dek(dek, row["encrypt_data"])

        executor.submit(cache_set, "dec", pii_key, value)
        return jsonify({"status": "success", "pii_key": pii_key, "value": value}), 200
    except Exception as e:
        log_service_error("decrypt", str(e), pii_key)
        return jsonify({"status": "error", "message": "Internal error"}), 500
    finally:
        try: cursor.close()
        except: pass
        try: conn.close()
        except: pass


# -------------------- CACHE CONTROL --------------------
@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    with cache_lock:
        cache.clear()
        cache_meta.clear()
    return jsonify({"status": "success", "message": "Cache cleared"})


@app.route("/cache/status", methods=["GET"])
def cache_status():
    with cache_lock:
        return jsonify({
            "cache_items_count": len(cache),
            "cache_meta_count": len(cache_meta),
            "keys": list(cache.keys())[:50]
        })


# -------------------- CONFIG CONTROL --------------------
@app.route("/config/reload", methods=["GET"])
def reload_config():
    load_configurations()
    with config_lock:
        current_config = CONFIG.copy()
    return jsonify({
        "status": "success",
        "message": "Configuration reloaded",
        "config": current_config
    })


# -------------------- WORKER START --------------------
def start_workers(count: int = 5):
    for _ in range(count):
        t = threading.Thread(target=encrypt_worker, daemon=True)
        t.start()


# -------------------- MAIN --------------------
if __name__ == "__main__":
    load_configurations()
    threading.Thread(target=config_refresh_loop, args=(int(CONFIG.get("config_refresh_interval", 3600)),), daemon=True).start()
    start_workers(count=int(CONFIG.get("worker_count", 10)))
    app.run(host="0.0.0.0", port=5000, debug=False)
