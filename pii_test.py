# ======================================================
# app_queue_flask_prod.py  (FINAL – FULLY PATCHED)
# ======================================================

import os
import re
import time
import json
import base64
import random
import hashlib
import logging
import threading
from queue import Queue, Empty
from collections import deque
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify
from flask_cors import CORS

import mysql.connector
from mysql.connector import pooling, errors as mysql_errors

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ======================================================
# APP
# ======================================================
app = Flask(__name__)
CORS(app)

# ======================================================
# DEFAULT CONFIG (DB OVERRIDES ONLY IF PRESENT)
# ======================================================
DEFAULT_CONFIG = {
    "is_cache": "1",
    "async_audit": "1",
    "encrypt_async_mode": "1",
    "cache_ttl": "300",
    "token_cache_ttl": "600",
    "config_refresh_interval": "3600",
    "pool_read": "32",
    "pool_write": "32",
    "worker_count": "40",
    "log_level": "INFO",
}

CONFIG = DEFAULT_CONFIG.copy()
config_lock = threading.Lock()

# ======================================================
# LOGGER (THREAD SAFE)
# ======================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger_lock = threading.Lock()

def log_debug(step, msg):
    with logger_lock:
        logging.debug(f"[{step}] {msg}")

def log_info(step, msg):
    with logger_lock:
        logging.info(f"[{step}] {msg}")

def log_error(step, msg):
    with logger_lock:
        logging.error(f"[{step}] {msg}")

# ======================================================
# METRICS
# ======================================================
START_TS = time.time()
METRICS = {
    "encrypt_requests": 0,
    "encrypt_success": 0,
    "encrypt_failure": 0,
    "decrypt_requests": 0,
    "decrypt_success": 0,
    "decrypt_failure": 0,
    "auth_failures": 0,
    "cache_hit": 0,
    "cache_miss": 0,
    "write_pool_exhausted": 0,
}
LATENCY = {
    "encrypt": deque(maxlen=20000),
    "decrypt": deque(maxlen=20000),
}
MET_LOCK = threading.Lock()

def inc_metric(k):
    with MET_LOCK:
        METRICS[k] += 1

def add_latency(k, start_ts):
    with MET_LOCK:
        LATENCY[k].append((time.time() - start_ts) * 1000)

# ======================================================
# MASTER KEYS (DO NOT REMOVE OLD KEYS)
# ======================================================
MASTER_KEYS = {
    "K01": bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "K02": bytes.fromhex(
        "a54ff53a6b1db8bf62a27db8228b9e47379b24b977b391a29fb1045db99f057e"
    ),
    "K03": bytes.fromhex(
        "4f3c2b1a0d1e9f8a7b6c5d4e3f2a190817263544332211009988776655443322"
    ),
}

def choose_master_key():
    kid = random.choice(list(MASTER_KEYS.keys()))
    return kid, MASTER_KEYS[kid]

# ======================================================
# DB POOLS
# ======================================================
dbconf = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASS", "Srj@1304"),
    "database": os.getenv("DB_NAME", "test"),
}

READ_POOL = pooling.MySQLConnectionPool(
    pool_name="read_pool",
    pool_size=int(DEFAULT_CONFIG["pool_read"]),
    **dbconf,
)

WRITE_POOL = pooling.MySQLConnectionPool(
    pool_name="write_pool",
    pool_size=int(DEFAULT_CONFIG["pool_write"]),
    **dbconf,
)

# 🔒 WRITE SEMAPHORE (PATCH)
WRITE_SEM = threading.Semaphore(int(DEFAULT_CONFIG["pool_write"]))

def get_read_conn():
    try:
        return READ_POOL.get_connection()
    except mysql_errors.PoolError as e:
        log_error("READ_POOL", str(e))
        return None

def get_write_conn():
    acquired = WRITE_SEM.acquire(blocking=False)
    if not acquired:
        inc_metric("write_pool_exhausted")
        return None, False
    try:
        conn = WRITE_POOL.get_connection()
        return conn, True
    except mysql_errors.PoolError as e:
        WRITE_SEM.release()
        log_error("WRITE_POOL", str(e))
        return None, False


def release_write_conn(conn, owned):
    if not owned:
        return
    try:
        if conn:
            conn.close()
    finally:
        WRITE_SEM.release()


# ======================================================
# CONFIG LOADER (UNCHANGED BEHAVIOR)
# ======================================================
def load_configurations():
    conn = get_read_conn()
    if not conn:
        log_error("CONFIG", "DB unavailable, using defaults")
        return
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT config_key, config_value FROM configurations")
        rows = cur.fetchall()
        new_cfg = DEFAULT_CONFIG.copy()
        for r in rows:
            k, v = r["config_key"], r["config_value"]
            if k in DEFAULT_CONFIG and v not in (None, "", "NULL"):
                new_cfg[k] = str(v)
        with config_lock:
            CONFIG.clear()
            CONFIG.update(new_cfg)
        logging.getLogger().setLevel(
            getattr(logging, CONFIG.get("log_level", "INFO"), logging.INFO)
        )
        log_info("CONFIG", f"Loaded config: {CONFIG}")
    finally:
        cur.close()
        conn.close()

def config_refresh_loop():
    while True:
        time.sleep(int(CONFIG.get("config_refresh_interval", 3600)))
        load_configurations()

# ======================================================
# TOKEN CACHE (UNCHANGED)
# ======================================================
TOKEN_CACHE = {}
TOKEN_META = {}
TOKEN_LOCK = threading.Lock()

def get_user_from_token(token: str) -> Optional[str]:
    if not token:
        return None
    now = time.time()
    with TOKEN_LOCK:
        if token in TOKEN_CACHE and now - TOKEN_META[token] < int(CONFIG["token_cache_ttl"]):
            return TOKEN_CACHE[token]
    conn = get_read_conn()
    if not conn:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT user_name FROM api_tokens WHERE token=%s AND is_active=1 LIMIT 1",
            (token,),
        )
        row = cur.fetchone()
        if row:
            with TOKEN_LOCK:
                TOKEN_CACHE[token] = row["user_name"]
                TOKEN_META[token] = now
            return row["user_name"]
        return None
    finally:
        cur.close()
        conn.close()

# ======================================================
# CACHE (UNCHANGED)
# ======================================================
CACHE = {}
CACHE_META = {}
CACHE_LOCK = threading.Lock()

def cache_get(prefix, key):
    if CONFIG["is_cache"] != "1":
        return None
    ck = f"{prefix}::{key}"
    with CACHE_LOCK:
        if ck in CACHE and time.time() - CACHE_META[ck] < int(CONFIG["cache_ttl"]):
            inc_metric("cache_hit")
            return CACHE[ck]
    inc_metric("cache_miss")
    return None

def cache_set(prefix, key, value):
    with CACHE_LOCK:
        CACHE[f"{prefix}::{key}"] = value
        CACHE_META[f"{prefix}::{key}"] = time.time()

# ======================================================
# CRYPTO (UNCHANGED)
# ======================================================
def sha256_key(v):
    return "pii::" + hashlib.sha256(v.encode()).hexdigest().upper()

def encrypt_value(v):
    dek = os.urandom(32)
    iv = os.urandom(16)
    ct = AES.new(dek, AES.MODE_CBC, iv).encrypt(pad(v.encode(), 16))
    kid, mk = choose_master_key()
    enc_key = AES.new(mk, AES.MODE_ECB).encrypt(pad(dek, 16))
    return kid, base64.b64encode(iv + ct).decode(), base64.b64encode(enc_key).decode()

def decrypt_value(enc, enc_key, kid):
    mk = MASTER_KEYS.get(kid)
    if not mk:
        raise Exception(f"Missing master key {kid}")
    dek = unpad(AES.new(mk, AES.MODE_ECB).decrypt(base64.b64decode(enc_key)), 16)
    raw = base64.b64decode(enc)
    return unpad(AES.new(dek, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode()

# ======================================================
# FULL PII DETECTION (UNCHANGED)
# ======================================================
PAN_REGEX = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$', re.I)
AADHAAR_REGEX = re.compile(r'^\d{12}$')
GSTIN_REGEX = re.compile(
    r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', re.I
)
EMAIL_REGEX = re.compile(
    r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'
)
MOBILE_REGEX = re.compile(r'^\+?\d{10,13}$')

def detect_pii_type_and_confidence(v):
    d = re.sub(r"\D", "", v)
    if PAN_REGEX.match(v): return "pan", 0.98
    if AADHAAR_REGEX.match(d): return "aadhaar", 0.99
    if GSTIN_REGEX.match(v): return "gst", 0.98
    if EMAIL_REGEX.match(v): return "email", 0.97
    if MOBILE_REGEX.match(v) or len(d) == 10: return "mobile", 0.95
    return "address", 0.30

def redact_value_by_type(v, t):
    if t == "email":
        l, d = v.split("@", 1)
        return l[0] + "****" + l[-1] + "@" + d
    if t == "mobile":
        d = re.sub(r"\D", "", v)
        return d[:3] + "****" + d[-3:]
    if t == "pan":
        return "****" + v[-4:]
    if t == "aadhaar":
        return "********" + re.sub(r"\D", "", v)[-4:]
    if t == "gst":
        return v[:2] + "****" + v[-4:]
    return v[:20] + "..." if len(v) > 40 else v

# ======================================================
# ASYNC BUFFERS
# ======================================================
AUDIT_BUF = []
DETECT_BUF = []
AUDIT_LOCK = threading.Lock()
DETECT_LOCK = threading.Lock()

def audit_flusher():
    global AUDIT_BUF
    while True:
        time.sleep(0.1 + random.uniform(0, 0.1))
        with AUDIT_LOCK:
            batch = AUDIT_BUF[:100]
            AUDIT_BUF[:100] = []
        if not batch:
            continue
        conn = get_write_conn()
        if not conn:
            with AUDIT_LOCK:
                AUDIT_BUF = batch + AUDIT_BUF
            continue
        try:
            cur = conn.cursor()
            cur.executemany(
                "INSERT INTO audit_logs "
                "(table_name, record_id, action, new_data, changed_by) "
                "VALUES (%s,%s,'INSERT',%s,%s)",
                batch,
            )
            conn.commit()
        finally:
            cur.close()
            release_write_conn(conn)

def detect_flusher():
    global DETECT_BUF
    while True:
        time.sleep(0.2 + random.uniform(0, 0.2))

        with DETECT_LOCK:
            batch = DETECT_BUF[:100]
            DETECT_BUF[:100] = []

        if not batch:
            continue

        conn = None
        cur = None
        owned = False

        try:
            conn, owned = get_write_conn()
            if not conn:
                raise Exception("WRITE pool unavailable")

            cur = conn.cursor()
            cur.executemany(
                "INSERT INTO pii_detection_log "
                "(pii_key,pii_redacted_value,pii_type,confidence_score,"
                "detected_from,related_record_id,requested_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                batch,
            )
            conn.commit()

        except Exception as e:
            log_error("DETECT_FLUSH", str(e))
            with DETECT_LOCK:
                DETECT_BUF = batch + DETECT_BUF

        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            release_write_conn(conn, owned)


# ======================================================
# WORKER
# ======================================================
encrypt_queue = Queue(maxsize=10000)

def encrypt_worker():
    while True:
        try:
            raw, user, holder = encrypt_queue.get(timeout=0.1)
        except Empty:
            continue
        try:
            pk = sha256_key(raw)
            cached = cache_get("enc", raw)
            if cached:
                holder.append({"pii_key": cached, "status": "already_exists"})
                continue

            t, c = detect_pii_type_and_confidence(raw)
            red = redact_value_by_type(raw, t)
            kid, enc, enc_key = encrypt_value(raw)

            conn,owned = get_write_conn()
            if not conn:
                raise Exception("WRITE pool exhausted")

            cur = conn.cursor()
            cur.execute(
                "INSERT IGNORE INTO pii_vault "
                "(pii_key,pii_type,display_data,encrypt_data,encrypt_key,key_id) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (pk, t, red, enc, enc_key, kid),
            )
            conn.commit()

            if cur.rowcount == 1:
                rid = cur.lastrowid
                with AUDIT_LOCK:
                    AUDIT_BUF.append(("pii_vault", rid, json.dumps({"pii_key": pk}), user))
                with DETECT_LOCK:
                    DETECT_BUF.append((pk, red, t, int(c * 100), "encrypt", rid, user))

            cache_set("enc", raw, pk)
            cache_set("dec", pk, raw)
            holder.append({"pii_key": pk, "status": "success"})
            inc_metric("encrypt_success")
        except Exception as e:
            inc_metric("encrypt_failure")
            holder.append({"status": "error", "error": str(e)})
        finally:
         if 'cur' in locals():  
          try:
            cur.close()
          except:
           pass
        release_write_conn(conn, owned)
        encrypt_queue.task_done()



        # finally:
        #     if 'cur' in locals():
        #         cur.close()
        #     if 'conn' in locals() and conn:
        #         release_write_conn(conn)
        #     encrypt_queue.task_done()

# ======================================================
# APIs (ALL PRESERVED)
# ======================================================
@app.route("/encrypt", methods=["POST"])
def encrypt_api():
    start = time.time()
    inc_metric("encrypt_requests")
    data = request.get_json(silent=True) or {}
    user = get_user_from_token(data.get("token"))
    if not user:
        inc_metric("auth_failures")
        return jsonify({"status": "unauthorized"}), 401

    results = []
    for v in data.get("values", []):
        holder = []
        encrypt_queue.put((v, user, holder))
        while not holder:
            time.sleep(0.001)
        results.append(holder[0])

    add_latency("encrypt", start)
    return jsonify({"status": "success", "data": results})

@app.route("/decrypt/<pii_key>")
def decrypt_api(pii_key):
    start = time.time()
    inc_metric("decrypt_requests")
    user = get_user_from_token(request.headers.get("X-API-Token"))
    if not user:
        inc_metric("auth_failures")
        return jsonify({"status": "unauthorized"}), 401

    cached = cache_get("dec", pii_key)
    if cached:
        inc_metric("decrypt_success")
        add_latency("decrypt", start)
        return jsonify({"value": cached})

    conn = get_read_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT encrypt_data,encrypt_key,key_id FROM pii_vault WHERE pii_key=%s",
        (pii_key,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        inc_metric("decrypt_failure")
        return jsonify({"status": "not_found"}), 404

    val = decrypt_value(row["encrypt_data"], row["encrypt_key"], row["key_id"])
    cache_set("dec", pii_key, val)
    inc_metric("decrypt_success")
    add_latency("decrypt", start)
    return jsonify({"value": val})

@app.route("/cache/status")
def cache_status():
    with CACHE_LOCK:
        return jsonify({
            "cache_items_count": len(CACHE),
            "keys": list(CACHE.keys())[:50],
        })

@app.route("/cache/clear", methods=["POST"])
def cache_clear():
    with CACHE_LOCK:
        CACHE.clear()
        CACHE_META.clear()
    return jsonify({"status": "success"})

@app.route("/config/reload")
def config_reload():
    load_configurations()
    return jsonify({"status": "success", "config": CONFIG})

@app.route("/metrics")
def metrics():
    with MET_LOCK:
        return jsonify({
            "uptime_sec": int(time.time() - START_TS),
            "metrics": METRICS,
            "queue_depth": encrypt_queue.qsize(),
            "workers": int(CONFIG["worker_count"]),
        })

# ======================================================
# STARTUP
# ======================================================
if __name__ == "__main__":
    load_configurations()
    threading.Thread(target=config_refresh_loop, daemon=True).start()
    for _ in range(int(CONFIG["worker_count"])):
        threading.Thread(target=encrypt_worker, daemon=True).start()
    threading.Thread(target=audit_flusher, daemon=True).start()
    threading.Thread(target=detect_flusher, daemon=True).start()
    log_info("SERVICE", "PII Vault started (FULL, SAFE, BACKPRESSURE-AWARE)")
    app.run(host="0.0.0.0", port=5000, debug=True)
