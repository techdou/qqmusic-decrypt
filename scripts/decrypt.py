#!/usr/bin/env python3
"""QQ Music encrypted audio decryptor: mflac/mgg/qmc* -> FLAC/OGG (optional MP3).

Self-contained, Python 3.10+ standard library only.
Crypto/tail-parsing logic consolidated from qmdec (upstream declares MIT in its
README): https://github.com/Sophomoresty/qmdec

Subcommands:
    decrypt <file-or-dir> [-o OUTDIR] [--mp3]   decrypt to standard format
    auth                                        refresh login cookie from
                                                running QQMusic.exe memory
    status                                      show login state & key cache

Login state lives in this skill's own .env (QQMUSIC_COOKIE / QQMUSIC_UIN).
The script loads it itself; never export/override from the shell.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = SKILL_DIR / ".env"
EKEY_CACHE_DIR = SKILL_DIR / "ekeys"

MUSICEX_MAGIC = b"musicex\x00"
QTAG_MAGIC = b"QTag"
STAG_MAGIC = b"STag"
SUPPORTED_EXTS = {
    ".mflac", ".mgg", ".mflac1", ".mflac2", ".mgg1", ".mgg2",
    ".qmc0", ".qmc2", ".qmc3", ".qmcflac", ".qmcogg",
}

# ---------------------------------------------------------------- login state

def load_env() -> dict:
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def save_env(cookie: str, uin: str) -> None:
    ENV_FILE.write_text(
        "# qqmusic-decrypt login state (auto-written by `decrypt.py auth`)\n"
        "# Contains the QQ Music session cookie. Keep local; do not commit or share.\n"
        f"QQMUSIC_COOKIE={cookie}\n"
        f"QQMUSIC_UIN={uin}\n",
        encoding="utf-8",
    )


def get_credentials() -> tuple[str, str]:
    """cookie, uin — skill .env first, then qmdec's config as compat fallback."""
    env = load_env()
    if env.get("QQMUSIC_COOKIE") and env.get("QQMUSIC_UIN"):
        return env["QQMUSIC_COOKIE"], env["QQMUSIC_UIN"]
    qmdec_cfg = Path.home() / ".config" / "qmdec" / "config.json"
    if qmdec_cfg.exists():
        try:
            cfg = json.loads(qmdec_cfg.read_text(encoding="utf-8"))
            if cfg.get("cookie") and cfg.get("uin"):
                return cfg["cookie"], str(cfg["uin"])
        except (json.JSONDecodeError, OSError):
            pass
    return "", ""

# ------------------------------------------------- auth: cookie from process

def extract_cookie_from_process() -> dict:
    """Scan QQMusic.exe memory for the session cookie. Native Windows only."""
    if sys.platform != "win32":
        return {"ok": False,
                "error": "auth requires native Windows Python (run outside WSL)."}

    import ctypes
    import ctypes.wintypes
    import re

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MAX_PATH = 260

    enum_buf = (ctypes.wintypes.DWORD * 4096)()
    cb_needed = ctypes.wintypes.DWORD()
    psapi.EnumProcesses(ctypes.byref(enum_buf), ctypes.sizeof(enum_buf),
                        ctypes.byref(cb_needed))

    qqmusic_pid = None
    for i in range(cb_needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)):
        pid = enum_buf[i]
        if pid == 0:
            continue
        h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        try:
            name_buf = (ctypes.c_char * MAX_PATH)()
            if psapi.GetModuleBaseNameA(h, None, name_buf, MAX_PATH):
                if name_buf.value == b"QQMusic.exe":
                    qqmusic_pid = pid
                    break
        finally:
            kernel32.CloseHandle(h)

    if qqmusic_pid is None:
        return {"ok": False,
                "error": "QQMusic.exe not running. Start QQ Music and log in first."}

    h_proc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                  False, qqmusic_pid)
    if not h_proc:
        return {"ok": False,
                "error": f"Cannot open QQMusic process (PID {qqmusic_pid}). "
                         "Try running as Administrator."}

    marker = b"qqmusic_key="
    try:
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.wintypes.DWORD),
                ("Protect", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
            ]

        MEM_COMMIT = 0x1000
        PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x60, 0x80}
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        bytes_read = ctypes.c_size_t()

        while addr < 0x7FFFFFFFFFFFFFFF:
            if kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            region_size = mbi.RegionSize or 0
            base_addr = mbi.BaseAddress or 0
            if region_size == 0:
                break
            if (mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE
                    and 0x1000 <= region_size <= 50 * 1024 * 1024):
                buf = (ctypes.c_char * region_size)()
                if kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(base_addr),
                                              buf, region_size, ctypes.byref(bytes_read)):
                    data = bytes(buf[: bytes_read.value])
                    pos = data.find(marker)
                    if pos >= 0:
                        raw = data[pos: pos + 512].split(b"\x00")[0].decode("utf-8", errors="ignore")
                        m = re.search(r"qqmusic_uin=(\d+)", raw)
                        if m:
                            return {"ok": True, "cookie": raw.strip(), "uin": m.group(1)}
            next_addr = base_addr + region_size
            if next_addr <= addr:
                break
            addr = next_addr

        return {"ok": False,
                "error": "Cookie not found in QQMusic memory. Is QQ Music logged in?"}
    finally:
        kernel32.CloseHandle(h_proc)

# ------------------------------------------------------------ tail parsing

def parse_file_tail(filepath: Path) -> dict | None:
    """musicex v1 (new client, key fetched via API) or QTag/STag (legacy, embedded)."""
    fsize = filepath.stat().st_size
    with open(filepath, "rb") as f:
        f.seek(-8, 2)
        tail8 = f.read(8)
        if tail8 == MUSICEX_MAGIC:
            return _parse_musicex(f, fsize)
        f.seek(-4, 2)
        tail4 = f.read(4)
        if tail4 in (QTAG_MAGIC, STAG_MAGIC):
            return _parse_legacy_tag(f, fsize, tail4)
    return None


def _parse_musicex(f, fsize: int) -> dict:
    f.seek(-16, 2)
    tail_size = struct.unpack("<I", f.read(4))[0]
    f.seek(-(16 + tail_size), 2)
    tail = f.read(tail_size)
    song_mid = tail[28:88].decode("utf-16-le").rstrip("\x00")
    filename = tail[88:184].decode("utf-16-le").rstrip("\x00")
    return {"format": "musicex", "song_mid": song_mid, "filename": filename,
            "audio_size": fsize - 16 - tail_size, "ekey": None}


def _parse_legacy_tag(f, fsize: int, tag_type: bytes) -> dict | None:
    """[audio][ekey_data][ekey_len:4B LE][QTag/STag]"""
    f.seek(-8, 2)
    ekey_len = struct.unpack("<I", f.read(4))[0]
    if ekey_len <= 0 or ekey_len > 4096:
        return None
    audio_size = fsize - 8 - ekey_len
    f.seek(audio_size, 0)
    ekey_data = f.read(ekey_len)
    if tag_type == QTAG_MAGIC:
        parts = ekey_data.split(b",")
        song_mid = parts[0].decode("utf-8", errors="ignore") if parts else ""
        ekey_b64 = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else ""
    else:
        song_mid, ekey_b64 = "", ekey_data.decode("utf-8", errors="ignore")
    return {"format": "legacy", "song_mid": song_mid, "filename": "",
            "audio_size": audio_size, "ekey": ekey_b64}

# ---------------------------------------------------------------- ekey

def resolve_ekey(meta: dict, cookie: str, uin: str) -> str | None:
    cache_key = meta.get("song_mid") or meta.get("filename", "")
    if not cache_key:
        return meta.get("ekey")
    if meta.get("ekey"):
        _cache_ekey(cache_key, meta["ekey"])
        return meta["ekey"]
    cached = _load_cached_ekey(cache_key)
    if cached:
        return cached
    if not cookie or not uin:
        return None
    file_mid = meta["filename"]
    for ext in (".mflac2", ".mflac1", ".mflac", ".mgg2", ".mgg1", ".mgg"):
        file_mid = file_mid.replace(ext, "")
    ekey = _fetch_ekey_from_api(meta["song_mid"], file_mid, cookie, uin)
    if ekey:
        _cache_ekey(cache_key, ekey)
    return ekey


def _cache_ekey(key: str, ekey: str) -> None:
    EKEY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (EKEY_CACHE_DIR / f"{key}.txt").write_text(ekey, encoding="utf-8")


def _load_cached_ekey(key: str) -> str | None:
    path = EKEY_CACHE_DIR / f"{key}.txt"
    if path.exists():
        content = path.read_text(encoding="utf-8").strip()
        if content:
            return content
    return None


def _fetch_ekey_from_api(song_mid: str, file_mid: str, cookie: str, uin: str) -> str | None:
    ext = ".mflac" if file_mid.startswith("F0") else ".mgg"
    request_data = {
        "comm": {
            "cv": 4747474, "ct": 24, "format": "json",
            "inCharset": "utf-8", "outCharset": "utf-8",
            "notice": 0, "platform": "yqq.json", "needNewCode": 1,
            "uin": int(uin), "g_tk_new_20200303": 5381, "g_tk": 5381,
        },
        "req_1": {
            "module": "vkey.GetVkeyServer",
            "method": "CgiGetVkey",
            "param": {
                "filename": [f"{file_mid}{ext}"],
                "guid": "10000",
                "songmid": [song_mid],
                "songtype": [0],
                "uin": uin,
                "loginflag": 1,
                "platform": "20",
            },
        },
    }
    url = "https://u.y.qq.com/cgi-bin/musicu.fcg"
    req = urllib.request.Request(url, data=json.dumps(request_data).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Cookie", cookie)
    req.add_header("User-Agent", "QQMusic/21")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    midurlinfo = result.get("req_1", {}).get("data", {}).get("midurlinfo", [])
    if midurlinfo:
        return midurlinfo[0].get("ekey", "") or None
    return None

# ------------------------------------------------- key derivation (TEA/EncV2)

ENCV2_PREFIX = b"QQMusic EncV2,Key:"
ENCV2_KEY1 = bytes((0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
                    0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28))
ENCV2_KEY2 = bytes((0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28, 0x23,
                    0x40, 0x21, 0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59))


def simple_make_key(salt: int, length: int) -> bytes:
    buf = bytearray(length)
    for i in range(length):
        buf[i] = int(abs(math.tan(float(salt) + float(i) * 0.1)) * 100.0) & 0xFF
    return bytes(buf)


def tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    v0, v1 = struct.unpack(">II", block)
    k0, k1, k2, k3 = struct.unpack(">4I", key)
    delta = 0x9E3779B9
    total = (delta * 16) & 0xFFFFFFFF
    for _ in range(16):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
    return struct.pack(">II", v0, v1)


def decrypt_tencent_tea(in_buf: bytes, key: bytes) -> bytes | None:
    if len(in_buf) % 8 != 0 or len(in_buf) < 16:
        return None
    dest_buf = bytearray(tea_decrypt_block(in_buf[:8], key))
    pad_len = dest_buf[0] & 0x07
    out_len = len(in_buf) - 1 - pad_len - 2 - 7
    if out_len <= 0:
        return None
    out = bytearray(out_len)
    iv_prev, iv_cur = bytes(8), in_buf[:8]
    in_pos, dest_idx = 8, 1 + pad_len

    def crypt_block():
        nonlocal iv_prev, iv_cur, in_pos, dest_buf, dest_idx
        iv_prev = iv_cur
        iv_cur = in_buf[in_pos: in_pos + 8]
        dest_buf = bytearray(dest_buf[i] ^ in_buf[in_pos + i] for i in range(8))
        dest_buf = bytearray(tea_decrypt_block(bytes(dest_buf), key))
        in_pos += 8
        dest_idx = 0

    i = 0
    while i < 2:
        if dest_idx < 8:
            dest_idx += 1
            i += 1
        else:
            crypt_block()
    out_pos = 0
    while out_pos < out_len:
        if dest_idx < 8:
            out[out_pos] = dest_buf[dest_idx] ^ iv_prev[dest_idx]
            dest_idx += 1
            out_pos += 1
        else:
            crypt_block()
    return bytes(out)


def _decrypt_encv2(raw: bytes) -> bytes | None:
    payload = raw[len(ENCV2_PREFIX):]
    dec1 = decrypt_tencent_tea(payload, ENCV2_KEY1)
    if dec1 is None:
        return None
    dec2 = decrypt_tencent_tea(dec1, ENCV2_KEY2)
    if dec2 is None:
        return None
    try:
        return base64.b64decode(dec2)
    except (ValueError, binascii.Error):
        return None


def derive_key(raw_key_dec: bytes) -> bytes | None:
    if raw_key_dec[: len(ENCV2_PREFIX)] == ENCV2_PREFIX:
        raw_key_dec = _decrypt_encv2(raw_key_dec)
        if raw_key_dec is None or len(raw_key_dec) < 16:
            return None
    simple_key = simple_make_key(106, 8)
    tea_key = bytearray(16)
    for i in range(8):
        tea_key[i * 2] = simple_key[i]
        tea_key[i * 2 + 1] = raw_key_dec[i]
    rs = decrypt_tencent_tea(raw_key_dec[8:], bytes(tea_key))
    if rs is None:
        return None
    return raw_key_dec[:8] + rs

# ---------------------------------------------------------------- ciphers

class MapCipher:
    """QMC2 map cipher (derived keys <= 300 bytes)."""

    def __init__(self, key: bytes):
        self.key = key
        self.n = len(key)

    @staticmethod
    def _rotate(value: int, bits: int) -> int:
        shift = (bits + 4) % 8
        return ((value << shift) | (value >> shift)) & 0xFF

    def _get_mask(self, offset: int) -> int:
        if self.n == 0:
            return 0
        if offset > 0x7FFF:
            offset %= 0x7FFF
        idx = (offset * offset + 71214) % self.n
        return self._rotate(self.key[idx], idx & 0x07)

    def decrypt(self, buf: bytearray, offset: int) -> None:
        for i in range(len(buf)):
            buf[i] ^= self._get_mask(offset + i)


class RC4Cipher:
    """QMC2 RC4 stream cipher (derived keys > 300 bytes)."""

    SEGMENT_SIZE = 5120
    FIRST_SEGMENT_SIZE = 128

    def __init__(self, key: bytes):
        self.key = key
        self.n = len(key)
        self.box = [i & 0xFF for i in range(self.n)]
        j = 0
        for i in range(self.n):
            j = (j + self.box[i] + key[i]) % self.n
            self.box[i], self.box[j] = self.box[j], self.box[i]
        self.hash = self._compute_hash()

    def _compute_hash(self) -> int:
        h = 1
        for v in self.key:
            if v == 0:
                continue
            # uint32 wraparound is part of the cipher state
            nh = (h * v) & 0xFFFFFFFF
            if nh == 0 or nh <= h:
                break
            h = nh
        return h

    def _get_segment_skip(self, id_val: int) -> int:
        seed = int(self.key[id_val % self.n])
        if seed == 0:
            return 0
        idx = int(float(self.hash) / float((id_val + 1) * seed) * 100.0)
        return idx % self.n

    def decrypt(self, buf: bytearray, offset: int) -> None:
        to_process = len(buf)
        processed = 0
        if offset < self.FIRST_SEGMENT_SIZE:
            block_size = min(to_process, self.FIRST_SEGMENT_SIZE - offset)
            self._enc_first_segment(buf, 0, block_size, offset)
            processed += block_size
            offset += block_size
            to_process -= block_size
            if to_process == 0:
                return
        if offset % self.SEGMENT_SIZE != 0:
            block_size = min(to_process, self.SEGMENT_SIZE - offset % self.SEGMENT_SIZE)
            self._enc_a_segment(buf, processed, block_size, offset)
            processed += block_size
            offset += block_size
            to_process -= block_size
            if to_process == 0:
                return
        while to_process > self.SEGMENT_SIZE:
            self._enc_a_segment(buf, processed, self.SEGMENT_SIZE, offset)
            processed += self.SEGMENT_SIZE
            offset += self.SEGMENT_SIZE
            to_process -= self.SEGMENT_SIZE
        if to_process > 0:
            self._enc_a_segment(buf, processed, to_process, offset)

    def _enc_first_segment(self, buf, buf_offset, length, stream_offset):
        for i in range(length):
            skip = self._get_segment_skip(stream_offset + i)
            buf[buf_offset + i] ^= self.key[skip]

    def _enc_a_segment(self, buf, buf_offset, length, stream_offset):
        box_copy = self.box.copy()
        j, k = 0, 0
        skip_len = ((stream_offset % self.SEGMENT_SIZE)
                    + self._get_segment_skip(stream_offset // self.SEGMENT_SIZE))
        for i in range(-skip_len, length):
            j = (j + 1) % self.n
            k = (box_copy[j] + k) % self.n
            box_copy[j], box_copy[k] = box_copy[k], box_copy[j]
            if i >= 0:
                idx = (box_copy[j] + box_copy[k]) % self.n
                buf[buf_offset + i] ^= box_copy[idx]

# ---------------------------------------------------------------- decrypt

def sniff_ext(data: bytes) -> str:
    if data[:4] == b"fLaC":
        return ".flac"
    if data[:4] == b"OggS":
        return ".ogg"
    if data[:3] == b"ID3" or (len(data) > 1 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
        return ".mp3"
    if data[4:8] == b"ftyp":
        return ".m4a"
    return ".bin"


def make_cipher(key: bytes):
    return RC4Cipher(key) if len(key) > 300 else MapCipher(key)


def decrypt_one(filepath: Path, output_dir: Path, cookie: str, uin: str,
                mp3: bool = False) -> dict:
    meta = parse_file_tail(filepath)
    if meta is None:
        return {"ok": False, "file": filepath.name,
                "error": "unknown file tail (no musicex/QTag/STag marker)"}

    ekey_b64 = resolve_ekey(meta, cookie, uin)
    if not ekey_b64:
        hint = ("no login state - run `decrypt.py auth` with QQ Music running"
                if not (cookie and uin)
                else "ekey empty - cookie may be expired, re-run `decrypt.py auth`")
        return {"ok": False, "file": filepath.name, "error": hint}

    try:
        raw_key = base64.b64decode(ekey_b64)
    except Exception:
        return {"ok": False, "file": filepath.name, "error": "invalid ekey encoding"}
    final_key = derive_key(raw_key)
    if final_key is None:
        return {"ok": False, "file": filepath.name, "error": "key derivation failed"}

    audio_size = meta["audio_size"]
    with open(filepath, "rb") as fin:
        preview = bytearray(fin.read(min(16, audio_size)))
    cipher = make_cipher(final_key)
    cipher.decrypt(preview, 0)
    ext = sniff_ext(bytes(preview))

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{filepath.stem}{ext}"

    with open(filepath, "rb") as fin, open(out_path, "wb") as fout:
        offset = 0
        while offset < audio_size:
            buf = bytearray(fin.read(min(51200, audio_size - offset)))
            cipher.decrypt(buf, offset)
            fout.write(buf)
            offset += len(buf)

    result = {"ok": True, "file": filepath.name, "output": str(out_path),
              "format": ext[1:]}
    if mp3:
        mp3_path = output_dir / f"{filepath.stem}.mp3"
        err = transcode_mp3(out_path, mp3_path)
        if err:
            result["mp3_error"] = err
        else:
            result["mp3"] = str(mp3_path)
    return result


def transcode_mp3(lossless_path: Path, mp3_path: Path) -> str | None:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return "ffmpeg not found on PATH (install ffmpeg or drop --mp3)"
    cmd = [ffmpeg, "-y", "-v", "error", "-i", str(lossless_path),
           "-map", "0:a", "-map", "0:v?", "-c:a", "libmp3lame", "-b:a", "320k",
           "-c:v", "copy", "-id3v2_version", "3", "-write_id3v1", "1", str(mp3_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        mp3_path.unlink(missing_ok=True)
        return (proc.stderr or "ffmpeg failed").strip()[:200]
    return None

# ---------------------------------------------------------------- cli

def cmd_auth(_args) -> None:
    result = extract_cookie_from_process()
    if result.get("ok"):
        save_env(result["cookie"], result["uin"])
        print(json.dumps({"ok": True, "uin": result["uin"], "env": str(ENV_FILE)}))
    else:
        print(json.dumps(result, ensure_ascii=True))
        sys.exit(1)


def cmd_status(_args) -> None:
    cookie, uin = get_credentials()
    env = load_env()
    source = ("skill .env" if env.get("QQMUSIC_COOKIE")
              else ("qmdec config" if cookie else "none"))
    cached = len(list(EKEY_CACHE_DIR.glob("*.txt"))) if EKEY_CACHE_DIR.exists() else 0
    print(json.dumps({"login_state": bool(cookie and uin), "uin": uin or "",
                      "source": source, "cookie_chars": len(cookie),
                      "cached_ekeys": cached}, ensure_ascii=True, indent=2))


def cmd_decrypt(args) -> None:
    cookie, uin = get_credentials()
    target = Path(args.input)
    output_dir = Path(args.output) if args.output else (target if target.is_dir() else target.parent)

    files: list[Path] = []
    if target.is_dir():
        for ext in SUPPORTED_EXTS:
            files.extend(target.glob(f"*{ext}"))
    elif target.is_file() and target.suffix.lower() in SUPPORTED_EXTS:
        files.append(target)
    else:
        print(json.dumps({"ok": False, "error": f"unsupported input: {target}"}, ensure_ascii=True))
        sys.exit(1)

    files = sorted(set(files))
    if not files:
        print(json.dumps({"ok": False, "error": "no encrypted files found"}, ensure_ascii=True))
        sys.exit(1)

    results, ok_count = [], 0
    for f in files:
        r = decrypt_one(f, output_dir, cookie, uin, mp3=args.mp3)
        results.append(r)
        if r["ok"]:
            ok_count += 1
            print(f"  [{ok_count}/{len(files)}] {f.name} -> {r['format']}"
                  + (f" + mp3" if r.get("mp3") else ""), file=sys.stderr)
        else:
            print(f"  [{ok_count}/{len(files)}] {f.name} -> FAIL: {r['error']}", file=sys.stderr)

    print(json.dumps({"ok": ok_count == len(files), "total": len(files),
                      "success": ok_count, "results": results},
                     ensure_ascii=True, indent=2))
    sys.exit(0 if ok_count == len(files) else 1)


def main() -> None:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decrypt", help="decrypt mflac/mgg/qmc* files")
    d.add_argument("input", help="encrypted file or directory")
    d.add_argument("-o", "--output", help="output directory (default: alongside source)")
    d.add_argument("--mp3", action="store_true",
                   help="also transcode to 320k MP3 (needs ffmpeg on PATH)")
    d.set_defaults(func=cmd_decrypt)
    a = sub.add_parser("auth", help="refresh login cookie from running QQMusic.exe")
    a.set_defaults(func=cmd_auth)
    s = sub.add_parser("status", help="show login state and cached ekeys")
    s.set_defaults(func=cmd_status)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
