# How it works — QQ Music qmc-family encryption

Read this only when debugging a decryption failure. Normal operation just
runs `scripts/decrypt.py` per the SKILL.md runbook.

## File layout

Encrypted file = `[encrypted audio][tail]`. Three tail generations exist:

| Tail | Generation | Key location |
|---|---|---|
| `musicex\0` (8-byte magic at EOF) | New PC client (2023+) | **Not in the file** — fetched from API by `song_mid` |
| `QTag` | Legacy | Embedded: `songmid,ekey` + 4-byte LE length before magic |
| `STag` | Legacy | Embedded: raw base64 ekey + 4-byte LE length before magic |

There is also an oldest generation (key derived from the file ID in the
filename, e.g. `song[616962].mflac`) — unsupported by this skill; such files
have no tail marker at all.

### musicex tail structure (from EOF backwards)

```
[audio][tail block: 192+ bytes][u32 tail_size][u32 = 1]["musicex\0"]
```

Inside the tail block: bytes 28–88 = `song_mid` (UTF-16LE), bytes 88–184 =
original filename like `F0M0001GnrUK1KXQqe.mflac` (UTF-16LE). The filename
prefix decides the API request extension: `F0…` → `.mflac`, otherwise `.mgg`.
`audio_size = filesize - 16 - tail_size`.

## ekey acquisition (musicex files)

1. Cache: `ekeys/<song_mid>.txt` (never expires).
2. API `POST https://u.y.qq.com/cgi-bin/musicu.fcg` with module
   `vkey.GetVkeyServer` / method `CgiGetVkey`, sending the account cookie
   (from `.env`) and `songmid` + `filename`. Response field
   `req_1.data.midurlinfo[0].ekey` is the key. Empty ekey with a valid cookie
   means the account lacks rights for the song.
3. Cookie source: `auth` scans `QQMusic.exe` process memory for the string
   `qqmusic_key=` (Win32 `ReadProcessMemory` over committed readable regions).

## Key derivation

ekey (base64, ~300–700 chars) → decode:

1. If it starts with `QQMusic EncV2,Key:` → strip prefix, decrypt twice with
   Tencent TEA (fixed keys `ENCV2_KEY1`, `ENCV2_KEY2`), base64-decode again.
2. Build a 16-byte TEA key: interleave `simple_make_key(106, 8)` (tan-based
   salt table) with the first 8 bytes of the key.
3. TEA-decrypt the rest; final key = `first 8 bytes || decrypted rest`.

## Stream decryption (QMC2)

Cipher choice by derived key length:

- **≤ 300 bytes → MapCipher**: XOR mask = `rotate(key[(i*i + 71214) % n], idx & 7)`
  where `i` is the reduced stream offset (`i > 0x7FFF` → `i %= 0x7FFF`) and
  `rotate` is the historical byte-shift expression, not a normal ROL.
- **> 300 bytes → segmented RC4**: key-scheduled S-box; first 128 bytes of the
  stream use a per-byte skip formula, then 5120-byte segments each restart
  from a copied box with `skip = (offset % 5120) + segment_skip(seg_id)`.
  `segment_skip = (hash / ((seg_id+1) * seed) * 100) % n`; `hash` is a uint32
  product accumulator over nonzero key bytes (wraparound is part of the state).

Output format is sniffed from the decrypted first 16 bytes:
`fLaC`→flac, `OggS`→ogg, `ID3`/MPEG sync→mp3, `ftyp`→m4a, else `.bin`.

## Source

Algorithms consolidated from qmdec (MIT):
https://github.com/Sophomoresty/qmdec — see its upstream for the original
module layout (`musicex.py`, `crypto.py`, `map_cipher.py`, `rc4.py`).
