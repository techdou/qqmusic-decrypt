---
name: qqmusic-decrypt
description: Decrypt QQ Music exclusive encrypted audio into standard formats — .mflac/.mflac1/.mflac2/.mgg/.mgg1/.mgg2/.qmcflac/.qmc0/.qmc2/.qmc3/.qmcogg to FLAC/OGG (lossless unwrap) or 320k MP3. Use whenever the user mentions QQ音乐专属格式/加密文件, mflac, mgg, qmcflac, 解密/解锁/转换QQ音乐歌曲, VIP 下载的歌其他播放器打不开, 转成通用格式, or hands over any local qmc-family file — even if they never say "decrypt" and just ask why a downloaded song won't play. New-format files (key not stored in the file) are handled automatically using the account login state bundled with this skill. NOT for downloading songs from QQ Music, NetEase .ncm, Kugou .kgm, or other platforms' DRM.
compatibility: Python 3.10+ standard library only. `auth` and first-time ekey fetch require native Windows Python with the QQ Music desktop client running and logged in (VIP). Each song's ekey is then cached forever (offline). `--mp3` requires ffmpeg on PATH. Pure-Python decrypt ≈15s per 30MB.
metadata:
  version: "1.1.0"
---

# QQ Music Decrypt

Unwrap locally available QQ Music encrypted audio (VIP downloads) into files
any player can open. One stdlib-only script does everything; the account
login state ships with this skill in `.env`, so decryption usually works with
zero setup.

## Scope

- **In**: local `qmc`-family files — `.mflac .mflac1 .mflac2 .mgg .mgg1 .mgg2
  .qmcflac .qmc0 .qmc2 .qmc3 .qmcogg`. Single file or whole directory.
- **Out**: FLAC/OGG (bit-exact unwrap, not a re-encode); optional 320k MP3.
- **Not for**: downloading new songs, NetEase `.ncm`, Kugou `.kgm/.kga`,
  anything that isn't a qmc-family file.

## Runbook

Script path (adjust `<skills-dir>` to your skill install root): `<skills-dir>/qqmusic-decrypt/scripts/decrypt.py`

1. Run `status` first. If `login_state: true`, skip to step 3 — decrypting
   works immediately.
2. If login state is missing/expired, run `auth` (requires QQ Music desktop
   running and logged in; the script extracts the cookie itself and writes it
   back to `.env`). Never ask the user to paste a cookie.
3. Decrypt:

```bash
# single file -> FLAC lands next to the source
python "$SKILL/scripts/decrypt.py" decrypt "歌手 - 歌名.mflac"

# whole directory, separate output dir, also 320k MP3 (ffmpeg)
python "$SKILL/scripts/decrypt.py" decrypt ~/Music/VipSongsDownload -o ~/Music/Decoded --mp3
```

4. Read the final JSON summary on stdout and report per-file outcomes to the
   user (paths + format). Progress lines go to stderr — ignore them in the
   report.

## Failure routing

| Script says | Cause | Do this |
|---|---|---|
| `no login state - run auth` | `.env` empty | run `auth`, then retry decrypt |
| `QQMusic.exe not running` | client closed | ask the user to open QQ Music and log in, then `auth` |
| `cookie may be expired` | old cookie, ekey came back empty | re-run `auth`, then retry |
| ekey still empty after fresh auth | account lacks rights for this song | stop; tell the user this song needs VIP/purchase — decryption cannot succeed |
| `unknown file tail` | not a qmc-family file | do not retry; tell the user the format is unsupported |
| output ext is `.bin` | decrypted header unrecognized | report the path to the user; don't delete the file |
| `ffmpeg not found` with `--mp3` | no ffmpeg on PATH | keep the lossless output, tell the user MP3 was skipped |

## Output contract

Progress → stderr; one JSON summary → stdout; exit code 0 = all files
succeeded. Success and failure look like this:

```json
{"ok": true, "total": 1, "success": 1, "results": [
  {"ok": true, "file": "陶喆 - 蝴蝶.mflac",
   "output": "C:\\Music\\陶喆 - 蝴蝶.flac", "format": "flac",
   "mp3": "C:\\Music\\陶喆 - 蝴蝶.mp3"}]}

{"ok": false, "total": 2, "success": 1, "results": [
  {"ok": true, "file": "a.mflac", "output": "C:\\Music\\a.flac", "format": "flac"},
  {"ok": false, "file": "b.mflac", "error": "ekey empty - cookie may be expired, re-run `decrypt.py auth`"}]}
```

**Never** print or log the cookie or ekey values from `.env`/`ekeys/` — they
are live account credentials. Report only file paths and statuses.

## Login state (`.env`)

`QQMUSIC_COOKIE` / `QQMUSIC_UIN` in this skill's `.env` are the authoritative
credential source. The script loads its own `.env` — never `export` a QQ Music
cookie into the shell, and never write credentials anywhere else. `auth`
refreshes the file; a qmdec install's `~/.config/qmdec/config.json` is read as
a fallback if `.env` is empty.

## Notes

- Output is a lossless unwrap (FLAC stays bit-exact FLAC); `--mp3` is an extra
  320k CBR transcode of that result.
- Per-song keys are cached under `ekeys/` and never expire — repeat decrypts
  of the same song work fully offline.
- Crypto/tail-format internals live in `references/how-it-works.md`; read it
  only when debugging why decryption itself failed.
- Crypto logic consolidated from qmdec (MIT, https://github.com/Sophomoresty/qmdec).
- For personal interoperability use with the user's own account and downloads.
