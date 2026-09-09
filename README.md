# qqmusic-decrypt

一个 agent 技能（skill）：把 QQ 音乐专属加密音频解密为标准格式——`.mflac/.mflac1/.mflac2/.mgg/.mgg1/.mgg2/.qmcflac/.qmc0/.qmc2/.qmc3/.qmcogg` → 无损 FLAC/OGG（直接解封装）或 320k MP3（转码）。

> 仅限解密本人拥有合法访问权限的音频（如个人已购音乐的备份迁移）。请遵守所在地法律与平台条款。

## 工作方式

- 输入加密音频 + 对应 ekey（解密密钥），本地解出原始格式，详见 `references/how-it-works.md`。
- ekey 通过登录态从 QQ 音乐接口获取，缓存在本地 `ekeys/` 目录（已被 `.gitignore` 挡住，绝不入库）。

## 安装

```bash
git clone https://github.com/techdou/qqmusic-decrypt.git ~/.agents/skills/qqmusic-decrypt
```

依赖：Python 3 + `requests`（获取 ekey 用）。

## 配置

```bash
cp .env.example .env
```

从已登录的 QQ 音乐网页会话中提取：

- `QQMUSIC_COOKIE` — 登录 cookie（用于拉取 ekey）
- `QQMUSIC_UIN` — QQ 号

`.env` 与 `ekeys/` 均为私密数据，已被 `.gitignore` 挡住。

## 用法

直接让 agent 调用，或手动执行：

```bash
python scripts/decrypt.py <input.mflac> [-o output_dir]
```

参数细节见 `SKILL.md`。

## License

[MIT](LICENSE)
