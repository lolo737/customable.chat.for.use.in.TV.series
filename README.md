# 🔒 SecureChat

A portable, peer-to-peer encrypted chat using **libsodium** (PyNaCl). No servers, no accounts, no cloud.

## Encryption
- **NaCl Box** — X25519 key exchange + XSalsa20-Poly1305 authenticated encryption
- Messages encrypted before leaving your machine
- Keys live in `~/.securechat/keypair.json`

## Setup
```bash
pip install -r requirements.txt
```

## Run

**Server (hosting):**
```bash
python securechat.py --server
```

**Client (connecting):**
```bash
python securechat.py --client --host 192.168.1.42
```

## Exchange Keys
1. Click "Copy My Public Key" — send to your chat partner (it's public, not secret)
2. They click "+ Add Peer Key" and paste yours in
3. Done — all messages now encrypted end-to-end

## Customise
Click ⚙ Appearance to change fonts, colours, background image, display name.

## Build standalone executable (for USB stick)
```bash
pyinstaller --onefile --windowed securechat.py
```
Output in `dist/` — runs on Windows/Mac/Linux without Python installed.

## Chat over the internet
Use Tailscale (free, easy) — both install it, use the Tailscale IP as the host.

## Wipe everything
Delete `~/.securechat/`
