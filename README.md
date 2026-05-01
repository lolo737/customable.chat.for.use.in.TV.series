# 🔒 SecureChat — Free TV & Film Prop

A portable, peer-to-peer encrypted chat application designed for use as a **screen prop in TV and film productions**. Fully functional, fully customisable, completely free to use.

> Inspired by the aesthetic of *Mr. & Mrs. Smith* (2024, Prime Video — Donald Glover, Maya Erskine).

---

## What it is

A real, working encrypted chat interface — not a mockup, not a loop. Two devices, one USB stick, actual messages sending and receiving in real time. Built for productions that need something that looks authentic because it *is* authentic.

---

## Encryption

- **NaCl Box** — X25519 key exchange + XSalsa20-Poly1305 authenticated encryption (libsodium via PyNaCl)
- Messages encrypted before leaving the machine
- Peer-to-peer — no server, no cloud, no third-party dependency
- Keys live in `~/.securechat/keypair.json`

---

## Features

### Themes — three built-in visual styles

| Theme | Aesthetic | Button |
|-------|-----------|--------|
| **Dark Teal** | Black + teal, monospace — *Mr. & Mrs. Smith* style | TRANSMIT |
| **Amber Terminal** | Black + amber, thick borders — government/classified ops | TRANSMIT |
| **Clean Light** | White + dark bubbles — modern, civilian, everyday | Send |

Switch theme from the **⚙ Appearance** menu, or via command line:

```bash
python securechat.py --server --theme "Amber Terminal"
python securechat.py --server --theme "Clean Light"
python securechat.py --server --theme "Dark Teal"
```

### Scheduled Messages

Set a message to send automatically at a specific date and time — DD/MM/YYYY format.

- **One-time** — fires once at the scheduled time
- **Annual recurring** — fires every year on the same date, forever (perfect for birthdays, anniversaries, plot devices)
- Accessible via the **⏰ Schedule a Message** button in the sidebar

### Self-Destruct Messages

Mark any message — live or scheduled — as self-destruct. The recipient sees it with a red border and a countdown label. Five seconds after it appears on their screen, it is automatically deleted from their local database.

Toggle the 💥 checkbox next to the input field before sending.

### Fully Customisable Appearance

From the **⚙ Appearance** menu:

- Background colour, chat background, accent colour
- Incoming and outgoing bubble colours — separately
- Incoming and outgoing text colours — separately
- Font family and size
- Background image (JPG or PNG)
- Display name

### Local Chat Log

All messages stored in a local SQLite database at `~/.securechat/messages.db`. No data leaves the machine except the encrypted message itself.

---

## Setup

```bash
pip install -r requirements.txt
```

## Run

**Server (the person hosting):**
```bash
python securechat.py --server
```

**Client (the person connecting):**
```bash
python securechat.py --client --host 192.168.1.42
```

No arguments — the app asks you on launch.

## Exchange Keys

1. Click **"Copy My Public Key"** — send to your chat partner (it's public, not secret)
2. They click **"+ Add Peer Key"** and paste yours in
3. Done — all messages now encrypted end-to-end

---

## Build a standalone executable (USB stick ready)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed securechat.py
```

Output in `dist/` — a single file that runs on Windows, Mac, or Linux without Python installed. Put it on a USB stick and it runs on any machine by double-clicking.

---

## Chat over the internet

Use [Tailscale](https://tailscale.com) (free, takes two minutes to set up) — both people install it, then use the Tailscale IP as the host address. No port forwarding required.

---

## Wipe everything

```bash
rm -rf ~/.securechat/
```

---

## Licence

**Free to use in:**
- Independent films
- Short films
- Student films
- TV series and episodic productions
- Documentaries
- Theatre and live performance
- Music videos
- Anything with Stanley Tucci in it

**Not free for:**
- Commercials and advertising
- Marvel productions (any studio, any universe)
- Any production with a total budget exceeding €2,000,000

If your production falls into the not-free category, get in touch. We can work something out.

### Credit

Not required but genuinely appreciated:

> *Chat interface prop: customable.chat — github.com/lolo737/customable.chat.for.use.in.TV.series*

---

## Read more

Medium article: [I Made a Free Prop for TV Productions — Inspired by Mr. & Mrs. Smith]([https://medium.com](https://medium.com/@jerrymorgan/i-made-a-free-prop-for-tv-productions-inspired-by-mr-mrs-smith-788e2289a8c6)

---

## About

Built by [lolo737](https://github.com/lolo737). Customable is chat for use in TV series as a prop — and it works.
