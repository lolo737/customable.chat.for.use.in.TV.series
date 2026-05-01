#!/usr/bin/env python3
"""
SecureChat — Peer-to-peer encrypted chat using libsodium (PyNaCl)

Features:
  - NaCl Box end-to-end encryption (X25519 + XSalsa20-Poly1305)
  - Scheduled messages  (send at DD/MM/YYYY HH:MM)
  - Annual recurring messages (fires every year on same date)
  - Self-destruct messages (auto-deleted 5s after recipient reads)
  - 3 built-in themes: Dark Teal / Amber Terminal / Clean Light
  - Fully customisable appearance (fonts, colours, background image)
  - Local SQLite chat log

Run as server: python securechat.py --server
Run as client: python securechat.py --client --host 192.168.1.x
"""

import sys, os, json, sqlite3, asyncio, argparse, base64, datetime
from pathlib import Path

try:
    import nacl.public, nacl.utils, nacl.encoding
except ImportError:
    print("ERROR: pip install pynacl"); sys.exit(1)

try:
    import websockets
except ImportError:
    print("ERROR: pip install websockets"); sys.exit(1)

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLineEdit, QPushButton, QLabel, QScrollArea, QFrame,
        QFileDialog, QInputDialog, QMessageBox, QFontDialog, QColorDialog,
        QListWidget, QDialog, QDialogButtonBox, QFormLayout, QCheckBox,
        QDateTimeEdit, QTableWidget, QTableWidgetItem, QHeaderView,
        QComboBox, QTextEdit
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime
    from PyQt5.QtGui import QFont, QColor
except ImportError:
    print("ERROR: pip install PyQt5"); sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

APP_DIR      = Path.home() / ".securechat"
APP_DIR.mkdir(exist_ok=True)
KEYS_FILE    = APP_DIR / "keypair.json"
DB_FILE      = APP_DIR / "messages.db"
THEME_FILE   = APP_DIR / "theme.json"
PEERS_FILE   = APP_DIR / "peers.json"
DEFAULT_PORT = 8765

# ── THEME PRESETS ─────────────────────────────────────────────────────────────

THEMES = {

    "Dark Teal": {
        "bg_color":        "#0a0a0a",
        "chat_bg":         "#0f0f0f",
        "sidebar_bg":      "#0d0d0d",
        "bubble_mine":     "#101c30",
        "bubble_theirs":   "#0d2420",
        "border_mine":     "#1a2e4a",
        "border_theirs":   "#0f3828",
        "text_mine":       "#a0c8e8",   # brighter outgoing text
        "text_theirs":     "#a8d8c8",
        "sender_mine":     "#4a80b0",
        "sender_theirs":   "#00d4aa",
        "text_color":      "#c8c8c8",
        "accent_color":    "#00d4aa",
        "font_family":     "Courier New",
        "font_size":       12,
        "bg_image":        "",
        "username":        "Anonymous",
        "send_label":      "TRANSMIT",
        "radius_mine":     "14px 14px 3px 14px",
        "radius_theirs":   "14px 14px 14px 3px",
        "border_width":    "1px",
        "sd_border":       "#cc2222",
        "sd_bg":           "#1a0d0d",
    },

    "Amber Terminal": {
        "bg_color":        "#050500",
        "chat_bg":         "#060600",
        "sidebar_bg":      "#070700",
        "bubble_mine":     "#0a0900",
        "bubble_theirs":   "#0c0a00",
        "border_mine":     "#5a4000",
        "border_theirs":   "#c8900a",
        "text_mine":       "#c8a040",   # bright amber outgoing
        "text_theirs":     "#a07820",
        "sender_mine":     "#5a4000",
        "sender_theirs":   "#c8900a",
        "text_color":      "#7a6010",
        "accent_color":    "#c8900a",
        "font_family":     "Courier New",
        "font_size":       12,
        "bg_image":        "",
        "username":        "Anonymous",
        "send_label":      "TRANSMIT",
        "radius_mine":     "16px 16px 3px 16px",
        "radius_theirs":   "16px 16px 16px 3px",
        "border_width":    "2px",
        "sd_border":       "#8b0000",
        "sd_bg":           "#100000",
    },

    "Clean Light": {
        "bg_color":        "#f4f4f4",
        "chat_bg":         "#ffffff",
        "sidebar_bg":      "#f4f4f4",
        "bubble_mine":     "#1a1a1a",
        "bubble_theirs":   "#f0f0f0",
        "border_mine":     "#111111",
        "border_theirs":   "#e4e4e4",
        "text_mine":       "#ffffff",   # white on dark — max brightness
        "text_theirs":     "#333333",
        "sender_mine":     "#4caf90",
        "sender_theirs":   "#4caf90",
        "text_color":      "#1a1a1a",
        "accent_color":    "#1a1a1a",
        "font_family":     "Helvetica Neue",
        "font_size":       12,
        "bg_image":        "",
        "username":        "Anonymous",
        "send_label":      "Send",
        "radius_mine":     "14px 14px 3px 14px",
        "radius_theirs":   "14px 14px 14px 3px",
        "border_width":    "1px",
        "sd_border":       "#cc0000",
        "sd_bg":           "#fff0f0",
    },
}

DEFAULT_THEME = THEMES["Dark Teal"].copy()


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO
# ─────────────────────────────────────────────────────────────────────────────

def load_or_create_keypair():
    if KEYS_FILE.exists():
        d = json.loads(KEYS_FILE.read_text())
        return nacl.public.PrivateKey(base64.b64decode(d["private"]))
    k = nacl.public.PrivateKey.generate()
    KEYS_FILE.write_text(json.dumps({
        "private": base64.b64encode(bytes(k)).decode(),
        "public":  base64.b64encode(bytes(k.public_key)).decode(),
    }))
    os.chmod(KEYS_FILE, 0o600)
    return k

def pub64(pk):
    return base64.b64encode(bytes(pk.public_key)).decode()

def encrypt(msg, my_key, their_pub64):
    box = nacl.public.Box(my_key, nacl.public.PublicKey(base64.b64decode(their_pub64)))
    return base64.b64encode(box.encrypt(msg.encode())).decode()

def decrypt(enc64, my_key, their_pub64):
    box = nacl.public.Box(my_key, nacl.public.PublicKey(base64.b64decode(their_pub64)))
    return box.decrypt(base64.b64decode(enc64)).decode()


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    c = sqlite3.connect(DB_FILE)
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer TEXT, direction TEXT, content TEXT,
        timestamp TEXT, self_destruct INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scheduled (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer TEXT, content TEXT,
        send_at TEXT,
        recurring INTEGER DEFAULT 0,
        self_destruct INTEGER DEFAULT 0,
        sent INTEGER DEFAULT 0,
        note TEXT
    )""")
    c.commit(); c.close()

def save_msg(peer, direction, content, sd=False):
    c = sqlite3.connect(DB_FILE)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO messages (peer,direction,content,timestamp,self_destruct) VALUES (?,?,?,?,?)",
              (peer, direction, content, ts, int(sd)))
    c.commit(); c.close()

def save_msg_get_id(peer, direction, content, sd=False):
    c = sqlite3.connect(DB_FILE)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = c.execute("INSERT INTO messages (peer,direction,content,timestamp,self_destruct) VALUES (?,?,?,?,?)",
                    (peer, direction, content, ts, int(sd)))
    row_id = cur.lastrowid
    c.commit(); c.close()
    return row_id

def destruct_msg(msg_id):
    c = sqlite3.connect(DB_FILE)
    c.execute("DELETE FROM messages WHERE id=? AND self_destruct=1", (msg_id,))
    c.commit(); c.close()

def load_history(peer):
    c = sqlite3.connect(DB_FILE)
    rows = c.execute(
        "SELECT id,direction,content,timestamp,self_destruct FROM messages WHERE peer=? ORDER BY id",
        (peer,)
    ).fetchall()
    c.close()
    return rows

def clear_history(peer=None):
    c = sqlite3.connect(DB_FILE)
    if peer: c.execute("DELETE FROM messages WHERE peer=?", (peer,))
    else:    c.execute("DELETE FROM messages")
    c.commit(); c.close()

def save_scheduled(peer, content, dt, recurring, sd, note=""):
    c = sqlite3.connect(DB_FILE)
    c.execute("INSERT INTO scheduled (peer,content,send_at,recurring,self_destruct,sent,note) VALUES (?,?,?,?,?,0,?)",
              (peer, content, dt.strftime("%Y-%m-%d %H:%M:%S"), int(recurring), int(sd), note))
    c.commit(); c.close()

def load_pending_scheduled():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = sqlite3.connect(DB_FILE)
    rows = c.execute(
        "SELECT id,peer,content,send_at,recurring,self_destruct,note FROM scheduled WHERE sent=0 AND send_at<=?",
        (now,)
    ).fetchall()
    c.close()
    return rows

def load_all_scheduled():
    c = sqlite3.connect(DB_FILE)
    rows = c.execute(
        "SELECT id,peer,content,send_at,recurring,self_destruct,sent,note FROM scheduled ORDER BY send_at"
    ).fetchall()
    c.close()
    return rows

def mark_scheduled_sent(sid, recurring, original_dt):
    c = sqlite3.connect(DB_FILE)
    if recurring:
        nxt = original_dt.replace(year=original_dt.year + 1)
        c.execute("UPDATE scheduled SET send_at=?,sent=0 WHERE id=?",
                  (nxt.strftime("%Y-%m-%d %H:%M:%S"), sid))
    else:
        c.execute("UPDATE scheduled SET sent=1 WHERE id=?", (sid,))
    c.commit(); c.close()

def delete_scheduled(sid):
    c = sqlite3.connect(DB_FILE)
    c.execute("DELETE FROM scheduled WHERE id=?", (sid,))
    c.commit(); c.close()


# ─────────────────────────────────────────────────────────────────────────────
# THEME / PEERS
# ─────────────────────────────────────────────────────────────────────────────

def load_theme():
    if THEME_FILE.exists():
        saved = json.loads(THEME_FILE.read_text())
        t = DEFAULT_THEME.copy()
        t.update(saved)
        return t
    return DEFAULT_THEME.copy()

def save_theme(t):
    THEME_FILE.write_text(json.dumps(t, indent=2))

def load_peers():
    return json.loads(PEERS_FILE.read_text()) if PEERS_FILE.exists() else {}

def save_peers(p):
    PEERS_FILE.write_text(json.dumps(p, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# SERVER THREAD
# ─────────────────────────────────────────────────────────────────────────────

class ServerThread(QThread):
    msg_received      = pyqtSignal(str, str, str)
    peer_connected    = pyqtSignal(str)
    peer_disconnected = pyqtSignal(str)

    def __init__(self, pk, port):
        super().__init__()
        self.pk = pk; self.port = port
        self.loop = None; self.connections = {}

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._serve())

    async def _serve(self):
        async with websockets.serve(self._handler, "0.0.0.0", self.port):
            await asyncio.Future()

    async def _handler(self, ws, path="/"):
        spub = sname = None
        try:
            hs = json.loads(await ws.recv())
            spub = hs["pub_key"]; sname = hs.get("name", "Unknown")
            self.connections[ws] = {"pub_key": spub, "name": sname}
            self.peer_connected.emit(sname)
            await ws.send(json.dumps({"pub_key": pub64(self.pk), "name": "Server"}))
            async for raw in ws:
                try:
                    env = json.loads(raw)
                    pt  = decrypt(env["msg"], self.pk, spub)
                    self.msg_received.emit(spub, sname, pt)
                except Exception:
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.connections.pop(ws, None)
            if sname: self.peer_disconnected.emit(sname)

    def send_all(self, payload):
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._bcast(payload), self.loop)

    async def _bcast(self, payload):
        for ws, info in list(self.connections.items()):
            try:
                enc = encrypt(payload, self.pk, info["pub_key"])
                await ws.send(json.dumps({"msg": enc}))
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CLIENT THREAD
# ─────────────────────────────────────────────────────────────────────────────

class ClientThread(QThread):
    msg_received      = pyqtSignal(str, str)
    connected         = pyqtSignal(str)
    disconnected      = pyqtSignal()
    connection_failed = pyqtSignal(str)

    def __init__(self, pk, host, port, username):
        super().__init__()
        self.pk = pk; self.host = host; self.port = port
        self.username = username; self.loop = None
        self._q = None; self.server_pub = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        self._q = asyncio.Queue()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect())

    async def _connect(self):
        try:
            async with websockets.connect(f"ws://{self.host}:{self.port}") as ws:
                await ws.send(json.dumps({"pub_key": pub64(self.pk), "name": self.username}))
                hs = json.loads(await ws.recv())
                self.server_pub = hs["pub_key"]
                self.connected.emit(self.server_pub)
                await asyncio.gather(self._recv(ws), self._send(ws))
        except Exception as e:
            self.connection_failed.emit(str(e))
        finally:
            self.disconnected.emit()

    async def _recv(self, ws):
        async for raw in ws:
            try:
                env = json.loads(raw)
                pt  = decrypt(env["msg"], self.pk, self.server_pub)
                self.msg_received.emit(self.server_pub, pt)
            except Exception:
                pass

    async def _send(self, ws):
        while True:
            pt = await self._q.get()
            if pt is None: break
            enc = encrypt(pt, self.pk, self.server_pub)
            await ws.send(json.dumps({"msg": enc}))

    def send(self, payload):
        if self.loop and self._q:
            asyncio.run_coroutine_threadsafe(self._q.put(payload), self.loop)

    def stop(self):
        if self.loop and self._q:
            asyncio.run_coroutine_threadsafe(self._q.put(None), self.loop)


# ─────────────────────────────────────────────────────────────────────────────
# SCHEDULE DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class ScheduleDialog(QDialog):
    def __init__(self, peers, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Schedule a Message")
        self.setMinimumWidth(480)
        layout = QFormLayout(self); layout.setSpacing(14)

        self.peer_combo = QComboBox()
        self.peer_combo.addItems(list(peers.keys()))
        self.peer_combo.addItem("Everyone (broadcast)")
        layout.addRow("To:", self.peer_combo)

        self.msg_edit = QTextEdit()
        self.msg_edit.setPlaceholderText("Your message…")
        self.msg_edit.setFixedHeight(100)
        layout.addRow("Message:", self.msg_edit)

        self.note_edit = QLineEdit()
        self.note_edit.setPlaceholderText("e.g. Happy birthday! (optional)")
        layout.addRow("Label:", self.note_edit)

        self.dt_pick = QDateTimeEdit()
        self.dt_pick.setDisplayFormat("dd/MM/yyyy   HH:mm")
        self.dt_pick.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.dt_pick.setCalendarPopup(True)
        self.dt_pick.setMinimumDateTime(QDateTime.currentDateTime())
        layout.addRow("Send at:", self.dt_pick)

        self.recur_chk = QCheckBox("Repeat every year on this date  📅")
        layout.addRow("", self.recur_chk)

        self.sd_chk = QCheckBox("Self-destruct after recipient reads it  💥")
        layout.addRow("", self.sd_chk)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._ok); btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _ok(self):
        if not self.msg_edit.toPlainText().strip():
            QMessageBox.warning(self, "Empty", "Please type a message."); return
        self.accept()

    def get(self):
        qdt = self.dt_pick.dateTime()
        py_dt = datetime.datetime(
            qdt.date().year(), qdt.date().month(), qdt.date().day(),
            qdt.time().hour(), qdt.time().minute()
        )
        return {
            "peer":          self.peer_combo.currentText(),
            "content":       self.msg_edit.toPlainText().strip(),
            "note":          self.note_edit.text().strip(),
            "send_at":       py_dt,
            "recurring":     self.recur_chk.isChecked(),
            "self_destruct": self.sd_chk.isChecked(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# SCHEDULE MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class ScheduleManager(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scheduled Messages")
        self.setMinimumSize(720, 380)
        layout = QVBoxLayout(self)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["#", "To", "Send At (DD/MM/YYYY)", "Yearly", "💥", "Status", "Message / Label"])
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        row_btns = QHBoxLayout()
        del_btn   = QPushButton("🗑  Delete Selected"); del_btn.clicked.connect(self._delete)
        close_btn = QPushButton("Close");              close_btn.clicked.connect(self.accept)
        row_btns.addWidget(del_btn); row_btns.addStretch(); row_btns.addWidget(close_btn)
        layout.addLayout(row_btns)
        self._load()

    def _load(self):
        self.table.setRowCount(0)
        for sid, peer, content, send_at, recurring, sd, sent, note in load_all_scheduled():
            r = self.table.rowCount(); self.table.insertRow(r)
            try:
                dt_str = datetime.datetime.strptime(send_at, "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y  %H:%M")
            except Exception:
                dt_str = send_at
            label = f"[{note}]  {content}" if note else content
            for col, val in enumerate([
                str(sid), peer, dt_str,
                "✓" if recurring else "—",
                "💥" if sd else "—",
                "Sent ✓" if sent else "Pending ⏳",
                label[:90]
            ]):
                self.table.setItem(r, col, QTableWidgetItem(val))

    def _delete(self):
        row = self.table.currentRow()
        if row < 0: return
        sid = int(self.table.item(row, 0).text())
        if QMessageBox.question(self, "Delete", "Delete this scheduled message?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            delete_scheduled(sid); self._load()


# ─────────────────────────────────────────────────────────────────────────────
# CHAT BUBBLE  — theme-aware, directional corners, per-side colours
# ─────────────────────────────────────────────────────────────────────────────

class Bubble(QFrame):
    def __init__(self, text, sender, ts, is_mine, theme,
                 sd=False, msg_id=None, on_destruct=None):
        super().__init__()
        self.msg_id = msg_id
        layout = QVBoxLayout(self)
        layout.setContentsMargins(11, 7, 11, 7)
        layout.setSpacing(3)

        # Sender label — different colour per side
        lbl_name = QLabel(sender)
        sender_color = theme.get("sender_mine" if is_mine else "sender_theirs",
                                 theme["accent_color"])
        lbl_name.setStyleSheet(
            f"color:{sender_color};font-size:10px;font-weight:bold;letter-spacing:1px;")
        if is_mine:
            lbl_name.setAlignment(Qt.AlignRight)

        # Message text — brighter on outgoing
        lbl_msg = QLabel(text)
        lbl_msg.setWordWrap(True)
        msg_color = theme.get("text_mine" if is_mine else "text_theirs",
                              theme["text_color"])
        lbl_msg.setStyleSheet(
            f"color:{msg_color};"
            f"font-family:{theme['font_family']};"
            f"font-size:{theme['font_size']}px;")

        # Timestamp
        footer = ts + ("  ·  💥 self-destruct" if sd else "")
        lbl_ts = QLabel(footer)
        ts_color = theme.get("sd_border", "#cc2222") if sd else "#444444"
        lbl_ts.setStyleSheet(f"color:{ts_color};font-size:9px;")
        lbl_ts.setAlignment(Qt.AlignRight)

        layout.addWidget(lbl_name)
        layout.addWidget(lbl_msg)
        layout.addWidget(lbl_ts)

        # Bubble background + border
        if sd:
            bg     = theme.get("sd_bg", "#1a0d0d")
            border = theme.get("sd_border", "#cc2222")
        else:
            bg     = theme["bubble_mine"]     if is_mine else theme["bubble_theirs"]
            border = theme.get("border_mine"  if is_mine else "border_theirs", "#222233")

        radius = theme.get("radius_mine" if is_mine else "radius_theirs", "10px")
        bw     = theme.get("border_width", "1px")

        self.setStyleSheet(
            f"QFrame{{background:{bg};border-radius:{radius};"
            f"border:{bw} solid {border};}}")
        self.setMaximumWidth(520)

        if sd and not is_mine and msg_id and on_destruct:
            QTimer.singleShot(5000, lambda: on_destruct(msg_id))


# ─────────────────────────────────────────────────────────────────────────────
# SCHEDULER CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class SchedulerChecker:
    def __init__(self, window):
        self.win = window
        self.t = QTimer(); self.t.timeout.connect(self._check); self.t.start(30_000)
        self._check()

    def _check(self):
        for sid, peer, content, send_at, recurring, sd, note in load_pending_scheduled():
            orig_dt = datetime.datetime.strptime(send_at, "%Y-%m-%d %H:%M:%S")
            label   = f"[{note}]  {content}" if note else content
            self.win._dispatch(label, peer=peer, sd=bool(sd))
            mark_scheduled_sent(sid, recurring, orig_dt)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class SecureChatWindow(QMainWindow):
    def __init__(self, pk, mode, host=None, port=DEFAULT_PORT):
        super().__init__()
        self.pk   = pk; self.mode = mode
        self.host = host; self.port = port
        self.theme = load_theme(); self.peers = load_peers()
        self.active_peer   = None
        self.server_thread = None
        self.client_thread = None

        init_db(); self._ui(); self._style()

        if mode == "server": self._start_server()
        else:                self._start_client()

        self.scheduler = SchedulerChecker(self)

    # ── BUILD UI ──────────────────────────────────────────────────────────────

    def _ui(self):
        self.setWindowTitle("SecureChat")
        self.setMinimumSize(860, 620); self.resize(1080, 740)
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── sidebar ──
        sb = QWidget(); sb.setFixedWidth(236)
        sl = QVBoxLayout(sb); sl.setContentsMargins(12,14,12,12); sl.setSpacing(7)

        title = QLabel("SECURECHAT"); title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:13px;font-weight:bold;letter-spacing:3px;padding:8px 0;")
        sl.addWidget(title)

        mode_lbl = QLabel(f"{'SERVER' if self.mode=='server' else 'CLIENT'}  MODE")
        mode_lbl.setAlignment(Qt.AlignCenter)
        mode_lbl.setStyleSheet("font-size:9px;letter-spacing:2px;")
        sl.addWidget(mode_lbl)

        short_key = pub64(self.pk)[:14] + "…"
        sl.addWidget(QLabel(f"Key: {short_key}", alignment=Qt.AlignCenter,
                            styleSheet="font-size:9px;opacity:0.4;"))

        copy_btn = QPushButton("Copy My Public Key"); copy_btn.clicked.connect(self._copy_pub)
        sl.addWidget(copy_btn)

        sl.addWidget(QLabel("PEERS", styleSheet="font-size:9px;font-weight:bold;letter-spacing:2px;margin-top:8px;"))
        self.peers_list = QListWidget(); self.peers_list.itemClicked.connect(self._select_peer)
        sl.addWidget(self.peers_list)
        add_p = QPushButton("+ Add Peer Key"); add_p.clicked.connect(self._add_peer)
        sl.addWidget(add_p)

        self.status_lbl = QLabel("Waiting for connection…")
        self.status_lbl.setAlignment(Qt.AlignCenter); self.status_lbl.setWordWrap(True)
        self.status_lbl.setStyleSheet("font-size:10px;margin-top:6px;")
        sl.addWidget(self.status_lbl)
        sl.addStretch()

        sl.addWidget(QLabel("SCHEDULED", styleSheet="font-size:9px;font-weight:bold;letter-spacing:2px;"))
        sched_btn = QPushButton("⏰  Schedule a Message"); sched_btn.clicked.connect(self._new_schedule)
        sl.addWidget(sched_btn)
        view_btn = QPushButton("📋  View Scheduled"); view_btn.clicked.connect(self._view_schedules)
        sl.addWidget(view_btn)

        app_btn = QPushButton("⚙  Appearance"); app_btn.clicked.connect(self._appearance)
        sl.addWidget(app_btn)
        clr_btn = QPushButton("🗑  Clear History"); clr_btn.clicked.connect(self._clear)
        sl.addWidget(clr_btn)

        # ── chat panel ──
        chat = QWidget(); cl = QVBoxLayout(chat); cl.setContentsMargins(0,0,0,0); cl.setSpacing(0)

        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.msgs_w = QWidget()
        self.msgs_l = QVBoxLayout(self.msgs_w)
        self.msgs_l.setAlignment(Qt.AlignTop); self.msgs_l.setSpacing(10)
        self.msgs_l.setContentsMargins(18,18,18,18)
        self.scroll.setWidget(self.msgs_w)

        inp_row = QHBoxLayout(); inp_row.setContentsMargins(10,10,10,10); inp_row.setSpacing(6)
        self.sd_chk = QCheckBox("💥"); self.sd_chk.setToolTip("Self-destruct")
        self.sd_chk.setStyleSheet("font-size:16px;color:#ff6666;")
        self.inp = QLineEdit()
        self.inp.setPlaceholderText(f"Message… (Enter to {self.theme.get('send_label','Send').lower()})")
        self.inp.returnPressed.connect(self._send); self.inp.setMinimumHeight(42)
        self.send_btn = QPushButton(self.theme.get("send_label", "Send"))
        self.send_btn.setMinimumHeight(42); self.send_btn.setMinimumWidth(90)
        self.send_btn.clicked.connect(self._send)
        inp_row.addWidget(self.sd_chk); inp_row.addWidget(self.inp, 1); inp_row.addWidget(self.send_btn)
        inp_w = QWidget(); inp_w.setLayout(inp_row)

        cl.addWidget(self.scroll); cl.addWidget(inp_w)
        root.addWidget(sb); root.addWidget(chat, 1)
        self._refresh_peers()

    # ── STYLE ─────────────────────────────────────────────────────────────────

    def _style(self):
        t = self.theme
        bg_img = ""
        if t.get("bg_image") and Path(t["bg_image"]).exists():
            safe = t["bg_image"].replace("\\", "/")
            bg_img = f"background-image:url('{safe}');background-size:cover;"

        sidebar_bg = t.get("sidebar_bg", t["bg_color"])
        accent     = t["accent_color"]
        hover      = self._lighten(accent)

        self.setStyleSheet(f"""
            QMainWindow,QWidget{{
                background:{t['bg_color']};color:{t['text_color']};
                font-family:{t['font_family']};font-size:{t['font_size']}px;}}
            QScrollArea{{background:{t['chat_bg']};{bg_img}border:none;}}
            QLineEdit{{background:{sidebar_bg};color:{t['text_color']};
                border:1px solid {t.get('border_mine','#333')};
                border-radius:6px;padding:6px 10px;
                font-family:{t['font_family']};font-size:{t['font_size']}px;}}
            QPushButton{{background:{accent};color:#000;border:none;
                border-radius:6px;padding:6px 12px;font-weight:bold;letter-spacing:1px;}}
            QPushButton:hover{{background:{hover};}}
            QListWidget{{background:{sidebar_bg};border:1px solid {t.get('border_theirs','#222')};
                border-radius:4px;color:{t['text_color']};}}
            QListWidget::item:selected{{background:{accent};color:#000;}}
            QScrollBar:vertical{{background:{t['bg_color']};width:6px;}}
            QScrollBar::handle:vertical{{background:{t.get('border_mine','#333')};border-radius:3px;}}
            QCheckBox{{color:{t['text_color']};}}
            QDateTimeEdit,QComboBox,QTextEdit{{
                background:{sidebar_bg};color:{t['text_color']};
                border:1px solid {t.get('border_theirs','#333')};
                border-radius:4px;padding:4px 8px;}}
            QTableWidget{{background:{sidebar_bg};color:{t['text_color']};
                border:none;gridline-color:{t.get('border_mine','#222')};}}
            QHeaderView::section{{background:{t['bg_color']};
                color:{accent};padding:4px;border:none;}}
        """)

        # update send button label when theme changes
        if hasattr(self, 'send_btn'):
            self.send_btn.setText(t.get("send_label", "Send"))
        if hasattr(self, 'status_lbl'):
            self.status_lbl.setStyleSheet(f"font-size:10px;color:{accent};margin-top:6px;")

    @staticmethod
    def _lighten(hex_color):
        """Return a slightly lighter version of a hex colour for hover states."""
        try:
            h = hex_color.lstrip("#")
            r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
            r = min(255, r + 40); g = min(255, g + 40); b = min(255, b + 40)
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception:
            return hex_color

    # ── APPEARANCE DIALOG ─────────────────────────────────────────────────────

    def _appearance(self):
        dlg = QDialog(self); dlg.setWindowTitle("Appearance"); dlg.setMinimumWidth(460)
        f = QFormLayout(dlg); f.setSpacing(12)

        # ── Preset picker ──
        preset_combo = QComboBox()
        preset_combo.addItems(list(THEMES.keys()))
        current_name = next(
            (k for k, v in THEMES.items() if v["bg_color"] == self.theme.get("bg_color")),
            "Dark Teal"
        )
        preset_combo.setCurrentText(current_name)

        def apply_preset(name):
            self.theme.update(THEMES[name])
            save_theme(self.theme)
            self._style()
            dlg.accept()

        preset_btn = QPushButton("Apply Preset")
        preset_btn.clicked.connect(lambda: apply_preset(preset_combo.currentText()))
        preset_row = QHBoxLayout()
        preset_row.addWidget(preset_combo, 1); preset_row.addWidget(preset_btn)
        preset_w = QWidget(); preset_w.setLayout(preset_row)
        f.addRow("Theme preset:", preset_w)

        sep = QLabel("─── or customise manually ───")
        sep.setStyleSheet("color:#555;font-size:10px;")
        sep.setAlignment(Qt.AlignCenter)
        f.addRow(sep)

        # ── Colour pickers ──
        def pick_color(key, lbl):
            c = QColorDialog.getColor(QColor(self.theme.get(key, "#000000")), self)
            if c.isValid():
                self.theme[key] = c.name()
                lbl.setText(c.name())
                lbl.setStyleSheet(f"background:{c.name()};padding:4px;color:#fff;")

        color_fields = [
            ("bg_color",      "Background"),
            ("chat_bg",       "Chat BG"),
            ("accent_color",  "Accent / Buttons"),
            ("bubble_mine",   "My bubble BG"),
            ("bubble_theirs", "Their bubble BG"),
            ("text_mine",     "My message text"),
            ("text_theirs",   "Their message text"),
        ]
        for key, label in color_fields:
            val = self.theme.get(key, "#000000")
            lbl = QLabel(val)
            lbl.setStyleSheet(f"background:{val};padding:4px;color:#fff;")
            lbl.setCursor(Qt.PointingHandCursor)
            lbl.mousePressEvent = lambda e, k=key, lb=lbl: pick_color(k, lb)
            f.addRow(label, lbl)

        # ── Font ──
        font_btn = QPushButton(f"{self.theme['font_family']} {self.theme['font_size']}pt")
        def pick_font():
            ft, ok = QFontDialog.getFont(
                QFont(self.theme['font_family'], self.theme['font_size']), self)
            if ok:
                self.theme['font_family'] = ft.family()
                self.theme['font_size']   = ft.pointSize()
                font_btn.setText(f"{ft.family()} {ft.pointSize()}pt")
        font_btn.clicked.connect(pick_font); f.addRow("Font", font_btn)

        # ── Background image ──
        img_btn = QPushButton("Choose Background Image")
        def pick_img():
            p, _ = QFileDialog.getOpenFileName(
                self, "Image", "", "Images (*.png *.jpg *.jpeg *.bmp)")
            if p: self.theme["bg_image"] = p; img_btn.setText(Path(p).name)
        img_btn.clicked.connect(pick_img); f.addRow("BG Image", img_btn)

        # ── Username ──
        uname = QLineEdit(self.theme.get("username", "Anonymous"))
        f.addRow("Your Name", uname)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        f.addRow(btns)

        if dlg.exec_():
            self.theme["username"] = uname.text()
            save_theme(self.theme); self._style()

    # ── PEERS ─────────────────────────────────────────────────────────────────

    def _add_peer(self):
        name, ok = QInputDialog.getText(self, "Add Peer", "Peer name:")
        if not ok or not name: return
        key, ok = QInputDialog.getText(self, "Add Peer", f"Paste {name}'s public key:")
        if not ok or not key: return
        self.peers[name] = key.strip(); save_peers(self.peers); self._refresh_peers()

    def _refresh_peers(self):
        self.peers_list.clear()
        for n in self.peers: self.peers_list.addItem(n)

    def _select_peer(self, item):
        self.active_peer = item.text(); self._load_history()

    def _copy_pub(self):
        QApplication.clipboard().setText(pub64(self.pk))
        self.status_lbl.setText("Public key copied!")
        QTimer.singleShot(2000, lambda: self.status_lbl.setText("Ready"))

    # ── SCHEDULING ────────────────────────────────────────────────────────────

    def _new_schedule(self):
        if not self.peers:
            QMessageBox.information(self, "No peers", "Add a peer first."); return
        dlg = ScheduleDialog(self.peers, self)
        if dlg.exec_():
            d = dlg.get()
            save_scheduled(d["peer"], d["content"], d["send_at"],
                           d["recurring"], d["self_destruct"], d["note"])
            ds = d["send_at"].strftime("%d/%m/%Y %H:%M")
            extra = (" ↻ yearly" if d["recurring"] else "") + (" 💥" if d["self_destruct"] else "")
            self.status_lbl.setText(f"Scheduled\n{ds}{extra}")
            QTimer.singleShot(4000, lambda: self.status_lbl.setText("Ready"))

    def _view_schedules(self):
        ScheduleManager(self).exec_()

    # ── MESSAGING ─────────────────────────────────────────────────────────────

    def _send(self):
        text = self.inp.text().strip()
        if not text: return
        sd = self.sd_chk.isChecked()
        self._dispatch(text, sd=sd, outgoing=True)
        self.inp.clear(); self.sd_chk.setChecked(False)

    def _dispatch(self, text, peer=None, sd=False, outgoing=True):
        payload  = json.dumps({"text": text, "sd": sd})
        username = self.theme.get("username", "Me")
        ts       = datetime.datetime.now().strftime("%H:%M")

        if outgoing:
            if self.mode == "server" and self.server_thread:
                self.server_thread.send_all(payload)
            elif self.mode == "client" and self.client_thread:
                self.client_thread.send(payload)
            self._bubble(text, username, ts, is_mine=True, sd=sd)
            save_msg(peer or self.host or "__broadcast__", "out", text, sd)

    def _on_server_msg(self, spub, sname, payload_raw):
        text, sd = self._parse(payload_raw)
        ts  = datetime.datetime.now().strftime("%H:%M")
        mid = save_msg_get_id(sname, "in", text, sd)
        self._bubble(text, sname, ts, is_mine=False, sd=sd, msg_id=mid)

    def _on_client_msg(self, spub, payload_raw):
        text, sd = self._parse(payload_raw)
        ts  = datetime.datetime.now().strftime("%H:%M")
        mid = save_msg_get_id(self.host or "Server", "in", text, sd)
        self._bubble(text, "Server", ts, is_mine=False, sd=sd, msg_id=mid)

    @staticmethod
    def _parse(raw):
        try:
            e = json.loads(raw); return e.get("text", raw), bool(e.get("sd", False))
        except Exception:
            return raw, False

    def _bubble(self, text, sender, ts, is_mine, sd=False, msg_id=None):
        b = Bubble(text, sender, ts, is_mine, self.theme,
                   sd=sd, msg_id=msg_id,
                   on_destruct=destruct_msg if sd else None)
        row = QHBoxLayout(); row.setContentsMargins(0,0,0,0); row.setSpacing(8)
        # avatar dot
        av = QLabel(sender[0].upper() if sender else "?")
        av.setFixedSize(26, 26)
        av.setAlignment(Qt.AlignCenter)
        av_bg = self.theme.get("border_mine" if is_mine else "border_theirs", "#333")
        av_fg = self.theme.get("sender_mine" if is_mine else "sender_theirs",
                               self.theme["accent_color"])
        av.setStyleSheet(
            f"background:{av_bg};color:{av_fg};border-radius:13px;"
            f"font-size:10px;font-weight:bold;")

        if is_mine:
            row.addStretch(); row.addWidget(b); row.addWidget(av)
        else:
            row.addWidget(av); row.addWidget(b); row.addStretch()

        w = QWidget(); w.setLayout(row)
        self.msgs_l.addWidget(w)
        QTimer.singleShot(50, lambda: self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()))

    def _load_history(self):
        while self.msgs_l.count():
            item = self.msgs_l.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        peer     = self.active_peer or self.host or "__broadcast__"
        username = self.theme.get("username", "Me")
        for mid, direction, content, ts, sd in load_history(peer):
            is_mine = direction == "out"
            self._bubble(content, username if is_mine else peer,
                         ts[11:16], is_mine, bool(sd), mid)

    def _clear(self):
        if QMessageBox.question(self, "Clear", "Delete all local history?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            clear_history()
            while self.msgs_l.count():
                item = self.msgs_l.takeAt(0)
                if item.widget(): item.widget().deleteLater()

    # ── NETWORKING ────────────────────────────────────────────────────────────

    def _start_server(self):
        self.server_thread = ServerThread(self.pk, self.port)
        self.server_thread.msg_received.connect(self._on_server_msg)
        self.server_thread.peer_connected.connect(
            lambda n: self.status_lbl.setText(f"✓ {n} connected"))
        self.server_thread.peer_disconnected.connect(
            lambda n: self.status_lbl.setText(f"✗ {n} left"))
        self.server_thread.start()
        import socket
        try:    ip = socket.gethostbyname(socket.gethostname())
        except: ip = "localhost"
        self.status_lbl.setText(f"Listening on\n{ip}:{self.port}")

    def _start_client(self):
        uname = self.theme.get("username", "Anonymous")
        self.client_thread = ClientThread(self.pk, self.host, self.port, uname)
        self.client_thread.msg_received.connect(self._on_client_msg)
        self.client_thread.connected.connect(
            lambda _: self.status_lbl.setText("Connected & encrypted"))
        self.client_thread.disconnected.connect(
            lambda: self.status_lbl.setText("Disconnected"))
        self.client_thread.connection_failed.connect(
            lambda e: self.status_lbl.setText(f"Failed:\n{e}"))
        self.client_thread.start()
        self.status_lbl.setText(f"Connecting…\n{self.host}:{self.port}")

    def closeEvent(self, event):
        if self.client_thread: self.client_thread.stop()
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SecureChat")
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=DEFAULT_PORT)
    parser.add_argument("--theme",  default=None,
                        help=f"Preset theme: {', '.join(THEMES.keys())}")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setApplicationName("SecureChat")
    pk = load_or_create_keypair()

    # Apply CLI theme if given
    if args.theme and args.theme in THEMES:
        t = load_theme(); t.update(THEMES[args.theme]); save_theme(t)

    if args.server:
        mode = "server"
    elif args.client:
        mode = "client"
    else:
        dlg = QDialog(); dlg.setWindowTitle("SecureChat")
        l = QVBoxLayout(dlg); l.addWidget(QLabel("Run as:"))
        btns = QDialogButtonBox()
        sv = btns.addButton("Server (I am hosting)",    QDialogButtonBox.AcceptRole)
        cl = btns.addButton("Client (I am connecting)", QDialogButtonBox.RejectRole)
        l.addWidget(btns)
        chosen = ["server"]
        sv.clicked.connect(dlg.accept)
        cl.clicked.connect(lambda: (chosen.__setitem__(0, "client"), dlg.accept()))
        dlg.exec_(); mode = chosen[0]
        if mode == "client":
            h, ok = QInputDialog.getText(None, "Connect", "Server IP address:")
            if not ok: sys.exit(0)
            args.host = h

    win = SecureChatWindow(pk, mode, host=args.host, port=args.port)
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
