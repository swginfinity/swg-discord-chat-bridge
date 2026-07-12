"""
SWG <-> Discord Chat Bridge v2

Bridges SWG in-game chatrooms to Discord channels.
Scans a configs/ folder — each .json file spawns one bot instance.
Drop in a config to add a bot, remove it to stop one.

Usage:
    python3 swg_chat_bridge.py                     # scans ./configs/
    python3 swg_chat_bridge.py /path/to/configs/    # custom folder
    python3 swg_chat_bridge.py configs/one-bot.json # single bot mode
"""

import asyncio
import glob
import json
import os
import sys
import struct
import time
import logging
import signal
import pathlib
import re

import discord

from soe_protocol import SOEProtocol


# --- Logging ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
main_log = logging.getLogger('main')

# Healthcheck file — touch periodically so Docker can check mtime
HEALTHCHECK_FILE = os.environ.get('HEALTHCHECK_FILE', '/tmp/chatbridge_alive')

# Per-bot last-announced server status, persisted across bot restarts. Without this,
# a restart (e.g. the AutoRestartTimer, or a crash-restart) that lands during a server
# outage forgets it already announced DOWN, so the recovery "UP" is swallowed as a
# "first connect, not a server event". Lives in the container fs (not a mount), so a
# deliberate redeploy still resets to baseline and won't emit a spurious UP. (RCA 2026-06-30)
STATE_DIR = os.environ.get('CHATBRIDGE_STATE_DIR', '/tmp/chatbridge_state')

# Required config keys for validation
REQUIRED_SWG_KEYS = {'LoginAddress', 'LoginPort', 'Character', 'ChatRoom', 'Username', 'Password'}
REQUIRED_DISCORD_KEYS = {'BotToken', 'ServerID', 'ChatChannel'}

# World-state packets the bridge receives only because its relay character stands in-world,
# but never handles. Suppressed from the per-packet `recv:` debug so verbose logging stays
# readable: UpdateTransformMessage alone is ~98% of inbound traffic (~70/s) and rolls the
# capped docker log in minutes, blinding diagnosis. Genuinely-flip-`verbose`-and-debug the
# chat/login/control packets still show. (2026-06-30)
NOISY_RECV_PACKETS = frozenset({
    'UpdateTransformMessage',
    'UpdateTransformWithParentMessage',
    'DeltasMessage',
    'BaselinesMessage',
    'ObjControllerMessage',
    'UpdateContainmentMessage',
    'UpdatePvpStatusMessage',
    'SceneCreateObjectByCrc',
    'SceneDestroyObject',
    'SceneEndBaselines',
})


# Emoji / pictographs that a 2003 SWG client cannot render, stripped from anything we
# relay INTO the game (MrO 2026-07-12: "need to filter them out").
#
# The astral ones (> U+FFFF) were not merely ugly, they were FATAL: one emoji made the
# whole message silently vanish. A ustring declares its length in UTF-16 CODE UNITS, but
# an astral char is 1 Python code point and 2 UTF-16 units, so the old length field ran
# 2 bytes short and Core3 parsed room_id out of the middle of the message text -> the
# chat was addressed to a nonexistent room. No emoji-bearing Discord message has EVER
# reached the game. (_write_ustring now computes the count correctly too — that is the
# protocol-level guard; this is the product-level one.)
#
# BMP pictographs (miscellaneous symbols, dingbats, ...) never corrupted anything — they
# are 1 unit — but the client renders them as junk, so they go too. Also dropped:
# variation selectors, ZWJ and skin-tone modifiers, which are the glue in emoji sequences
# and would otherwise be left behind as orphans.
_EMOJI_RE = re.compile(
    "["
    "\U00010000-\U0010FFFF"   # ALL astral planes — the ones that broke the protocol
    "←-⇿"           # arrows
    "⌀-⏿"           # misc technical (incl. ⌚⏰)
    "①-⓿"           # enclosed alphanumerics
    "■-➿"           # geometric shapes, misc symbols, dingbats (☺✈❤✂)
    "⬀-⯿"           # misc symbols and arrows (⭐⬅)
    "〰〽㊗㊙"
    "︀-️"           # variation selectors (VS15/VS16)
    "‍"                  # zero-width joiner — emoji sequence glue
    "]+"
)


def strip_emoji(s: str) -> str:
    """Remove emoji/pictographs and collapse the whitespace they leave behind."""
    if not s:
        return s
    return re.sub(r"\s{2,}", " ", _EMOJI_RE.sub("", s)).strip()


# =============================================================================
# SWG Client (UDP) — async wrapper around SOE protocol
# =============================================================================

class SWGChatClient:
    """Async SWG client that connects to game server and manages chatroom."""

    def __init__(self, cfg, log, on_chat, on_tell, on_server_status):
        self.cfg = cfg
        self.log = log
        self.on_chat = on_chat
        self.on_tell = on_tell
        self.on_server_status = on_server_status

        # In-order delivery: default OFF. Enable per bot with "inOrderDelivery": true.
        # 10s of unfilled hole = ~16 of Core3's ~600ms resend cycles; generous on
        # purpose, because a skip is a HARD COMMIT (once acked, Core3 deletes it).
        self.in_order = bool(cfg.get('inOrderDelivery', False))
        self.STALL_SECS = float(cfg.get('inOrderStallSecs', 10))

        # Fragment sequence fix: default OFF. Enable per bot with "fragmentSeqFix": true.
        # Stops us burning a reliable sequence on every fragmented send (any relayed
        # message over ~210 chars, and any tell over ~200). See _fragment_and_encrypt.
        self.frag_seq_fix = bool(cfg.get('fragmentSeqFix', False))

        self.protocol = SOEProtocol(in_order=self.in_order,
                                    frag_seq_fix=self.frag_seq_fix)
        self.transport = None
        self.loop = None

        # State
        self.host = cfg['LoginAddress']
        self.port = cfg['LoginPort']
        self.ping_port = None
        self.logged_in = False
        self.connected = False
        self.paused = False
        self.character = cfg['Character']
        self.server_name = None
        self.server_names = {}
        self.servers = {}
        self.character_id = None
        self.chat_room_id = None
        self.chat_room_path = cfg['ChatRoom']
        self.chat_room_full_path = None  # resolved full path from server, used for health check queries

        self.last_message_time = time.time()
        self.fails = 0
        self.tell_counter = 1
        self._reconnecting = False
        self._reconnect_delay = 2  # exponential backoff: 2 → 4 → 8 → ... → 60
        self._tasks = []

        # Metrics
        self.start_time = time.time()
        self.reconnect_count = 0
        self.messages_sent = 0
        self.messages_received = 0
        self.last_room_response = time.time()  # tracks last successful room query/enter

        # Deafness watchdog (Phase 1b) + source filter (Phase 1a)
        self.filtered_packets = 0     # datagrams dropped as not-from-our-peer
        self.datagrams_in = 0         # non-ping datagrams accepted from our peer
        self.watchdog_trips = 0
        self._watchdog_cooldown_until = 0.0

        self.verbose = cfg.get('verboseSWGLogging', False)

        if self.verbose:
            self.log.setLevel(logging.DEBUG)

    async def start(self):
        """Start the UDP client."""
        if self._tasks:
            return  # already running — don't duplicate tasks
        self.loop = asyncio.get_running_loop()
        self.start_time = time.time()
        await self._connect()

        self._tasks = [
            asyncio.create_task(self._ack_loop()),
            asyncio.create_task(self._ping_loop()),
            asyncio.create_task(self._netstatus_loop()),
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._deafness_watchdog()),
        ]

        # A background task dying on an unhandled exception used to vanish silently,
        # taking its safeguard with it (a struct.error killed the health task this way
        # on 2026-07-12). Surface it instead.
        for t in self._tasks:
            t.add_done_callback(self._task_died)

    def _task_died(self, task):
        """A background task ended. If it crashed, say so — do not lose the safeguard silently."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self.log.error(f"BACKGROUND TASK DIED: {task.get_coro().__name__} — {exc!r}", exc_info=exc)

    async def stop(self):
        """Stop the UDP client and cancel background tasks."""
        for task in self._tasks:
            if task and not task.done():
                task.cancel()
        self._tasks = []
        if self.transport:
            self.transport.close()
            self.transport = None

    async def _connect(self):
        """Open UDP socket and send session request."""
        self.logged_in = False
        self.connected = False
        self.host = self.cfg['LoginAddress']
        self.port = self.cfg['LoginPort']
        self.ping_port = None
        self.protocol = SOEProtocol(in_order=self.in_order,
                                    frag_seq_fix=self.frag_seq_fix)

        if self.transport:
            self.transport.close()

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._on_data),
            local_addr=('0.0.0.0', 0)
        )
        self.transport = transport
        self._send_raw(self.protocol.encode_session_request())

    def _send_raw(self, data):
        """Send raw bytes to current server."""
        if data is None or self.transport is None:
            return
        if isinstance(data, list):
            for d in data:
                self.transport.sendto(bytes(d), (self.host, self.port))
        else:
            self.transport.sendto(bytes(data), (self.host, self.port))

    def _on_data(self, data, addr):
        """Handle incoming UDP packet."""
        # PHASE 1a — source filter. The login->zone handoff REUSES this socket:
        # _handle_EnumerateCharacterId swaps in a fresh SOEProtocol() and retargets
        # self.port, but the transport is never recreated. So the login server —
        # which still has us in its sequenceBuffer and keeps resending its unacked
        # head — can land packets on the ZONE protocol object. Decrypted with the
        # wrong (or zero) crc_seed, a stale packet's reliable header is garbage,
        # i.e. a RANDOM 16-bit sequence stamp fed straight into sequence state.
        # Drop anything not from the peer we are currently talking to.
        if addr[1] not in (self.port, self.ping_port):
            self.filtered_packets += 1
            return

        # Liveness is stamped only for traffic we ACCEPT as ours. This must stay
        # BELOW the filter: a stream of stale login-server packets refreshing
        # last_message_time would suppress the 55s dead-link failsafe in _ack_loop.
        self.last_message_time = time.time()

        if self.ping_port and addr[1] == self.ping_port:
            return

        self.datagrams_in += 1          # NON-ping datagrams — the watchdog's "traffic is flowing" signal

        try:
            packets = self.protocol.decode(data)
        except Exception as e:
            self.log.warning(f"Decode error (skipping packet): {e}")
            return

        if not packets:
            return

        for pkt in packets:
            ptype = pkt.get('type', '')
            if self.verbose and ptype not in NOISY_RECV_PACKETS:
                # Show packet data for debugging, but truncate large payloads
                pkt_summary = {k: v for k, v in pkt.items() if k != '_raw'}
                detail = str(pkt_summary)
                if len(detail) > 500:
                    detail = detail[:500] + '...'
                self.log.debug(f"recv: {ptype} {detail}")
            handler = getattr(self, f'_handle_{ptype}', None)
            if handler:
                handler(pkt)

    # --- Packet handlers ---

    def _handle_SessionResponse(self, pkt):
        if not self.logged_in:
            self._send_raw(self.protocol.encode_login_client_id(
                self.cfg['Username'], self.cfg['Password']))
        else:
            self._send_raw(self.protocol.encode_client_id_msg())

    def _handle_LoginClientToken(self, pkt):
        self.log.info("Logged into SWG login server")
        self.logged_in = True

    def _handle_LoginEnumCluster(self, pkt):
        self.server_names = pkt.get('servers', {})

    def _handle_LoginClusterStatus(self, pkt):
        self.servers = pkt.get('servers', {})

    def _handle_EnumerateCharacterId(self, pkt):
        characters = pkt.get('characters', {})
        character = characters.get(self.character)
        if not character:
            for name, char in characters.items():
                if char.get('name', '').startswith(self.character):
                    character = char
                    break

        if not character:
            self.log.error(f"Character '{self.character}' not found!")
            return

        server_id = character['server_id']
        server_data = self.servers.get(server_id, {})
        self.port = server_data.get('port', self.port)
        self.ping_port = server_data.get('ping_port')
        self.character_id = character['character_id']

        if server_id in self.server_names:
            self.server_name = self.server_names[server_id].get('name', '')

        self.log.info(f"Connecting to zone server {self.host}:{self.port}")

        session_key = self.protocol.session.session_key
        self.protocol = SOEProtocol(in_order=self.in_order,
                                    frag_seq_fix=self.frag_seq_fix)
        self.protocol.session.session_key = session_key
        self._send_raw(self.protocol.encode_session_request())

    def _handle_ClientPermissions(self, pkt):
        self._send_raw(self.protocol.encode_select_character(self.character_id))
        asyncio.get_running_loop().call_later(1.0, self._create_chatroom)

    def _create_chatroom(self):
        """Create the chatroom (also serves as join if it exists)."""
        room_path = self.chat_room_path
        if not room_path.startswith("SWG."):
            room_path = f"SWG.{self.server_name}.{room_path}"

        self.log.info(f"Creating/joining chatroom: {room_path}")
        self._send_raw(self._encode_chat_create_room(room_path))
        # Also query the room to get its ID (create returns error 24 if room exists)
        asyncio.get_running_loop().call_later(0.5, self._query_chatroom, room_path)
        asyncio.get_running_loop().call_later(1.0, self._send_scene_ready)

    def _query_chatroom(self, room_path):
        """Send ChatQueryRoom to get room ID by path."""
        self.log.info(f"Querying chatroom: {room_path}")
        self._send_raw(self._encode_chat_query_room(room_path))

    def _send_scene_ready(self):
        self._send_raw(self.protocol.encode_cmd_scene_ready())

    def _handle_ChatRoomList(self, pkt):
        rooms = pkt.get('rooms', {})
        target_room = self.chat_room_path
        for room_id, room in rooms.items():
            room_path = room.get('path', '')
            if room_path.endswith(target_room) or target_room in room_path:
                self.chat_room_id = room.get('id', room_id)
                self.chat_room_full_path = room_path
                self.log.info(f"Found chatroom: {room_path} (ID: {self.chat_room_id})")
                self._send_raw(self._encode_chat_enter_room(self.chat_room_id))
                break

    def _handle_ChatOnCreateRoom(self, pkt):
        """Server response to our create/join room request."""
        room_path = pkt.get('room_path', '')
        room_id = pkt.get('room_id', 0)
        error = pkt.get('error', 0)
        if room_id and room_path:
            target = self.chat_room_path
            if target in room_path or room_path.endswith(target.split('.')[-1]):
                self.chat_room_id = room_id
                self.chat_room_full_path = room_path
                self.log.info(f"Created chatroom: {room_path} (ID: {room_id})")
                self._send_raw(self._encode_chat_enter_room(room_id))
        else:
            self.log.debug(f"ChatOnCreateRoom error {error} — room may already exist, waiting for query result")

    def _handle_ChatQueryRoomResults(self, pkt):
        """Server response to ChatQueryRoom — gives us room ID from path."""
        room_path = pkt.get('room_path', '')
        room_id = pkt.get('room_id', 0)
        target = self.chat_room_path
        if room_id and (target in room_path or room_path.endswith(target.split('.')[-1])):
            self.chat_room_id = room_id
            self.chat_room_full_path = room_path
            self.last_room_response = time.time()
            self.log.info(f"Found chatroom via query: {room_path} (ID: {room_id})")
            # Only (re)enter when not already in the room. The 60s liveness
            # query stays, but re-entering on every query produced join/leave
            # churn the health monitor misread as a zombie.
            if not self.connected:
                self._send_raw(self._encode_chat_enter_room(room_id))

    def _handle_ChatOnEnteredRoom(self, pkt):
        player = pkt.get('player', '')
        room_id = pkt.get('room_id', 0)
        if room_id == self.chat_room_id and player.lower() == self.character.lower():
            if not self.connected:
                self.connected = True
                self.log.info(f"Entered chatroom ID# {room_id} as {player}")
            self.last_room_response = time.time()
            self.on_server_status(True)
            self.fails = 0
            self._reconnect_delay = 2  # reset backoff on success

    def _handle_ChatRoomMessage(self, pkt):
        char_name = pkt.get('character', '')
        room_id = pkt.get('room_id', 0)
        message = pkt.get('message', '')
        if room_id == self.chat_room_id and char_name.lower() != self.character.lower():
            self.messages_received += 1
            if not self.paused:
                self.on_chat(char_name, message)

    def _handle_ChatInstantMessageToClient(self, pkt):
        player = pkt.get('player', '')
        message = pkt.get('message', '')
        if player.lower() != self.character.lower():
            self.on_tell(player, message)

    def _handle_ChatOnLeaveRoom(self, pkt):
        room_id = pkt.get('room_id', 0)
        player = pkt.get('player', '')
        error = pkt.get('error', 0)
        if room_id == self.chat_room_id and player.lower() == self.character.lower():
            self.log.warning(f"Left chatroom ID# {room_id} (error: {error}), will rejoin")
            self.connected = False
            asyncio.get_running_loop().call_later(2.0, self._create_chatroom)

    def _handle_Disconnect(self, pkt):
        self.log.warning(f"Disconnect from server: {pkt}")

    # --- Send methods ---

    def send_chat(self, message, sender):
        """Send a message to the SWG chatroom."""
        if not self.connected:
            return
        message = strip_emoji(message)
        sender = strip_emoji(sender)          # Discord display names carry emoji too
        if not message.strip():
            # The message was nothing but emoji — there is nothing left to relay, and an
            # empty chat line in-game is just noise.
            self.log.info(f"Dropping emoji-only message from {sender!r} — nothing to relay")
            return
        colored = f' \\#ff3333{sender}: \\#ff66ff{message}'
        if len(colored) > 2000:
            colored = colored[:2000]
        self._send_raw(self.protocol.encode_chat_send_to_room(colored, self.chat_room_id))
        self.messages_sent += 1

    def send_tell(self, player, message):
        """Send a tell to a player."""
        if not self.connected:
            return
        message = strip_emoji(message)
        if not message.strip():
            return
        if len(message) > 400:
            message = message[:400]
        self._send_raw(self._encode_chat_instant_message(player, message))

    # --- Encode helpers not in soe_protocol yet ---

    def _encode_chat_create_room(self, room_path, title=""):
        """Encode ChatCreateRoom (0x35366bed)."""
        header = self.protocol.encode_soe_header(0x35366bed, 7)
        buf = bytearray(496)
        buf[0] = 1   # public
        buf[1] = 0   # no moderation
        off = 4
        path_bytes = room_path.encode('ascii')
        struct.pack_into('<H', buf, off, len(path_bytes))
        off += 2
        buf[off:off + len(path_bytes)] = path_bytes
        off += len(path_bytes)
        title_bytes = title.encode('ascii')
        struct.pack_into('<H', buf, off, len(title_bytes))
        off += 2
        buf[off:off + len(title_bytes)] = title_bytes
        off += len(title_bytes)
        struct.pack_into('<I', buf, off, self.protocol.session.request_id)
        self.protocol.session.request_id += 1
        off += 4
        return self.protocol.encrypt(header + buf[:off])

    def _encode_chat_query_room(self, room_path):
        """Encode ChatQueryRoom (0x9cf2b192)."""
        header = self.protocol.encode_soe_header(0x9cf2b192, 3)
        path_bytes = room_path.encode('ascii')
        buf = bytearray(4 + 2 + len(path_bytes))
        struct.pack_into('<I', buf, 0, self.protocol.session.request_id)
        self.protocol.session.request_id += 1
        struct.pack_into('<H', buf, 4, len(path_bytes))
        buf[6:6 + len(path_bytes)] = path_bytes
        return self.protocol.encrypt(header + buf)

    def _encode_chat_enter_room(self, room_id):
        """Encode ChatEnterRoomById (0xbc6bddf2)."""
        header = self.protocol.encode_soe_header(0xbc6bddf2, 3)
        buf = bytearray(8)
        struct.pack_into('<I', buf, 0, self.protocol.session.request_id)
        self.protocol.session.request_id += 1
        struct.pack_into('<I', buf, 4, room_id)
        return self.protocol.encrypt(header + buf)

    def _encode_chat_instant_message(self, player, message):
        """Encode ChatInstantMessageToCharacter (0x84bb21f7)."""
        header = self.protocol.encode_soe_header(0x84bb21f7, 5)
        msg_encoded = message.encode('utf-16-le')
        # Calculate actual size needed: 3 astrings + uint32 + msg + uint32 + uint32
        server = self.server_name or ""
        needed = (2 + 3) + (2 + len(server)) + (2 + len(player)) + 4 + len(msg_encoded) + 4 + 4
        buf = bytearray(needed)
        off = 0
        off = _write_astring(buf, off, "SWG")
        off = _write_astring(buf, off, self.server_name or "")
        off = _write_astring(buf, off, player)
        struct.pack_into('<I', buf, off, len(message))
        off += 4
        buf[off:off + len(msg_encoded)] = msg_encoded
        off += len(msg_encoded)
        struct.pack_into('<I', buf, off, 0)
        off += 4
        struct.pack_into('<I', buf, off, self.tell_counter)
        self.tell_counter += 1
        off += 4
        return self.protocol.encrypt(header + buf[:off])

    # --- Background loops ---

    async def _reconnect(self):
        """Reconnect to the server with exponential backoff."""
        if self._reconnecting:
            return
        self._reconnecting = True
        self.reconnect_count += 1
        try:
            self.log.info(f"Reconnecting (attempt #{self.reconnect_count}, delay {self._reconnect_delay}s)...")
            if self.transport:
                # Send a PROTOCOL disconnect before dropping the socket. Closing
                # the UDP socket alone leaves the SWG server holding our chatroom
                # subscription, and it keeps routing chat to the dead session —
                # the new session then receives ZERO inbound chat, permanently.
                # This is the exact bug fixed in 420cba3 ("auto-restart uses
                # disconnect() not stop() — prevents stale chatroom subscription",
                # msgs_in=0 forever, seen on cwi/dc/live in April). That fix was
                # applied to _auto_restart and shutdown, but NOT here — and this
                # is the one teardown path that runs during a FAULT. So the
                # self-heal was cementing the very deafness it meant to cure
                # (2026-07-12). Best-effort: the socket may already be dead.
                # try/finally: a task cancellation during the 0.2s await must not
                # skip the close and leak the socket (GLM-5.2 review, 2026-07-12).
                try:
                    self._send_raw(self.protocol.encode_disconnect())
                    await asyncio.sleep(0.2)      # let the packet leave
                except Exception:
                    pass
                finally:
                    self.transport.close()
                    self.transport = None
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(self._reconnect_delay * 2, 60)
            await self._connect()
        finally:
            self._reconnecting = False

    async def _deafness_watchdog(self):
        """Force a reconnect when the SEQUENCE LAYER is dead but the socket is not.

        Every deafness mode we have had or can construct shares one signature:
        datagrams keep arriving, and not one reliable packet is ACCEPTED.
          - 16-bit wrap desync (the 2026-07-12 outage): bots deaf ~3.4h into every
            session while reporting connected=True.
          - Poisoned bootstrap / sequence desync: every packet reads as a duplicate.
          - A stalled hole under in-order delivery (below).
          - Whatever we have not thought of yet. THIS is why the watchdog is keyed
            on a liveness signal rather than on any specific fault.

        Nothing today catches this class. The 55s no-data timer (_ack_loop) needs
        TOTAL silence, and the server's own retransmits keep it fed forever. The
        room-query self-heal needs `connected` AND a room id and takes 300s. A bot
        stuck deaf mid-handshake never reaches `connected` at all, so it is covered
        by NOTHING — Core3 resends the unacked handshake forever, the socket stays
        warm, and the bot is silently dead until the 4h restart timer.

        The >=10-datagram floor is the "traffic is actually flowing" gate: a quiet
        dev server can legitimately see a 30s window with zero reliable packets
        (just ~2 unsequenced net-status replies), and an unfloored watchdog would
        reconnect-loop there forever. Every real deafness mode FLOODS the window
        instead, because Core3 is retransmitting its unacked head at 0.6-2s
        intervals. 10 sits an order of magnitude below the failure signature and an
        order above quiet-idle.
        """
        WINDOW = 30.0
        MIN_DATAGRAMS = 10
        while True:
            # Snapshot the PROTOCOL OBJECT, not just its counter. self.protocol is
            # REPLACED on _connect and on the login->zone handoff, so comparing a
            # counter across a swap yields a negative delta and silently MISSES a
            # deafness event. Sample and compare the same object, or skip the window.
            proto = self.protocol
            accepted_before = proto.session.reliable_accepted
            datagrams_before = self.datagrams_in
            paused_before = self.paused
            await asyncio.sleep(WINDOW)

            # Guards are re-checked AFTER the sleep, so anything that was true for any
            # part of the window invalidates it. A bot that was PAUSED sits in the
            # watchdog's exact signature — it stops acking, so Core3 fills its unacked
            # window and floods resends: datagrams >> 10, accepted == 0. If the window
            # merely ENDED unpaused we would force-reconnect a perfectly healthy bot.
            # Same for a reconnect or a protocol swap mid-window: the counters are not
            # comparable. In every one of those cases, discard the window.
            if (self.paused or paused_before or self._reconnecting
                    or not self.transport or self.protocol is not proto):
                continue

            accepted = proto.session.reliable_accepted - accepted_before
            datagrams = self.datagrams_in - datagrams_before

            if accepted == 0 and datagrams >= MIN_DATAGRAMS:
                # Cooldown: a reconnect cannot fix a fault that is INSIDE us (e.g. a
                # dead _ack_loop means we never ack, Core3 floods resends, and we trip
                # again on the very next window). Without this, silent deafness would
                # be traded for an endless reconnect loop — each one dropping chat.
                # Reconnect, then give it room to actually establish before judging again.
                if time.monotonic() - self._watchdog_cooldown_until < 0:
                    continue
                self._watchdog_cooldown_until = time.monotonic() + 120

                self.watchdog_trips += 1
                self.log.warning(
                    f"WATCHDOG: {datagrams} datagrams in {WINDOW:.0f}s, ZERO reliable packets "
                    f"accepted — sequence layer is deaf while the socket is alive. "
                    f"Forcing reconnect (trip #{self.watchdog_trips})."
                )
                if self.watchdog_trips >= 3:
                    self.log.error(
                        f"WATCHDOG has now fired {self.watchdog_trips} times — reconnecting is "
                        f"NOT curing this. The fault is likely on our side (a dead background "
                        f"task?), not the link. Investigate; do not assume the reconnect fixed it."
                    )
                await self._reconnect()

    async def _ack_loop(self):
        """Send ACKs and check for timeouts."""
        while True:
            await asyncio.sleep(0.1)
            if self.paused:
                continue
            # STALL VALVE. If a hole refuses to fill while traffic is clearly still
            # flowing, give up on it rather than sit deaf forever. In-order delivery
            # turns "silently lose one packet" into "possibly stall", and a stall is
            # the failure class this whole workstream exists to kill — so it needs an
            # exit. Skipping IS today's behavior (lose it, move on), so the worst case
            # is no worse than the status quo and this cannot create a NEW deafness mode.
            #
            # Gated on "datagrams are still arriving" — NOT on any buffer being
            # non-empty, which was blind in exactly the cases that matter.
            s = self.protocol.session
            if (self.protocol.in_order and s.gap_since is not None
                    and (time.monotonic() - s.gap_since) > self.STALL_SECS
                    and (time.time() - self.last_message_time) < 5):
                hole = s.next_expected
                lost = self.protocol.force_skip_gap()
                self.log.warning(
                    f"STALL: reliable packet {hole} never arrived after "
                    f"{self.STALL_SECS}s of live traffic — skipping to {s.next_expected} "
                    f"({lost} packet(s) abandoned; total skipped={s.packets_skipped})")

            ack = self.protocol.encode_ack()
            if ack:
                self._send_raw(ack)
            if time.time() - self.last_message_time > 55:
                self.fails += 1
                self.log.warning(f"No data for 55s (fail #{self.fails})")
                self.connected = False
                if self.fails == 3:
                    self.on_server_status(False)
                if self.fails >= 5:
                    self.log.warning("5 consecutive failures — waiting 30s before retry")
                    await asyncio.sleep(30)
                    self.fails = 0
                self.last_message_time = time.time()
                await self._reconnect()

    async def _ping_loop(self):
        """Send pings every second."""
        while True:
            await asyncio.sleep(1.0)
            if not self.ping_port or not self.connected:
                continue
            buf = bytearray(4)
            tick = int(time.time() * 1000) & 0xFFFF
            struct.pack_into('>H', buf, 0, tick)
            struct.pack_into('>H', buf, 2, 0x7701)
            if self.transport:
                self.transport.sendto(bytes(buf), (self.host, self.ping_port))

    async def _netstatus_loop(self):
        """Send net status every 15 seconds."""
        while True:
            await asyncio.sleep(15.0)
            if not self.connected:
                continue
            self._send_raw(self.protocol.encode_net_status())

    async def _health_check_loop(self):
        """Periodic chatroom health check — verify we're still in the right room.
        Self-heal: if the SWG connection goes silently dead (room queries stop
        echoing), force a reconnect. That room-query timeout is the one reliable
        liveness signal; the former msgs_out / msgs_in reconnect heuristics were
        removed 2026-05-22 — they false-positived on every normal quiet room
        (see chat-bridge-self-heal-falsepositive-fix-2026-05-21.md)."""
        last_check_msgs_in = 0
        in_stale_checks = 0
        IN_STALE_THRESHOLD = 60  # minutes of no inbound chat before a log-only notice

        while True:
            await asyncio.sleep(60.0)
            if not self.connected or not self.chat_room_id:
                in_stale_checks = 0
                continue

            # Re-query room to verify membership — use resolved full path if available
            room_path = self.chat_room_full_path
            if not room_path:
                room_path = self.chat_room_path
                if not room_path.startswith("SWG."):
                    room_path = f"SWG.{self.server_name}.{room_path}"
            self._send_raw(self._encode_chat_query_room(room_path))

            # Self-heal: room query responses stopped.
            # The health check sends a query every 60s — if no response for 5+
            # minutes, the SWG socket is silently dead. This is the ONLY reliable
            # liveness signal, so it keeps the forced reconnect.
            room_stale = time.time() - self.last_room_response
            if room_stale > 300:
                self.log.warning(
                    f"SELF-HEAL: No room query response for {int(room_stale)}s — "
                    f"SWG connection likely dead. Forcing reconnect.")
                self.connected = False
                await self._reconnect()
                continue

            # Inbound-stall notice — LOG-ONLY, not a reconnect trigger.
            # "msgs_in flat for 60 min" cannot tell a genuinely quiet room from a
            # dropped subscription, so forcing a reconnect false-positived on
            # every low-traffic room. The room-query check above already catches
            # a truly dead connection. Logged at info for visibility only.
            if self.messages_received == last_check_msgs_in:
                in_stale_checks += 1
                if in_stale_checks == IN_STALE_THRESHOLD:
                    self.log.info(
                        f"No inbound chat for {in_stale_checks} min — room is quiet "
                        f"(query responses still arriving; not reconnecting).")
            else:
                in_stale_checks = 0

            last_check_msgs_in = self.messages_received

            # Log metrics every 5 minutes
            uptime = int(time.time() - self.start_time)
            if uptime % 300 < 65:  # within the first health check of each 5-min window
                # seq/room_stale are the diagnostics that were missing on 2026-07-12:
                # `connected=True` only ever meant "socket alive", so a bot that had
                # wrapped its 16-bit sequence (and was discarding every packet) read
                # as perfectly healthy. seq crossing 65535 while msgs_in keeps
                # climbing is the proof the wrap fix is working.
                seq = self.protocol.session.last_sequence if self.protocol else -1
                # rel_ok = reliable packets ACCEPTED. This is the honest liveness
                # number: `connected` and even `seq` can look fine while the
                # sequence layer is deaf. If rel_ok stops climbing while datagrams
                # keep arriving, the bot is deaf — and the watchdog will say so.
                rel_ok = self.protocol.session.reliable_accepted if self.protocol else -1
                room_stale = int(time.time() - self.last_room_response)
                extra = ""
                if self.filtered_packets:
                    extra += f" filtered={self.filtered_packets}"
                if self.watchdog_trips:
                    extra += f" wdog={self.watchdog_trips}"
                # OUTBOUND health. room_stale was the ONLY witness to an outbound stall
                # (and it only samples every 5 min); ooo is the direct one — Core3 telling
                # us it is missing a packet we were supposed to send. A small count is
                # benign (UDP reordering between fragment datagrams, healed from Core3's
                # receiveBuffer); a sustained climb with room_stale rising = outbound dead.
                if self.protocol:
                    if self.protocol.session.out_of_order_in:
                        extra += f" ooo={self.protocol.session.out_of_order_in}"
                    if self.protocol.session.oversize_out:
                        extra += f" oversize={self.protocol.session.oversize_out}"
                if self.frag_seq_fix:
                    extra += " fragfix=on"
                self.log.info(
                    f"Health: uptime={uptime}s connected={self.connected} "
                    f"room={self.chat_room_id} reconnects={self.reconnect_count} "
                    f"msgs_in={self.messages_received} msgs_out={self.messages_sent} "
                    f"seq={seq} rel_ok={rel_ok} room_stale={room_stale}s{extra}"
                    f"{' in_stale=' + str(in_stale_checks) if in_stale_checks > 0 else ''}")

    def get_stats(self):
        """Return current metrics dict."""
        return {
            'uptime': int(time.time() - self.start_time),
            'connected': self.connected,
            'room_id': self.chat_room_id,
            'reconnects': self.reconnect_count,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'fails': self.fails,
        }

    async def disconnect(self):
        """Send clean disconnect to SWG server before stopping."""
        if self.transport:
            try:
                self._send_raw(self.protocol.encode_disconnect())
                await asyncio.sleep(0.2)  # let packet go out
            except Exception:
                pass
        await self.stop()


class _UDPProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol adapter."""

    def __init__(self, callback):
        self.callback = callback

    def datagram_received(self, data, addr):
        self.callback(data, addr)

    def error_received(self, exc):
        logging.getLogger('udp').error(f"UDP error: {exc}")


def _write_astring(buf, off, s):
    """Write an ASCII string (2-byte length prefix)."""
    encoded = s.encode('ascii')
    struct.pack_into('<H', buf, off, len(encoded))
    off += 2
    buf[off:off + len(encoded)] = encoded
    off += len(encoded)
    return off


# =============================================================================
# Discord Bot — one instance per config file
# =============================================================================

class ChatBridge(discord.Client):
    """Discord client that bridges to SWG chat."""

    def __init__(self, bot_cfg, config_name):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True
        super().__init__(intents=intents)

        self.swg_cfg = bot_cfg['SWG']
        self.discord_cfg = bot_cfg['Discord']
        self.config_name = config_name
        self.bot_name = self.discord_cfg.get('BotName', config_name)
        self.log = logging.getLogger(config_name)

        self.swg = SWGChatClient(
            self.swg_cfg,
            log=self.log,
            on_chat=self._relay_chat,
            on_tell=self._relay_tell,
            on_server_status=self._relay_server_status,
        )

        self.chat_channel = None
        # Persisted across bot restarts so a restart can't forget we already announced
        # DOWN and then swallow the recovery UP. None = never recorded (genuine first start).
        self._status_state_file = os.path.join(STATE_DIR, f"{self.config_name}.status")
        self._last_notified_status = self._load_status()
        # Gate DOWN announcements until we've confirmed connectivity at least once this
        # session: a fails==3 during our own (re)connect handshake can't be told apart from
        # a real server-down, and against a persisted UP state would fire a spurious DOWN.
        self._connected_this_session = False
        self.notification_channel = None
        self.notification_tag = ""
        self.notification_user_id = self.discord_cfg.get('NotificationMentionUserID', '')
        self.server_guild = None
        self.verbose_discord = self.discord_cfg.get('verboseDiscordLogging', False)

        # Admin access — users and channels allowed to run admin commands
        # Supports both dict {"id": "label"} and list ["id"] formats
        admin_users = self.discord_cfg.get('AdminUsers', self.discord_cfg.get('AdminUserIDs', []))
        admin_channels = self.discord_cfg.get('AdminChannels', self.discord_cfg.get('AdminChannelIDs', []))
        # Dict keys or list items — either way, extract the IDs
        self.admin_user_ids = set(str(u) for u in (admin_users.keys() if isinstance(admin_users, dict) else admin_users))
        self.admin_channel_ids = set(str(c) for c in (admin_channels.keys() if isinstance(admin_channels, dict) else admin_channels))
        # Always include notification user as admin
        if self.notification_user_id:
            self.admin_user_ids.add(str(self.notification_user_id))

        if self.verbose_discord:
            self.log.setLevel(logging.DEBUG)

    async def setup_hook(self):
        restart_mins = self.discord_cfg.get('AutoRestartTimer', 0)
        if restart_mins:
            self.log.info(f"Auto-restart scheduled in {restart_mins} minutes")

            async def _auto_restart():
                await asyncio.sleep(restart_mins * 60)
                self.log.info("Auto-restart triggered")
                # disconnect() sends encode_disconnect() first, so SWG server cleans
                # up our chatroom subscription. stop() alone just drops the UDP socket,
                # leaving server-side subscription stale — new session then receives
                # no chat room messages (msgs_in stays 0). See RCA 2026-04-19.
                await self.swg.disconnect()
                await self.close()

            asyncio.create_task(_auto_restart())

    async def on_ready(self):
        self.log.info(f"Discord ready: {self.user}")

        self.server_guild = self.get_guild(int(self.discord_cfg['ServerID']))
        if not self.server_guild:
            self.log.error(f"Guild {self.discord_cfg['ServerID']} not found!")
            return

        for ch in self.server_guild.text_channels:
            if ch.name == self.discord_cfg['ChatChannel']:
                self.chat_channel = ch
            if ch.name == self.discord_cfg.get('NotificationChannel', ''):
                self.notification_channel = ch

        if not self.chat_channel:
            self.log.error(f"Chat channel '{self.discord_cfg['ChatChannel']}' not found!")

        role_name = self.discord_cfg.get('NotificationMentionRole', '')
        role = discord.utils.get(self.server_guild.roles, name=role_name) if role_name else None
        if role:
            self.notification_tag = f"<@&{role.id}> "
        elif self.notification_user_id:
            self.notification_tag = f"<@{self.notification_user_id}> "

        presence_name = self.discord_cfg.get('PresenceName', 'in-game')
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name=presence_name))

        await self.swg.start()
        self.log.info("SWG client started")

    async def on_resumed(self):
        """Discord gateway resumed after disconnect — SWG client stays running."""
        self.log.info("Discord reconnected (resumed)")

    async def on_disconnect(self):
        """Discord gateway disconnected — log but don't touch SWG."""
        self.log.warning("Discord gateway disconnected, will auto-reconnect")

    async def on_message(self, message):
        if self.verbose_discord:
            ch_name = getattr(message.channel, 'name', 'DM')
            self.log.debug(f"discord msg: #{ch_name} {message.author.display_name}: {message.clean_content[:200]}")

        if message.author == self.user or message.author.bot:
            return

        # DMs: only from notification user
        if isinstance(message.channel, discord.DMChannel):
            if str(message.author.id) != self.notification_user_id:
                return

        # Guild messages: only from chat or notification channel
        if isinstance(message.channel, discord.TextChannel):
            if message.channel.name not in (self.discord_cfg['ChatChannel'],
                                             self.discord_cfg.get('NotificationChannel', '')):
                return

        # Resolve display name
        if self.server_guild:
            member = self.server_guild.get_member(message.author.id)
            sender = member.display_name if member else message.author.display_name
        else:
            sender = message.author.display_name

        content = message.clean_content.lower()

        # Commands — admin check: user in AdminUserIDs or message in AdminChannelIDs
        is_admin = (str(message.author.id) in self.admin_user_ids or
                    str(getattr(message.channel, 'id', '')) in self.admin_channel_ids)

        if content.startswith('!server'):
            status = "is UP!" if self.swg.connected else "is DOWN :("
            await message.reply(f"{self.swg_cfg.get('SWGServerName', 'Server')} {status}")

        elif content.startswith('!status'):
            stats = self.swg.get_stats()
            uptime_h = stats['uptime'] // 3600
            uptime_m = (stats['uptime'] % 3600) // 60
            await message.reply(
                f"**{self.bot_name}** — {'Connected' if stats['connected'] else 'Disconnected'}\n"
                f"Uptime: {uptime_h}h {uptime_m}m | Room: {stats['room_id']}\n"
                f"Reconnects: {stats['reconnects']} | In: {stats['messages_received']} | Out: {stats['messages_sent']}")

        elif content.startswith('!fixchat'):
            if not is_admin:
                await message.reply("Only the bot owner can use !fixchat")
                return
            await message.reply(f"Rebooting {self.bot_name}")
            self.log.info(f"!fixchat from {sender}")
            await asyncio.sleep(0.5)
            await self.swg.disconnect()
            await self.close()

        elif content.startswith('!pausechat'):
            if not is_admin:
                await message.reply("Only the bot owner can use !pausechat")
                return
            self.swg.paused = not self.swg.paused
            status = "Un-pausing" if not self.swg.paused else "Pausing"
            await message.reply(f"{status} {self.bot_name}")
            self.log.info(f"!pausechat from {sender}")

        elif content.startswith('!debugchat') and is_admin:
            self.swg.verbose = True
            self.verbose_discord = True
            self.log.setLevel(logging.DEBUG)
            await message.reply(f"Enabling debug mode for {self.bot_name} (SWG + Discord verbose)")
            self.log.info(f"!debugchat from {sender}")

        # Forward chat channel messages to SWG
        if isinstance(message.channel, discord.TextChannel) and message.channel.name == self.discord_cfg['ChatChannel']:
            text = message.clean_content
            # Strip URLs — SWG client can't handle them and they cause disconnects
            text = re.sub(r'https?://\S+', '[link]', text)
            # Strip any HTML-like tags
            text = re.sub(r'<[^>]+>', '', text)
            text = text.strip()
            if text:
                self.swg.send_chat(text, sender)

    async def _send_to_discord(self, channel, content, retries=3):
        """Send a message to Discord with retry logic."""
        for i in range(retries):
            try:
                await channel.send(content)
                return True
            except discord.HTTPException as e:
                self.log.warning(f"Discord send failed (attempt {i+1}/{retries}): {e}")
                if i < retries - 1:
                    await asyncio.sleep(1 * (i + 1))
        self.log.error(f"Discord send FAILED after {retries} attempts: {content[:100]}")
        return False

    def _relay_chat(self, player, message):
        """Called by SWG client when game chat is received."""
        if self.chat_channel:
            asyncio.ensure_future(
                self._send_to_discord(self.chat_channel, f"**{player}:**  {message}"))

    def _relay_tell(self, player, message):
        """Called by SWG client when a tell is received."""
        if player.lower() != self.swg.character.lower():
            self.log.info(f"Tell from {player}: {message}")
            self.swg.send_tell(player, "Sorry, I don't talk to strangers ... XOXO")

    def _load_status(self):
        """Last-announced server status, persisted across bot restarts.
        Returns True/False, or None if never recorded (genuine first start)."""
        try:
            with open(self._status_state_file) as f:
                val = json.load(f)
            if isinstance(val, bool):
                return val
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log.warning(f"Could not read status state {self._status_state_file}: {e}")
        return None

    def _save_status(self):
        """Persist the last-announced status (atomic) so a restart can't lose it."""
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = self._status_state_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._last_notified_status, f)
            os.replace(tmp, self._status_state_file)
        except Exception as e:
            self.log.warning(f"Could not persist status state {self._status_state_file}: {e}")

    def _relay_server_status(self, is_up):
        """Called by SWG client on server up/down."""
        if is_up:
            # A True status only arrives from a confirmed chatroom entry = real connectivity.
            self._connected_this_session = True
        elif not self._connected_this_session:
            # Suppress a DOWN before our first successful connect this session — can't tell a
            # real server-down from our own stalled handshake. Don't touch persisted state.
            return
        if is_up == self._last_notified_status:
            return
        if self._last_notified_status is None:
            self._last_notified_status = is_up
            self._save_status()
            return  # Don't fire UP or DOWN on first connect (bot restart, not server event)
        self._last_notified_status = is_up
        self._save_status()
        if self.notification_channel:
            server_name = self.swg_cfg.get('SWGServerName', 'Server')
            status = "UP!" if is_up else "DOWN!"
            asyncio.ensure_future(
                self._send_to_discord(
                    self.notification_channel,
                    f"{self.notification_tag}The server {server_name} is {status}"))
        self.log.info(f"Server {'UP' if is_up else 'DOWN'}")


# =============================================================================
# Bot runner — folder scan, restart loop per bot
# =============================================================================

def validate_config(cfg, filename):
    """Validate that a config has all required keys. Returns error string or None."""
    if 'SWG' not in cfg:
        return f"missing 'SWG' section"
    if 'Discord' not in cfg:
        return f"missing 'Discord' section"

    missing_swg = REQUIRED_SWG_KEYS - set(cfg['SWG'].keys())
    if missing_swg:
        return f"missing SWG keys: {missing_swg}"

    missing_discord = REQUIRED_DISCORD_KEYS - set(cfg['Discord'].keys())
    if missing_discord:
        return f"missing Discord keys: {missing_discord}"

    try:
        int(cfg['Discord']['ServerID'])
    except (ValueError, TypeError):
        return f"ServerID must be a valid integer"

    return None


def load_configs(config_path):
    """Load bot configurations from a path (file or directory)."""
    path = pathlib.Path(config_path)

    if path.is_file():
        with open(path) as f:
            cfg = json.load(f)
        name = path.stem
        err = validate_config(cfg, path.name)
        if err:
            main_log.error(f"  Invalid config {path.name}: {err}")
            return []
        return [(name, cfg)]

    if path.is_dir():
        configs = []
        for json_file in sorted(path.glob('*.json')):
            if json_file.stem.startswith('example'):
                continue
            try:
                with open(json_file) as f:
                    cfg = json.load(f)

                err = validate_config(cfg, json_file.name)
                if err:
                    main_log.error(f"  Skipped {json_file.name}: {err}")
                    continue

                name = json_file.stem
                configs.append((name, cfg))
                main_log.info(f"  Loaded: {json_file.name} ({cfg['Discord'].get('BotName', name)})")
            except json.JSONDecodeError as e:
                main_log.error(f"  Skipped {json_file.name}: invalid JSON: {e}")
        return configs

    main_log.error(f"Config path not found: {config_path}")
    return []


async def run_bot(name, bot_cfg, startup_delay=0):
    """Run a single bot with automatic restart on failure."""
    log = logging.getLogger(name)
    restart_delay = 5

    if startup_delay > 0:
        log.info(f"Staggered start: waiting {startup_delay}s...")
        await asyncio.sleep(startup_delay)

    while True:
        bridge = None
        try:
            bridge = ChatBridge(bot_cfg, name)
            token = bot_cfg['Discord']['BotToken']
            log.info("Starting...")
            await bridge.start(token, reconnect=True)
            restart_delay = 5  # reset backoff on clean exit
        except asyncio.CancelledError:
            log.info("Shutting down")
            break
        except Exception as e:
            log.error(f"Crashed: {e}")
        finally:
            if bridge:
                try:
                    await bridge.swg.disconnect()
                except Exception:
                    pass
                # Close the DISCORD client too. discord.Client.start() does not tear
                # down its own aiohttp session or gateway websocket — only close() does.
                # Without this, every cancellation (now reachable on EVERY config
                # hot-reload, not just shutdown) leaks a session + fd and leaves a
                # zombie gateway connection alive under the same bot token.
                try:
                    if not bridge.is_closed():
                        await bridge.close()
                except Exception:
                    pass

        log.info(f"Restarting in {restart_delay}s...")
        await asyncio.sleep(restart_delay)
        restart_delay = min(restart_delay * 2, 60)


async def _healthcheck_loop():
    """Touch healthcheck file periodically so Docker can verify we're alive."""
    while True:
        try:
            pathlib.Path(HEALTHCHECK_FILE).touch()
        except OSError:
            pass
        await asyncio.sleep(30)


async def run_all(config_path):
    """Load configs and run bots with hot-reload — watches for added/removed config files."""
    path = pathlib.Path(config_path)
    if not path.is_dir():
        # Single file mode — no hot reload
        configs = load_configs(config_path)
        if not configs:
            main_log.error("No bot configs found!")
            return
        main_log.info(f"Starting {len(configs)} bot(s) (single file, no hot-reload)")
        tasks = [asyncio.create_task(run_bot(name, cfg, startup_delay=i * 5)) for i, (name, cfg) in enumerate(configs)]
        tasks.append(asyncio.create_task(_healthcheck_loop()))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: [t.cancel() for t in tasks])
        await asyncio.gather(*tasks, return_exceptions=True)
        main_log.info("All bots stopped")
        return

    # Directory mode — hot reload enabled
    bot_tasks = {}   # name -> asyncio.Task
    bot_configs = {}  # name -> config dict
    config_mtimes = {}  # name -> config file mtime; drives hot-reload on CHANGE
    all_tasks = []

    def _cancel_all():
        for t in bot_tasks.values():
            t.cancel()
        for t in all_tasks:
            t.cancel()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _cancel_all)

    async def _config_watcher():
        """Scan config directory every 10 seconds for changes."""
        while True:
            try:
                # Find current config files
                current_files = set()
                for json_file in path.glob('*.json'):
                    if json_file.stem.startswith('example'):
                        continue
                    current_files.add(json_file.stem)

                # Restart bots whose config CHANGED on disk.
                # Without this, an edited config is never re-read: the loop below skips
                # any bot that is already running, and run_bot() captured its cfg dict at
                # task-creation time. So "flip a flag in the config" silently did nothing,
                # and the only levers were a container restart (bounces all 6 bots) or a
                # delete-then-re-add dance. That means a flag-gated rollout had no rollback
                # at all — which is the whole point of gating it. (2026-07-12)
                for json_file in path.glob('*.json'):
                    name = json_file.stem
                    if name.startswith('example') or name not in bot_tasks:
                        continue
                    try:
                        mtime = json_file.stat().st_mtime
                    except OSError:
                        continue
                    if config_mtimes.get(name) == mtime:
                        continue
                    if name not in config_mtimes:          # first sight — just record it
                        config_mtimes[name] = mtime
                        continue
                    try:
                        with open(json_file) as f:
                            cfg = json.load(f)
                        err = validate_config(cfg, json_file.name)
                        if err:
                            main_log.error(f"Hot-reload: '{name}' config changed but is INVALID "
                                           f"({err}) — keeping the running bot on its old config.")
                            config_mtimes[name] = mtime
                            continue
                    except Exception as e:
                        # A half-written file (editor mid-save) must NOT kill a live bot.
                        # Leave mtime unrecorded so we retry on the next scan.
                        main_log.warning(f"Hot-reload: '{name}' config unreadable ({e}) — retrying.")
                        continue

                    main_log.info(f"Hot-reload: config changed — restarting bot '{name}'")
                    config_mtimes[name] = mtime
                    bot_tasks[name].cancel()
                    try:
                        await bot_tasks[name]
                    except (asyncio.CancelledError, Exception):
                        pass
                    bot_configs[name] = cfg
                    bot_tasks[name] = asyncio.create_task(run_bot(name, cfg))

                # Start new bots
                for json_file in path.glob('*.json'):
                    name = json_file.stem
                    if name.startswith('example'):
                        continue
                    if name in bot_tasks and not bot_tasks[name].done():
                        continue  # already running

                    try:
                        with open(json_file) as f:
                            cfg = json.load(f)
                        err = validate_config(cfg, json_file.name)
                        if err:
                            continue
                    except Exception:
                        continue

                    # Check for duplicate tokens against running bots
                    new_token = cfg['Discord']['BotToken']
                    dupe = False
                    for other_name, other_cfg in bot_configs.items():
                        if other_name != name and other_cfg['Discord']['BotToken'] == new_token:
                            main_log.error(f"  DUPLICATE TOKEN: {name} and {other_name}")
                            dupe = True
                            break
                    if dupe:
                        continue

                    main_log.info(f"Hot-reload: starting bot '{name}'")
                    bot_configs[name] = cfg
                    bot_tasks[name] = asyncio.create_task(run_bot(name, cfg))

                # Stop removed bots
                for name in list(bot_tasks.keys()):
                    if name not in current_files:
                        main_log.info(f"Hot-reload: stopping bot '{name}' (config removed)")
                        bot_tasks[name].cancel()
                        try:
                            await bot_tasks[name]
                        except (asyncio.CancelledError, Exception):
                            pass
                        del bot_tasks[name]
                        bot_configs.pop(name, None)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                main_log.error(f"Config watcher error: {e}")

            await asyncio.sleep(10)

    # Initial load
    configs = load_configs(config_path)
    if configs:
        # Check for duplicate tokens
        tokens = {}
        valid = []
        for name, cfg in configs:
            token = cfg['Discord']['BotToken']
            if token in tokens:
                main_log.error(f"  DUPLICATE TOKEN: {name} and {tokens[token]}")
                continue
            tokens[token] = name
            valid.append((name, cfg))

        main_log.info(f"Starting {len(valid)} bot(s) (hot-reload enabled, scanning every 10s)")
        for i, (name, cfg) in enumerate(valid):
            bot_configs[name] = cfg
            bot_tasks[name] = asyncio.create_task(run_bot(name, cfg, startup_delay=i * 5))
    else:
        main_log.info("No configs yet — watching for new ones (hot-reload enabled)")

    all_tasks = [
        asyncio.create_task(_healthcheck_loop()),
        asyncio.create_task(_config_watcher()),
    ]

    try:
        await asyncio.gather(*all_tasks, *bot_tasks.values(), return_exceptions=True)
    except asyncio.CancelledError:
        pass
    main_log.info("All bots stopped")


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('CONFIG_DIR', 'configs')
    main_log.info(f"SWG Chat Bridge v2 — scanning: {config_path}")
    asyncio.run(run_all(config_path))


if __name__ == '__main__':
    main()
