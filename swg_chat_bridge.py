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

# Required config keys for validation
REQUIRED_SWG_KEYS = {'LoginAddress', 'LoginPort', 'Character', 'ChatRoom', 'Username', 'Password'}
REQUIRED_DISCORD_KEYS = {'BotToken', 'ServerID', 'ChatChannel'}


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

        self.protocol = SOEProtocol()
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
        ]

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
        self.protocol = SOEProtocol()

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
        self.last_message_time = time.time()

        if self.ping_port and addr[1] == self.ping_port:
            return

        try:
            packets = self.protocol.decode(data)
        except Exception as e:
            self.log.warning(f"Decode error (skipping packet): {e}")
            return

        if not packets:
            return

        for pkt in packets:
            ptype = pkt.get('type', '')
            if self.verbose:
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
        self.protocol = SOEProtocol()
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
            self.last_room_response = time.time()
            self.log.info(f"Found chatroom via query: {room_path} (ID: {room_id})")
            self._send_raw(self._encode_chat_enter_room(room_id))

    def _handle_ChatOnEnteredRoom(self, pkt):
        player = pkt.get('player', '')
        room_id = pkt.get('room_id', 0)
        if room_id == self.chat_room_id and player.lower() == self.character.lower():
            if not self.connected:
                self.connected = True
                self.log.info(f"Entered chatroom ID# {room_id} as {player}")
            self.last_room_response = time.time()
            if self.fails >= 3:
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
        colored = f' \\#ff3333{sender}: \\#ff66ff{message}'
        if len(colored) > 2000:
            colored = colored[:2000]
        self._send_raw(self.protocol.encode_chat_send_to_room(colored, self.chat_room_id))
        self.messages_sent += 1

    def send_tell(self, player, message):
        """Send a tell to a player."""
        if not self.connected:
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
        buf = bytearray(512)
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
                self.transport.close()
                self.transport = None
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(self._reconnect_delay * 2, 60)
            await self._connect()
        finally:
            self._reconnecting = False

    async def _ack_loop(self):
        """Send ACKs and check for timeouts."""
        while True:
            await asyncio.sleep(0.1)
            if self.paused:
                continue
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
        Self-healing: if relay appears stuck (connected but no chatroom activity
        despite Discord sending messages), force a reconnect."""
        last_check_msgs_out = 0
        last_check_msgs_in = 0
        stale_checks = 0
        STALE_THRESHOLD = 10  # minutes of no outbound activity before reconnect

        while True:
            await asyncio.sleep(60.0)
            if not self.connected or not self.chat_room_id:
                stale_checks = 0
                continue

            # Re-query room to verify membership
            room_path = self.chat_room_path
            if not room_path.startswith("SWG."):
                room_path = f"SWG.{self.server_name}.{room_path}"
            self._send_raw(self._encode_chat_query_room(room_path))

            # Self-heal check 1: room query responses stopped
            # Health check sends a query every 60s — if no response for 5+ minutes,
            # the SWG connection is silently dead.
            room_stale = time.time() - self.last_room_response
            if room_stale > 300:
                self.log.warning(
                    f"SELF-HEAL: No room query response for {int(room_stale)}s — "
                    f"SWG connection likely dead. Forcing reconnect.")
                stale_checks = 0
                self.connected = False
                await self._reconnect()
                continue

            # Self-heal check 2: relay appears stuck
            # Discord is receiving messages (msgs_in up) but nothing sent to SWG (msgs_out flat)
            if self.messages_sent == last_check_msgs_out and self.messages_received > last_check_msgs_in:
                stale_checks += 1
                if stale_checks >= STALE_THRESHOLD:
                    self.log.warning(
                        f"SELF-HEAL: Relay appears stuck — {stale_checks} min with no outbound "
                        f"despite {self.messages_received - last_check_msgs_in} inbound. Forcing reconnect.")
                    stale_checks = 0
                    self.connected = False
                    await self._reconnect()
                    continue
            else:
                stale_checks = 0

            last_check_msgs_out = self.messages_sent
            last_check_msgs_in = self.messages_received

            # Log metrics every 5 minutes
            uptime = int(time.time() - self.start_time)
            if uptime % 300 < 65:  # within the first health check of each 5-min window
                self.log.info(
                    f"Health: uptime={uptime}s connected={self.connected} "
                    f"room={self.chat_room_id} reconnects={self.reconnect_count} "
                    f"msgs_in={self.messages_received} msgs_out={self.messages_sent}"
                    f"{' stale=' + str(stale_checks) if stale_checks > 0 else ''}")

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
                await self.swg.stop()
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
            self.swg.send_chat(message.clean_content, sender)

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

    def _relay_server_status(self, is_up):
        """Called by SWG client on server up/down."""
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


async def run_bot(name, bot_cfg):
    """Run a single bot with automatic restart on failure."""
    log = logging.getLogger(name)
    restart_delay = 5

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
        tasks = [asyncio.create_task(run_bot(name, cfg)) for name, cfg in configs]
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
        for name, cfg in valid:
            bot_configs[name] = cfg
            bot_tasks[name] = asyncio.create_task(run_bot(name, cfg))
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
