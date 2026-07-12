# SWG Discord Chat Bridge

A Python bot that bridges SWG in-game chatrooms to Discord channels. Drop a JSON config file per server — each one spawns an independent bot instance that logs into the game, joins a chatroom, and relays messages both ways.

Replaces the original 14-bot Node.js setup with a single Python process. Based on the original [swg-discord-bot](https://github.com/dpwhittaker/swg-discord-bot) by [dpwhittaker](https://github.com/dpwhittaker), which implemented the SOE protocol and SWG chat bridge in Node.js.

## Features

- **Multi-bot from one process** — each `.json` config in `configs/` spawns a separate bot
- **Hot-reload** — add/remove config files without restarting; watcher scans every 10 seconds
- **Auto-reconnect** — exponential backoff (2s → 60s) on SWG disconnect, auto-restart on crash
- **Health checks** — periodic chatroom verification, Docker healthcheck support, metrics logging
- **Server status** — notifies a Discord channel when the SWG server goes up or down
- **Admin commands** — `!fixchat`, `!pausechat`, `!debugchat`, `!status` with configurable permissions
- **Graceful shutdown** — clean SOE disconnect on SIGTERM/SIGINT
- **Discord resilience** — survives Discord gateway drops without restarting SWG connection

## Quick Start

### Run directly

> **Debian / Ubuntu one-time prerequisite.** The `venv` and `pip` modules are
> not bundled with the base `python3` package on Debian (or a minimal Ubuntu),
> so `python3 -m venv` fails with *"ensurepip is not available … you need to
> install the python3-venv package"*. Install them first:
>
> ```bash
> sudo apt update && sudo apt install -y python3-venv python3-pip
> ```
>
> (Fedora/RHEL: `sudo dnf install python3 python3-pip`. macOS/Windows: the
> python.org installer already includes both.)

```bash
# Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy and edit a config
cp configs/example.json configs/my-server.json
# Edit my-server.json with your SWG server and Discord bot details

# Run (scans configs/ folder)
python3 swg_chat_bridge.py

# Or run a single config
python3 swg_chat_bridge.py configs/my-server.json
```

### Run with Docker

**Important:** The compose file uses `network_mode: host` because the SWG login server communicates over UDP. Docker bridge networking blocks UDP responses, causing bots to timeout during the login handshake. Do not remove `network_mode: host`.

Bots start with a 5-second stagger between each to avoid overwhelming the login server with simultaneous connection attempts.

```bash
# Copy and edit a config
cp configs/example.json configs/my-server.json

# Build and run
docker compose up -d

# View logs
docker logs -f swg-chatbots

# Rebuild after code changes
git pull && docker compose down && docker compose up -d --build

# Add another bot (no restart needed — hot-reload picks it up)
cp configs/example.json configs/second-server.json
# Edit second-server.json, bot starts within 10 seconds

# Disable a bot without deleting (no restart needed)
mv configs/my-server.json configs/my-server.json.disabled
```

### Run with a process manager (PM2 or forever)

For a host without Docker, a Node process manager can keep the Python bridge
alive across crashes and reboots. Both run the **same** `swg_chat_bridge.py`
entry point — point them at the venv's interpreter so dependencies resolve, and
start from the repo root so the relative `configs/` path is found. (No
`network_mode` caveat here — running on the host directly, UDP to the SWG login
server works normally.)

The bridge already auto-reconnects to SWG and self-restarts its bot threads on
crash; the process manager only adds whole-process supervision (OOM kill, an
unhandled exit, host reboot).

**PM2** (recommended of the two — better logs, boot persistence):

```bash
npm install -g pm2          # one-time

# Start (scans configs/). Run from the repo root.
pm2 start swg_chat_bridge.py \
  --name swg-chat-bridge \
  --interpreter "$(pwd)/.venv/bin/python3" \
  --time                    # timestamp log lines

# Or a single config: args after `--`
pm2 start swg_chat_bridge.py --name swg-chat-bridge \
  --interpreter "$(pwd)/.venv/bin/python3" -- configs/my-server.json

pm2 logs swg-chat-bridge    # tail logs
pm2 restart swg-chat-bridge
pm2 stop swg-chat-bridge

# Survive a host reboot
pm2 save
pm2 startup                 # run the command it prints (sets up the init script)
```

**forever:**

```bash
npm install -g forever      # one-time

# -c sets the interpreter; run from the repo root so configs/ resolves
forever start -c "$(pwd)/.venv/bin/python3" \
  -l "$(pwd)/forever-chat.log" --append \
  swg_chat_bridge.py

forever list                          # show running scripts
forever logs swg_chat_bridge.py -f    # tail logs
forever restart swg_chat_bridge.py
forever stop swg_chat_bridge.py
```

> Run only one supervisor at a time — don't stack PM2/forever on top of the
> Docker container (or each other) for the same configs, or you'll get
> duplicate bots logging into the same chatroom. Docker (above) remains the
> production deployment; PM2/forever are alternatives for non-Docker hosts.

## Troubleshooting

### `ModuleNotFoundError: No module named 'discord'`

You ran the bot with a Python that doesn't have the dependencies installed —
almost always because you ran `python3 swg_chat_bridge.py` **without first
installing `requirements.txt`** (or outside the virtualenv where you installed
them). The dependencies (`discord.py`) are not bundled; you have to install them.

Fix — from the repo directory:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 swg_chat_bridge.py
```

Every later run must use that same environment — either `source .venv/bin/activate`
first, or call the venv's Python directly: `./.venv/bin/python3 swg_chat_bridge.py`.
If you use a process manager, point it at the venv interpreter (see
[Run with a process manager](#run-with-a-process-manager-pm2-or-forever)) — a
bare `pm2 start … --interpreter python3` hits the same missing-module error.

(Quick install without a venv: `pip3 install -r requirements.txt` — but on
newer distros this fails with an "externally-managed-environment" error, which
is exactly why the venv steps above are the recommended path.)

## Configuration

Each bot needs a JSON file in the `configs/` folder. See `configs/example.json` for a full template.

### SWG Section

| Key | Required | Description |
|-----|----------|-------------|
| `LoginAddress` | Yes | SWG login server IP or hostname |
| `LoginPort` | Yes | Login server port (usually 44453) |
| `SWGServerName` | Yes | Server name (used in status messages) |
| `Username` | Yes | SWG account username |
| `Password` | Yes | SWG account password (empty string if none) |
| `Character` | Yes | Character name to log in as |
| `ChatRoom` | Yes | Chatroom path (e.g., `SWG.ServerName.RoomName`) |
| `verboseSWGLogging` | No | Log all SWG packets (default: false) |
| `inOrderDelivery` | No | Enforce in-order reliable delivery + honest acking (default: false). See below. |
| `inOrderStallSecs` | No | Seconds a sequence hole may persist under live traffic before the stall valve abandons it (default: 10). Only meaningful with `inOrderDelivery: true`. |
| `fragmentSeqFix` | No | Stop burning a reliable sequence number on every fragmented **outbound** send (default: false). See below. |

#### `fragmentSeqFix` — what it does and why

`inOrderDelivery` (above) fixes the **inbound** direction. This fixes the **outbound** one, and it is a
different bug: we were not losing packets, **we were never sending one.**

`encode_soe_header()` consumes reliable sequence **N** for a `0x0009` packet. If the finished packet then
exceeds 493 bytes, `encrypt()` hands it to `_fragment_and_encrypt()`, which drops the `0x0009` header
carrying N and re-headers the payload as `0x000d` fragments taking **fresh** sequences N+1, N+2, …
**N is consumed and never transmitted.**

Core3 is strictly in-order on receive (`BaseClient::validatePacket`): a packet above the expected sequence
is parked in `receiveBuffer`, answered with `OutOfOrder`, and **not processed** — `clientSequence` never
advances. We have no outbound retransmit and used to ignore `OutOfOrder` entirely, so nothing ever filled
the hole. The bot's whole **outbound** channel (Discord → game) went dead, while inbound stayed perfectly
healthy and `connected` stayed `True`. The only witness was `room_stale` climbing until the 300s
room-query self-heal forced a reconnect.

**The trigger is routine, not an edge case:** the payload is UTF-16 (2 bytes/char), so **any relayed message
over ~210 characters fragments** — as does any `/tell` over ~200. On 2026-07-12 this took the `tc` bot down
twice in one day (a 212-char and a 291-char relay), each for 304s. `live` was exposed too and merely lucky
that player chat is short.

**On:** the first fragment reuses N (it is still sitting in the header we discard), so the outbound stream
stays contiguous. A guard refuses to fragment any packet that is not a pre-stamped `0x0009` — without it a
future non-sequenced caller would silently desync forever (`-1 & 0xFFFF == 65535`; `struct.pack_into` does
not raise).

**Health signals:** the `Health:` line gains `ooo=` (OutOfOrder packets received — Core3 telling us it is
missing something **we** were supposed to send) and `oversize=`. `ooo` is the direct outbound-health number
we never had. A small nonzero `ooo` is **normal** — ordinary UDP reordering between back-to-back fragment
datagrams trips it and Core3 heals it from its own `receiveBuffer`. A **sustained climb** alongside a rising
`room_stale` is the failure. `fragfix=on` appears in the health line when the flag is set.

**Why it is flag-gated:** it *promotes a code path that has never once succeeded in production* — every
fragmented message we have ever sent was parked by Core3 and destroyed at the next reconnect. If the fragment
layout were wrong, Core3 disconnects the client as hostile, which is worse than the stall it cures. So roll it
out one bot at a time. **Known residual:** this removes the *deterministic* hole, not the hole *class* — a
genuinely lost fragment still stalls the channel until the 300s self-heal, and that exposure now scales with
fragment count. Outbound retransmit is the real cure and is not built yet; keep the self-heal as the backstop.

#### `inOrderDelivery` — what it does and why

**Off (default, legacy):** the bridge acks whatever reliable packet it last saw, even if that packet arrived
**out of order**. Core3's `flushSendBuffer(seq)` then deletes *every* buffered packet up to that sequence —
including ones we never received. Those chat lines are **destroyed at the source and silently lost forever**;
the bridge has no idea and reports itself perfectly healthy.

**On:** the bridge only acks the **contiguous head** of the sequence. It drops out-of-order packets rather than
acking past a hole, so Core3 retransmits the hole *and* everything after it. Nothing is destroyed before we
have it. Trade-off: a hole that never fills would stall the stream, so a **stall valve** (`inOrderStallSecs`)
abandons the hole after N seconds of *live traffic*, logging `STALL:` — this is strictly no worse than the
legacy behaviour (which loses the packet anyway), just loud instead of silent.

**Health signals:** the `Health:` line gains `rel_ok=` (reliable packets *accepted*) — the first honest
"the sequence layer is alive" signal; `connected=True` only ever meant "socket alive", which is how a bot
could sit deaf for hours. Healthy = `rel_ok` climbing, and `rel_ok ≈ seq + 1` means zero gaps.
A **deafness watchdog** force-reconnects if no reliable packet is accepted in 30s while datagrams keep
arriving (`WATCHDOG`). Both `STALL:` and `WATCHDOG` are wired into log-monitor and will page.

**Rollout note:** the flag is per-bot and **hot-reloaded** — edit `configs/<bot>.json` and only that bot
restarts (~10s, no rebuild, no container bounce). Rolling back is the same edit in reverse.

### Discord Section

| Key | Required | Description |
|-----|----------|-------------|
| `BotToken` | Yes | Discord bot token |
| `ServerID` | Yes | Discord guild/server ID |
| `ChatChannel` | Yes | Discord channel name for chat bridge |
| `BotName` | No | Display name in logs (default: config filename) |
| `PresenceName` | No | Bot's "Watching ___" status (default: "in-game") |
| `NotificationChannel` | No | Channel name for server up/down alerts |
| `NotificationMentionRole` | No | Role name to @mention on server status |
| `NotificationMentionUserID` | No | User ID to @mention on server status |
| `AdminUsers` | No | Dict of user IDs → labels who can run admin commands |
| `AdminChannels` | No | Dict of channel IDs → labels where admin commands work |
| `AutoRestartTimer` | No | Auto-restart bot after N minutes (0 = disabled) |
| `verboseDiscordLogging` | No | Log all Discord messages (default: false) |

### Admin Permissions

Admin commands (`!fixchat`, `!pausechat`, `!debugchat`) are restricted to authorized users and channels. The `NotificationMentionUserID` is always included as admin.

```json
"AdminUsers": {
    "231103549025681419": "MrObvious",
    "350993329749491712": "wickedhangover"
},
"AdminChannels": {
    "1483787066893537380": "#bot-zone"
}
```

Also accepts a simple list format: `"AdminUserIDs": ["231103549025681419"]`

## Discord Commands

| Command | Access | Description |
|---------|--------|-------------|
| `!server` | Everyone | Shows if SWG server is up or down |
| `!status` | Everyone | Shows bot uptime, room ID, reconnect count, message stats |
| `!fixchat` | Admin only | Restarts this bot (clean disconnect + reconnect) |
| `!pausechat` | Admin only | Toggle pause — stops relaying messages without disconnecting |
| `!debugchat` | Admin only | Enable verbose logging for both SWG and Discord |

## Architecture

```
Discord ←→ ChatBridge (discord.py) ←→ SWGChatClient (UDP) ←→ SWG Server
                                           |
                                      SOEProtocol
                                    (session, encrypt,
                                     packet encode/decode)
```

### Files

| File | Purpose |
|------|---------|
| `swg_chat_bridge.py` | Main bot — Discord client, SWG client, config watcher, bot runner |
| `soe_protocol.py` | SOE protocol implementation — session management, encryption, packet encoding/decoding |
| `configs/example.json` | Example configuration (skipped by bot scanner) |
| `Dockerfile` | Container image build |
| `docker-compose.yml` | Docker Compose with healthcheck, log rotation, read-only config mount |

### How It Works

1. **Login:** Bot connects to SWG login server via UDP, authenticates, gets character list
2. **Zone:** Selects character, connects to zone server, receives world state
3. **Chat:** Creates/queries chatroom by path, enters room by ID, begins relaying
4. **Bridge:** SWG chat messages → Discord channel. Discord messages → SWG chatroom (with colored sender name)
5. **Health:** Every 60s, re-queries chatroom to verify membership. Logs metrics every 5 min
6. **Hot-reload:** Every 10s, scans config directory for added/removed files

### Reconnection Flow

```
SWG timeout (10s no packets)
  → fails++
  → reconnect with backoff (2s → 4s → 8s → ... → 60s max)
  → on 3rd consecutive fail: notify Discord "server DOWN"
  → on successful room join: reset backoff, notify "server UP" if was down
```

### Message Format

- **SWG → Discord:** `**PlayerName:**  message text`
- **Discord → SWG:** `\#ff3333SenderName: \#ff66ffmessage text` (colored in-game)

## Hot-Reload

When running against a config directory (the default), the bot watches for changes every 10 seconds:

| Action | What Happens |
|--------|-------------|
| Drop new `.json` file | Bot validates config and starts within 10 seconds |
| Delete/rename `.json` file | Bot gracefully disconnects and stops |
| Rename to `.json.disabled` | Same as delete — bot stops, config preserved |
| Rename back to `.json` | Bot starts again |
| Edit existing `.json` | No effect until bot restarts (via `!fixchat` or crash) |

Files starting with `example` are always skipped.

Single-file mode (`python3 swg_chat_bridge.py configs/one-bot.json`) disables hot-reload.

## Docker

### Build and Run

```bash
docker compose up -d --build
```

### Health Check

Docker monitors the bot via a healthcheck that verifies `/tmp/chatbridge_alive` is touched every 30 seconds. If the file goes stale for 2+ minutes, Docker marks the container unhealthy.

### Log Rotation

Logs are capped at 10MB with 3 rotated files (configured in `docker-compose.yml`).

### Volumes

| Mount | Container Path | Mode | Purpose |
|-------|---------------|------|---------|
| `./configs` | `/app/configs` | Read-only | Bot configuration files |

## FAQ

**Q: How do I get a Discord bot token?**
Create a bot at [discord.com/developers](https://discord.com/developers/applications). Under Bot settings, click "Reset Token" to generate one. The bot needs Message Content Intent enabled under Privileged Gateway Intents.

**Q: How do I find Discord channel/server/user IDs?**
Enable Developer Mode in Discord (Settings → Advanced → Developer Mode). Then right-click any channel, server, or user and select "Copy ID".

**Q: Can one Discord bot token run multiple SWG servers?**
No. Each config file needs its own Discord bot token. The bot checks for duplicate tokens at startup and rejects them.

**Q: The bot connects but joins the wrong chatroom. What's happening?**
The bot queries the room by path using `ChatQueryRoom`. If the path doesn't match, it may fall back to the auto-joined planet room. Make sure `ChatRoom` in your config matches the exact server-side path (e.g., `SWG.ServerName.RoomName`). Check logs with `verboseSWGLogging: true`.

**Q: The bot keeps reconnecting every few seconds.**
The SWG server may be down or unreachable. The bot uses exponential backoff (2s → 60s max) to avoid hammering the server. Check that `LoginAddress` and `LoginPort` are correct and the server is running.

**Q: How do I restart just one bot without affecting others?**
Use `!fixchat` in Discord (admin only), or rename the config file away and back. The hot-reload watcher handles it automatically.

**Q: Messages from Discord aren't showing up in-game.**
Check that the bot's character is actually in the chatroom — use `!status` to verify the room ID is set. If room ID is `None`, the bot failed to join. Check SWG logs with `verboseSWGLogging: true`.

**Q: Can the bot handle server restarts automatically?**
Yes. When the SWG server goes down, the bot detects the timeout after 10 seconds, notifies Discord (if `NotificationChannel` is set), and reconnects with exponential backoff. When the server comes back, it logs in, joins the chatroom, and notifies Discord it's back up.

**Q: The bot is receiving game chat but not posting to Discord.**
Check Discord permissions — the bot needs Send Messages permission in the chat channel. Also check `docker logs swg-chatbots` for Discord HTTP errors. The bot retries failed sends 3 times with increasing delays.

**Q: How do I see what the bot is doing?**
Use `!debugchat` (admin only) to enable verbose logging at runtime, or set `verboseSWGLogging` and `verboseDiscordLogging` to `true` in the config. Logs go to stdout (visible via `docker logs` or terminal).

**Q: Can I run the bot outside Docker?**
Yes. Install Python 3.10+, create a venv, `pip install -r requirements.txt`, and run directly. Docker is optional — it just adds healthchecks and log rotation.

**Q: What SWG protocol does the bot use?**
SOE (Sony Online Entertainment) UDP protocol with session management, CRC encryption, and multi-packet fragmentation. The `soe_protocol.py` file handles all of this. The bot acts as a standard SWG game client — it logs in, zones, and joins chat like any player.

**Q: The bot logged in but I don't see it in-game.**
The bot's character zones into the world at its last saved position. It doesn't move or interact — it only handles chat. Other players will see the character standing idle.

**Q: Can I bridge multiple chatrooms to different Discord channels?**
Currently each config bridges one SWG chatroom to one Discord channel. For multiple rooms, create multiple configs with different characters and channels (each needs its own Discord bot token).

**Q: What happens if Discord goes down?**
discord.py has built-in reconnection (`reconnect=True`). The SWG connection stays alive during Discord outages. When Discord comes back, the bot resumes relaying without restarting.
