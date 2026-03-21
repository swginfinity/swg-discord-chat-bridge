# SWG Discord Chat Bridge v2

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

```bash
# Copy and edit a config
cp configs/example.json configs/my-server.json

# Build and run
docker compose up -d

# View logs
docker logs -f swg-chatbots

# Add another bot (no restart needed — hot-reload picks it up)
cp configs/example.json configs/second-server.json
# Edit second-server.json, bot starts within 10 seconds

# Disable a bot without deleting (no restart needed)
mv configs/my-server.json configs/my-server.json.disabled
```

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
