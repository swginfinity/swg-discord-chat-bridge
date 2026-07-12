"""
SOE Protocol implementation for SWG — ported from SOEProtocol.js (chatbot).

Handles:
- Session management (SessionRequest/Response)
- XOR block-chain encryption/decryption with CRC seed
- Custom CRC-32 validation
- zlib compression/decompression
- Packet fragmentation and multi-packet handling
- SWG message encoding/decoding (login, chat, zone)
"""

import struct
import zlib
import os
import time
from typing import Optional

# CRC lookup table (standard CRC-32 polynomial 0xEDB88320)
CRC_TABLE = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]


def generate_crc(data: bytes, seed: int) -> int:
    """Custom CRC-32 with seed initialization (NOT standard CRC-32)."""
    crc = CRC_TABLE[(~seed) & 0xFF]
    crc ^= 0x00FFFFFF

    index = ((seed >> 8) ^ crc) & 0xFF
    crc = (crc >> 8) & 0x00FFFFFF
    crc ^= CRC_TABLE[index]

    index = ((seed >> 16) ^ crc) & 0xFF
    crc = (crc >> 8) & 0x00FFFFFF
    crc ^= CRC_TABLE[index]

    index = ((seed >> 24) ^ crc) & 0xFF
    crc = (crc >> 8) & 0x00FFFFFF
    crc ^= CRC_TABLE[index]

    for byte in data:
        index = (byte ^ crc) & 0xFF
        crc = (crc >> 8) & 0x00FFFFFF
        crc ^= CRC_TABLE[index]

    return (~crc) & 0xFFFFFFFF


class SOESession:
    """Tracks SOE session state."""

    def __init__(self):
        self.connection_id = 0
        self.crc_seed = 0
        self.crc_length = 0
        self.use_compression = 0
        self.seed_size = 0
        self.server_udp_size = 0
        self.sequence = 0
        self.last_ack = -1
        self.last_sequence = -1
        self.request_id = 0
        self.session_key = b""

        # Fragment reassembly
        self.fragments = None
        self.fragment_length = 0

        # Deafness watchdog (Phase 1b). Counts reliable packets we actually
        # ACCEPTED — not datagrams received. Every deafness mode we have had or
        # can construct (16-bit wrap desync, poisoned bootstrap, a future
        # hole-stall) shares one signature: datagrams keep arriving but this
        # number stops moving. It is the only honest "the sequence layer is
        # alive" signal we have; `connected` only ever meant "socket alive".
        self.reliable_accepted = 0
        self.multipacket_dropped = 0    # 0x0003 seen — our peer never sends these

        # --- In-order delivery (config: inOrderDelivery). See _accept_sequence. ---
        self.next_expected = 0          # the reliable id we need next (unbounded)
        self.initialized = False        # have we committed the server's sequence origin?
        self.bootstrap_streak = 0       # consecutive in-order stamps seen while bootstrapping
        self.boot_origin = 0            # provisional session origin (see _accept_inorder)
        self.gap_min = None             # LOWEST id seen ABOVE the hole (== min(pending), no payloads)
        self.gap_since = None           # when the current hole formed (monotonic)
        # instrumentation (always counted, even when the fix is OFF)
        self.gaps_observed = 0
        self.forced_skips = 0
        self.packets_skipped = 0        # a skip to gap_min can drop MANY packets, not one
        self.crc_mismatch = 0


class SOEProtocol:
    """SOE protocol encoder/decoder."""

    def __init__(self, verbose: bool = False, in_order: bool = False):
        self.session = SOESession()
        self.verbose = verbose
        # in_order: hold the ack at the contiguous head instead of acking past a
        # gap (which makes Core3 delete the packet we never got). Default OFF —
        # enable per bot via config `inOrderDelivery` after watching the counters.
        self.in_order = in_order

    def decrypt(self, data: bytearray) -> bytearray:
        """Decrypt an SOE packet using XOR block-chain cipher."""
        result = bytearray(len(data))
        # Copy header (2 bytes, unencrypted)
        result[0:2] = data[0:2]

        mask = self.session.crc_seed
        offset = 2

        # Process 4-byte blocks
        while offset <= len(data) - 6:
            temp = struct.unpack_from("<I", data, offset)[0]
            decrypted = (temp ^ mask) & 0xFFFFFFFF
            struct.pack_into("<I", result, offset, decrypted)
            mask = temp  # Use pre-XOR (encrypted) value as next mask
            offset += 4

        # Trailing bytes — XOR with low byte of last mask
        mask &= 0xFF
        while offset < len(data) - 2:
            result[offset] = (data[offset] ^ mask) & 0xFF
            offset += 1

        # Copy CRC (last 2 bytes, unencrypted)
        result[offset:offset + 2] = data[offset:offset + 2]

        # Check compression flag (byte before CRC)
        if result[-3] == 1:
            try:
                decompressed = zlib.decompress(bytes(result[2:-3]))
                result = bytearray(result[0:2]) + bytearray(decompressed) + bytearray(result[-3:])
            except zlib.error:
                pass

        return result

    def encrypt(self, data: bytearray) -> bytearray:
        """Encrypt an SOE packet using XOR block-chain cipher."""
        # Handle fragmentation for large packets
        if len(data) > 493:
            return self._fragment_and_encrypt(data)

        # Append compression flag and CRC placeholder
        if len(data) > 100 or struct.unpack_from(">H", data, 0)[0] == 0x000d:
            compressed = zlib.compress(bytes(data[2:]))
            data = bytearray(data[0:2]) + bytearray(compressed) + bytearray([1, 0, 0])
        else:
            data = bytearray(data) + bytearray([0, 0, 0])

        result = bytearray(len(data))
        result[0:2] = data[0:2]

        mask = self.session.crc_seed
        offset = 2

        # Process 4-byte blocks
        while offset <= len(result) - 6:
            plaintext = struct.unpack_from("<I", data, offset)[0]
            mask = (plaintext ^ mask) & 0xFFFFFFFF
            struct.pack_into("<I", result, offset, mask)
            offset += 4

        # Trailing bytes
        mask &= 0xFF
        while offset < len(result) - 2:
            result[offset] = (data[offset] ^ mask) & 0xFF
            offset += 1

        # Append CRC
        crc = generate_crc(bytes(result[0:offset]), self.session.crc_seed) & 0xFFFF
        struct.pack_into(">H", result, offset, crc)

        return result

    def _fragment_and_encrypt(self, data: bytearray) -> list:
        """Fragment a large packet and encrypt each fragment."""
        packets = []
        swg_packet_size = 496 - 8 - 3  # First fragment has extra 4-byte length header
        i = 4  # Skip the first 4 bytes (SOE header already in data)

        first = True
        while i < len(data):
            if first:
                head = bytearray(8)
                struct.pack_into(">H", head, 0, 0x000d)
                struct.pack_into(">H", head, 2, self.session.sequence & 0xFFFF)
                # Don't increment sequence for first fragment
                struct.pack_into(">I", head, 4, len(data) - 4)
                first = False
            else:
                swg_packet_size = 496 - 4 - 3
                head = bytearray(4)
                struct.pack_into(">H", head, 0, 0x000d)
                struct.pack_into(">H", head, 2, self.session.sequence & 0xFFFF)

            self.session.sequence += 1
            chunk = data[i:i + swg_packet_size]
            packet = bytearray(head) + bytearray(chunk)
            packets.append(self.encrypt(packet))
            i += swg_packet_size

        return packets

    def encode_soe_header(self, opcode: int, operands: int) -> bytearray:
        """Create an SOE DataChannel header with sequence number."""
        buf = bytearray(10)
        struct.pack_into(">H", buf, 0, 0x0009)  # DataChannelA
        struct.pack_into(">H", buf, 2, self.session.sequence & 0xFFFF)
        self.session.sequence += 1
        struct.pack_into("<H", buf, 4, operands)
        struct.pack_into("<I", buf, 6, opcode)
        return buf

    # --- Encoding methods ---

    def encode_session_request(self) -> bytearray:
        """Encode a SessionRequest packet (not encrypted)."""
        buf = bytearray(14)
        struct.pack_into(">H", buf, 0, 0x0001)
        struct.pack_into(">I", buf, 2, 2)  # CRC length
        struct.pack_into(">I", buf, 6, struct.unpack(">I", os.urandom(4))[0])  # Random connection ID
        struct.pack_into(">I", buf, 10, 496)  # Client UDP size
        return buf

    def encode_login_client_id(self, username: str, password: str) -> bytearray:
        """Encode LoginClientID message."""
        header = self.encode_soe_header(0x41131f96, 4)
        buf = bytearray(496)
        off = 0
        off = _write_astring(buf, off, username)
        off = _write_astring(buf, off, password)
        off = _write_astring(buf, off, "20050408-18:00")
        return self.encrypt(header + buf[:off])

    def encode_select_character(self, character_id: bytes) -> bytearray:
        """Encode SelectCharacter message."""
        header = self.encode_soe_header(0xb5098d76, 2)
        buf = bytearray(8)
        buf[0:len(character_id)] = character_id
        return self.encrypt(header + buf)

    def encode_client_id_msg(self) -> bytearray:
        """Encode ClientIdMsg for zone server authentication.
        Format: [gameBits:4=0][dataLen:4][sessionKey+accountID][version:astring]
        """
        header = self.encode_soe_header(0xd5899226, 3)
        buf = bytearray(496)
        off = 0
        # gameBits (4 bytes, zeros)
        off += 4
        # dataLen = session key blob length (includes accountID)
        struct.pack_into("<I", buf, off, len(self.session.session_key))
        off += 4
        # session key blob (session string + accountID)
        buf[off:off + len(self.session.session_key)] = self.session.session_key
        off += len(self.session.session_key)
        # version string
        off = _write_astring(buf, off, "20050408-18:00")
        return self.encrypt(header + buf[:off])

    def encode_cmd_scene_ready(self) -> bytearray:
        """Encode CmdSceneReady message."""
        return self.encrypt(self.encode_soe_header(0x43fd1c22, 1))

    def encode_create_character(self, name: str,
                                 race: str = "object/creature/player/human_male.iff",
                                 hair: str = "",
                                 profession: str = "crafting_artisan",
                                 height: float = 1.0,
                                 tutorial: bool = False) -> bytearray:
        """Encode ClientCreateCharacter message (opcode 0xB97F3074)."""
        header = self.encode_soe_header(0xB97F3074, 11)
        buf = bytearray(1024)
        off = 0
        off = _write_astring(buf, off, "")       # customization
        off = _write_ustring(buf, off, name)     # character name
        off = _write_astring(buf, off, race)     # race template
        off = _write_astring(buf, off, "")       # starting location (ignored)
        off = _write_astring(buf, off, hair)     # hair object
        off = _write_astring(buf, off, "")       # hair customization
        off = _write_astring(buf, off, profession)
        buf[off] = 0                             # unknown byte
        off += 1
        struct.pack_into("<f", buf, off, height)
        off += 4
        off = _write_ustring(buf, off, "")       # biography
        buf[off] = 1 if tutorial else 0          # tutorial flag
        off += 1
        return self.encrypt(header + buf[:off])

    # --- Reliable-sequence handling (see SOE's own udplibrary) -----------------
    # The wire carries only the LOW 16 BITS of the reliable id. That is
    # deliberate — SOE's UdpLibrary.hpp: "since we can never have anywhere close
    # to 65000 packets outstanding, we only need to send the low order word ...
    # we can reconstruct the full id from that, we just need to take into account
    # the wrap around issue."
    #
    # So the receiver MUST keep a wide monotonic id and reconstruct it from the
    # 16-bit stamp. This decoder previously compared the RAW 16-bit stamp with
    # `if sequence <= last_sequence: discard`, which is a monotonic test on a
    # CIRCULAR counter: the moment the server's sequence rolled 65535 -> 0, every
    # subsequent packet compared "old" and was silently discarded FOREVER. The
    # bot stayed socket-alive (so `connected` remained True) while receiving
    # nothing — the 2026-07-12 deafness. Wrap arrives after 65,536 packets, i.e.
    # ~3.4h at live world-traffic rates, which is why the 4h AutoRestartTimer
    # usually outran it and hid the bug.
    #
    # This mirrors UdpReliableChannel::GetReliableIncomingId (UdpLibrary.hpp:2069):
    # prepend the last-known high word, then correct by +/- 0x10000 if the result
    # lands outside the outstanding-packet window.
    _WRAP_WINDOW = 30000        # SOE: cHardMaxOutstandingPackets ("don't change this")
    _BOOTSTRAP_CONFIRM = 3      # consecutive in-order stamps before the origin is committed

    def _reliable_incoming_id(self, stamp: int) -> int:
        """Reconstruct the full (unbounded) reliable id, centered on next_expected.

        This is SOE's GetReliableIncomingId (UdpLibrary.hpp:2069), which centers on
        mReliableIncomingId — i.e. the NEXT EXPECTED id, which is exactly what
        next_expected is. (The legacy path below centers on last_sequence instead;
        harmless there, but this is the conformant form.)
        """
        ref = self.session.next_expected
        rid = stamp | (ref & ~0xFFFF)
        if rid < ref - self._WRAP_WINDOW:
            rid += 0x10000                     # stamp wrapped forward
        elif rid > ref + self._WRAP_WINDOW:
            rid -= 0x10000                     # stale straggler from before the wrap
        return rid

    def _reliable_incoming_id_legacy(self, stamp: int) -> int:
        """Reconstruct the full (unbounded) reliable id from a 16-bit wire stamp."""
        last = self.session.last_sequence
        if last < 0:
            return stamp                       # first packet of the session
        rid = stamp | (last & ~0xFFFF)
        if rid < last - self._WRAP_WINDOW:
            rid += 0x10000                     # stamp wrapped forward
        elif rid > last + self._WRAP_WINDOW:
            rid -= 0x10000                     # stale straggler from before the wrap
        return rid

    def _accept_inorder(self, buf) -> bool:
        """IN-ORDER gate. True = deliver this packet now. False = drop it.

        THE BUG THIS FIXES: the legacy gate below accepts ANY newer id and advances
        past a GAP, and encode_ack then AckAlls past it. Core3's flushSendBuffer
        (BaseClient.cpp:1407) deletes EVERY buffered packet <= that seq — INCLUDING
        the one we never received — and after that deletion NO resend path can bring
        it back. So one lost/reordered inbound packet is lost FOREVER, and we told
        the server we had it. Sometimes that packet is a player's chat line.

        THE FIX: never ack past a hole. We drop out-of-order packets rather than
        buffering them, and Core3's checkup timer resends its unacked head — and the
        dropped tail with it, in order (resendPackets() walks sequenceBuffer from
        index 0, BaseClient.cpp:1181-1220). Measured live: reliable inbound is
        8.5-11.8 pkt/s against a ~60 pkt/s resend ceiling, so it converges with ~5x
        headroom. NOTE the ceiling is a RATE limit, not a burst size
        (maxPacketResent = max(5, 30000*checkupTime/496), :1193).

        We keep NO payload buffer. `gap_min` — the lowest id seen above the hole — is
        min(pending) without the payloads, and it is what gives the stall valve
        somewhere to jump.

        NOT DOING (and do not "fix" this later): re-acking duplicates, as SOE does
        (UdpLibrary.cpp:3552-3582). Against Core3 that is FATAL — acknowledgeServerPackets
        cancels and re-arms the checkup timer on EVERY ack, including a duplicate
        (the guard at :1369 is a strict `<`). Our ack loop runs at 100ms, so re-acking
        dups would push the retransmit deadline out faster than it can ever fire ->
        resendPackets() NEVER RUNS -> it would disable the one recovery mechanism this
        whole design depends on. SOE's peer does not cancel-and-rearm. Core3 does.
        Conform to the PEER, not the reference.
        """
        s = self.session
        stamp = struct.unpack_from(">H", buf, 2)[0]

        # BOOTSTRAP. We cannot assume the server starts at 0: `//serverSequence = 0;`
        # is COMMENTED OUT in Core3's close() (BaseClient.cpp:362), so a reused
        # BaseClient can begin mid-stream. Assuming 0 would make every real packet
        # read as a duplicate -> permanent silent deafness. So we ADOPT the server's
        # origin from the first reliable packet we see, and require N consecutive
        # in-order stamps before committing it, so a single stray cannot define it.
        #
        # 🔴 The bootstrap runs the SAME gap-tracking logic as steady state. An earlier
        # version had a separate "streak-break" branch that did `next_expected = rid+1;
        # return True` — i.e. it DELIVERED an out-of-order packet and JUMPED THE HOLE.
        # Once the streak completed, encode_ack then AckAll'd past that hole and Core3
        # deleted the packet we never got — THE EXACT BUG THIS FEATURE EXISTS TO PREVENT,
        # and gaps_observed never even saw it. Made worse by the fact that we withhold the
        # ack until commit, which PROVOKES the very resend that broke the streak.
        # Never advance past a hole. Not even here.
        if not s.initialized and s.bootstrap_streak == 0 and s.gap_min is None:
            s.next_expected = stamp             # provisional origin: the first id we saw
            s.boot_origin = stamp

        # During the bootstrap use the RAW stamp: the wrap reconstruction centers on
        # next_expected, and a provisional origin that is wrong-by-a-lot would make it
        # "correct" a real id by +/-0x10000. A session cannot wrap in its first few
        # packets, so there is nothing to reconstruct yet.
        rid = stamp if not s.initialized else self._reliable_incoming_id(stamp)

        if not s.initialized and rid < s.boot_origin:
            # BELOW our provisional origin. We never accepted anything under the origin,
            # so this CANNOT be a duplicate — it means our first packet was a straggler
            # and we started too high. Adopt the lower origin and restart the streak.
            #
            # Comparing against boot_origin (not next_expected) is load-bearing. A packet
            # RESENT by Core3 mid-bootstrap — which we actively provoke by withholding the
            # ack until commit — sits in [boot_origin, next_expected). Treating THAT as
            # "we started too high" would re-lower the origin and DELIVER IT A SECOND TIME:
            # double-dispatched handshake, duplicate chat lines into Discord.
            #   rid <  boot_origin              -> we started too high  (adopt)
            #   boot_origin <= rid < next_expec -> ordinary duplicate   (drop)
            s.boot_origin = rid
            s.next_expected = rid
            s.bootstrap_streak = 0
            s.gap_min = s.gap_since = None

        if rid < s.next_expected:
            return False                        # duplicate / already delivered — drop, do NOT re-ack

        if rid == s.next_expected:              # the one we are waiting for
            s.next_expected += 1
            s.last_sequence = rid               # keep seq= meaningful in the health line
            s.reliable_accepted += 1
            s.gap_min = s.gap_since = None      # hole (if any) is closed
            if not s.initialized:
                s.bootstrap_streak += 1
                if s.bootstrap_streak >= self._BOOTSTRAP_CONFIRM:
                    s.initialized = True        # ack is withheld until this commits
                    origin = s.next_expected - s.bootstrap_streak
                    if origin != 0:
                        print(f"[soe] WARN: session origin was {origin}, not 0 "
                              f"(Core3 close() does not reset serverSequence)")
            return True

        # rid > next_expected: a GAP. Drop this packet and do NOT advance. We simply
        # never ack past the hole, so Core3 keeps the missing packet at the head of
        # its sequenceBuffer and resends it — and this packet with it.
        if s.gap_min is None or rid < s.gap_min:
            s.gap_min = rid
        if s.gap_since is None:
            s.gap_since = time.monotonic()
            s.gaps_observed += 1
        return False

    def force_skip_gap(self) -> int:
        """Stall valve: give up on an unfillable hole. Returns packets abandoned.

        Jumps to gap_min (NOT next_expected+1) — a burst loss of k consecutive packets
        must cost ONE skip, not k skips of STALL_SECS each.

        The skip is EXACTLY today's lossy behavior (lose the packet, move on), so the
        worst case is no worse than the status quo and this CANNOT create a new
        permanent-deafness mode. That property is the whole reason the valve exists.
        """
        s = self.session
        if s.gap_min is None or not s.initialized:
            return 0
        lost = s.gap_min - s.next_expected
        s.next_expected = s.gap_min
        s.gap_min = s.gap_since = None
        s.forced_skips += 1
        s.packets_skipped += max(lost, 0)

        # 🔴 A forced skip jumps OVER packets — and if any of them were fragments, the
        # accumulator now holds a message with a HOLE in it. Unlike an ordinary gap
        # (where in-order delivery keeps the accumulator coherent, because the tail is
        # resent in order), a skip genuinely poisons it. Drop the partial message.
        s.fragments = None
        s.fragment_length = 0
        return max(lost, 0)

    def _accept_sequence(self, buf) -> bool:
        """True if this reliable packet is NEW (and advance the id). False = old/dup.

        Replaces `if sequence <= last_sequence` — same intent, but on the
        reconstructed id so it survives the 16-bit rollover.
        """
        if self.in_order:
            return self._accept_inorder(buf)
        stamp = struct.unpack_from(">H", buf, 2)[0]
        rid = self._reliable_incoming_id_legacy(stamp)
        if rid <= self.session.last_sequence:
            # A packet landing FAR behind the head is not an ordinary duplicate —
            # it means our id and the server's have diverged, and every packet
            # would be rejected from here on (silent, permanent deafness — the
            # very failure this fix exists to kill). Make it loud rather than
            # invisible. (GLM-5.2 review, 2026-07-12.)
            if rid < self.session.last_sequence - self._WRAP_WINDOW:
                print(f"[soe] WARN: reliable id {rid} is >{self._WRAP_WINDOW} behind "
                      f"head {self.session.last_sequence} — sequence desync, session needs a reset")
            return False
        self.session.last_sequence = rid
        self.session.reliable_accepted += 1     # watchdog liveness — see SOESession
        return True

    def encode_ack(self) -> Optional[bytearray]:
        """Encode an ACK packet.

        Compares on the reconstructed (unbounded) id, but sends only the LOW
        16 BITS on the wire — exactly as SOE does. The old code packed
        `last_sequence` straight into a >H field, which (a) short-circuited to
        None forever once the ids stopped increasing across a wrap, so the bot
        STOPPED ACKING and the server retransmitted endlessly, and (b) would now
        raise struct.error once last_sequence exceeds 65535.
        """
        s = self.session
        if self.in_order:
            # Ack ONLY the contiguous head — never past a hole. This is SOE's
            # AckAll(mReliableIncomingId - 1) (UdpLibrary.cpp:3565). Withholding is
            # safe: Core3 ignores a lower ack (BaseClient.cpp:1369) and simply keeps
            # the missing packet at the head of sequenceBuffer, where its checkup
            # timer resends it.
            # Nothing is acked until the bootstrap has committed the origin — acking
            # a provisional origin would tell Core3 to delete packets we may still need.
            if not s.initialized:
                return None
            ack_id = s.next_expected - 1
            # STRICTLY ADVANCING. Never re-send an equal ack: an equal ack still
            # cancels + re-arms Core3's checkup timer (:1369 is a strict `<`), which
            # would starve the retransmit we depend on.
            if ack_id < 0 or s.last_ack >= ack_id:
                return None
        else:
            if s.last_ack >= s.last_sequence:
                return None
            ack_id = s.last_sequence

        buf = bytearray(4)
        struct.pack_into(">H", buf, 0, 0x0015)
        struct.pack_into(">H", buf, 2, ack_id & 0xFFFF)
        s.last_ack = ack_id
        return self.encrypt(buf)

    def encode_disconnect(self) -> bytearray:
        """Encode a Disconnect packet (0x0005)."""
        buf = bytearray(8)
        struct.pack_into(">H", buf, 0, 0x0005)
        struct.pack_into(">I", buf, 2, self.session.connection_id)
        struct.pack_into(">H", buf, 6, 6)  # reason: application
        return buf  # disconnect is not encrypted

    def encode_net_status(self) -> bytearray:
        """Encode ClientNetStatusRequest."""
        buf = bytearray(40)
        struct.pack_into(">H", buf, 0, 0x0007)
        import time
        tick = int(time.time() * 1000) & 0xFFFF
        struct.pack_into("<H", buf, 2, tick)
        buf[31] = 0x02  # Packets sent
        buf[39] = 0x01  # Packets received
        return self.encrypt(buf)

    def encode_data_transform(self, object_id: int, move_count: int,
                              x: float, z: float, y: float,
                              dir_x: float = 0.0, dir_y: float = 0.0,
                              dir_z: float = 0.0, dir_w: float = 1.0,
                              speed: float = 0.0) -> bytearray:
        """Encode DataTransform (ObjectController 0x71) — client position update.
        Wire format: ObjController header + moveCount + quaternion + position + speed.
        """
        # ObjectControllerMessage: operands=5, CRC=0x80CE5E46, header1=0x1B, header2=0x71
        header = self.encode_soe_header(0x80CE5E46, 5)
        buf = bytearray(56)
        off = 0
        struct.pack_into("<I", buf, off, 0x1B)        # header1
        off += 4
        struct.pack_into("<I", buf, off, 0x71)        # header2 (DataTransform)
        off += 4
        struct.pack_into("<Q", buf, off, object_id)   # player object ID
        off += 8
        struct.pack_into("<I", buf, off, 0)           # padding
        off += 4
        struct.pack_into("<I", buf, off, move_count)  # movement counter
        off += 4
        struct.pack_into("<f", buf, off, dir_x)       # direction quaternion
        off += 4
        struct.pack_into("<f", buf, off, dir_y)
        off += 4
        struct.pack_into("<f", buf, off, dir_z)
        off += 4
        struct.pack_into("<f", buf, off, dir_w)
        off += 4
        struct.pack_into("<f", buf, off, x)           # position
        off += 4
        struct.pack_into("<f", buf, off, z)
        off += 4
        struct.pack_into("<f", buf, off, y)
        off += 4
        struct.pack_into("<f", buf, off, speed)
        off += 4
        return self.encrypt(header + buf[:off])

    def encode_data_transform_with_parent(self, object_id: int, move_count: int,
                                           parent_id: int,
                                           x: float, z: float, y: float,
                                           dir_x: float = 0.0, dir_y: float = 0.0,
                                           dir_z: float = 0.0, dir_w: float = 1.0,
                                           speed: float = 0.0) -> bytearray:
        """Encode DataTransformWithParent (ObjectController 0xF1) — position in a cell."""
        header = self.encode_soe_header(0x80CE5E46, 5)
        buf = bytearray(64)
        off = 0
        struct.pack_into("<I", buf, off, 0x1B)
        off += 4
        struct.pack_into("<I", buf, off, 0xF1)        # DataTransformWithParent
        off += 4
        struct.pack_into("<Q", buf, off, object_id)
        off += 8
        struct.pack_into("<I", buf, off, 0)
        off += 4
        struct.pack_into("<I", buf, off, move_count)
        off += 4
        struct.pack_into("<Q", buf, off, parent_id)   # cell object ID
        off += 8
        struct.pack_into("<f", buf, off, dir_x)
        off += 4
        struct.pack_into("<f", buf, off, dir_y)
        off += 4
        struct.pack_into("<f", buf, off, dir_z)
        off += 4
        struct.pack_into("<f", buf, off, dir_w)
        off += 4
        struct.pack_into("<f", buf, off, x)
        off += 4
        struct.pack_into("<f", buf, off, z)
        off += 4
        struct.pack_into("<f", buf, off, y)
        off += 4
        struct.pack_into("<f", buf, off, speed)
        off += 4
        return self.encrypt(header + buf[:off])

    def encode_command_queue_enqueue(self, object_id: int, action_count: int,
                                      command_crc: int, target_id: int = 0,
                                      arguments: str = "") -> bytearray:
        """Encode CommandQueueEnqueue (ObjectController 0x116) — execute a game command.
        Wire format: ObjController header + size(0) + actionCount + commandCRC + targetID + arguments(unicode).
        command_crc is CRC32 of lowercase command name (e.g., crc32("sit"), crc32("stand")).
        """
        header = self.encode_soe_header(0x80CE5E46, 5)
        # Calculate buffer size: header1(4) + header2(4) + objectID(8) + pad(4) + size(4) + actionCount(4) + commandCRC(4) + targetID(8) + unicode_string
        arg_encoded = arguments.encode("utf-16-le") if arguments else b""
        arg_chars = len(arguments)
        buf_size = 4 + 4 + 8 + 4 + 4 + 4 + 4 + 8 + 4 + len(arg_encoded)
        buf = bytearray(buf_size)
        off = 0
        struct.pack_into("<I", buf, off, 0x23)           # header1 (client priority)
        off += 4
        struct.pack_into("<I", buf, off, 0x116)          # header2 (CommandQueueEnqueue)
        off += 4
        struct.pack_into("<Q", buf, off, object_id)      # player object ID
        off += 8
        struct.pack_into("<I", buf, off, 0)              # padding
        off += 4
        struct.pack_into("<I", buf, off, 0)              # size field (parsed but unused)
        off += 4
        struct.pack_into("<I", buf, off, action_count)   # action counter
        off += 4
        struct.pack_into("<I", buf, off, command_crc)    # command CRC
        off += 4
        struct.pack_into("<Q", buf, off, target_id)      # target object ID
        off += 8
        struct.pack_into("<I", buf, off, arg_chars)      # unicode string length (char count)
        off += 4
        if arg_encoded:
            buf[off:off + len(arg_encoded)] = arg_encoded
            off += len(arg_encoded)
        return self.encrypt(header + buf[:off])

    def encode_spatial_chat(self, object_id: int, target_id: int,
                            message: str, chat_type: int = 0,
                            mood_type: int = 0) -> bytearray:
        """Encode SpatialChat (ObjectController 0x00F3) — speak in the world.
        Wire format: ObjController header + sourceID + targetID + text(unicode) + volume(short) + chatType(short) + moodType(short).
        """
        header = self.encode_soe_header(0x80CE5E46, 5)
        msg_encoded = message.encode("utf-16-le")
        buf_size = 4 + 4 + 8 + 4 + 8 + 8 + 4 + len(msg_encoded) + 6 + 2
        buf = bytearray(buf_size)
        off = 0
        struct.pack_into("<I", buf, off, 0x23)           # header1
        off += 4
        struct.pack_into("<I", buf, off, 0x00F3)         # header2 (SpatialChat)
        off += 4
        struct.pack_into("<Q", buf, off, object_id)      # sender object ID
        off += 8
        struct.pack_into("<I", buf, off, 0)              # padding
        off += 4
        struct.pack_into("<Q", buf, off, object_id)      # source ID
        off += 8
        struct.pack_into("<Q", buf, off, target_id)      # target ID (0 for no target)
        off += 8
        struct.pack_into("<I", buf, off, len(message))   # unicode char count
        off += 4
        buf[off:off + len(msg_encoded)] = msg_encoded
        off += len(msg_encoded)
        struct.pack_into("<H", buf, off, 0x32)           # volume (50 = normal)
        off += 2
        struct.pack_into("<H", buf, off, chat_type)      # chat type
        off += 2
        struct.pack_into("<H", buf, off, mood_type)      # mood type
        off += 2
        return self.encrypt(header + buf[:off])

    def encode_chat_send_to_room(self, message: str, room_id: int) -> bytearray:
        """Encode ChatSendToRoom message."""
        header = self.encode_soe_header(0x20e4dbe3, 5)
        msg_bytes = len(message.encode('utf-16-le'))
        buf = bytearray(4 + msg_bytes + 12)  # uint32 len + utf16 data + spacer + room_id + req_id
        off = 0
        off = _write_ustring(buf, off, message)
        # 4 bytes spacer (zeros)
        off += 4
        struct.pack_into("<I", buf, off, room_id)
        off += 4
        self.session.request_id += 1
        struct.pack_into("<I", buf, off, self.session.request_id)
        off += 4
        return self.encrypt(header + buf[:off])

    def encode_npc_conversation_select(self, object_id: int, npc_id: int,
                                        option_index: int) -> bytearray:
        """Encode NpcConversationSelect (ObjectController 0x00E1) — choose a response."""
        header = self.encode_soe_header(0x80CE5E46, 5)
        buf = bytearray(28)
        off = 0
        struct.pack_into("<I", buf, off, 0x23)           # header1
        off += 4
        struct.pack_into("<I", buf, off, 0x00E1)         # header2 (NpcConversationSelect)
        off += 4
        struct.pack_into("<Q", buf, off, object_id)      # player object ID
        off += 8
        struct.pack_into("<I", buf, off, 0)              # padding
        off += 4
        struct.pack_into("<Q", buf, off, npc_id)         # NPC object ID
        off += 8
        # Option is encoded in the selectedOption byte
        # Wait — looking at protocol more carefully, the select sends just the index after npc_id
        # Rewrite with correct format
        buf2 = bytearray(32)
        off = 0
        struct.pack_into("<I", buf2, off, 0x23)
        off += 4
        struct.pack_into("<I", buf2, off, 0x00E1)
        off += 4
        struct.pack_into("<Q", buf2, off, object_id)
        off += 8
        struct.pack_into("<I", buf2, off, 0)
        off += 4
        struct.pack_into("<I", buf2, off, option_index)  # selected option index
        off += 4
        return self.encrypt(header + buf2[:off])

    def encode_npc_conversation_stop(self, object_id: int, npc_id: int) -> bytearray:
        """Encode StopNpcConversation (ObjectController 0x00DE)."""
        header = self.encode_soe_header(0x80CE5E46, 5)
        buf = bytearray(28)
        off = 0
        struct.pack_into("<I", buf, off, 0x23)
        off += 4
        struct.pack_into("<I", buf, off, 0x00DE)         # StopNpcConversation
        off += 4
        struct.pack_into("<Q", buf, off, object_id)
        off += 8
        struct.pack_into("<I", buf, off, 0)
        off += 4
        struct.pack_into("<Q", buf, off, npc_id)
        off += 8
        return self.encrypt(header + buf[:off])

    # --- Decoding methods ---

    def decode(self, data: bytes) -> list:
        """Decode an SOE packet, returning a list of decoded messages."""
        buf = bytearray(data)
        header = struct.unpack_from(">H", buf, 0)[0]

        # Decrypt if needed (headers > 0x0002 are encrypted)
        if header > 0x0002:
            buf = self.decrypt(buf)

        if header == 0x0001:  # SessionRequest (shouldn't happen from server)
            return [{"type": "SessionRequest"}]

        elif header == 0x0002:  # SessionResponse
            self.session.connection_id = struct.unpack_from(">I", buf, 2)[0]
            self.session.crc_seed = struct.unpack_from(">I", buf, 6)[0]
            self.session.crc_length = buf[10]
            self.session.use_compression = buf[11]
            self.session.seed_size = buf[12]
            self.session.server_udp_size = struct.unpack_from(">I", buf, 13)[0]
            self.session.sequence = 0
            self.session.last_ack = -1
            self.session.last_sequence = -1
            self.session.request_id = 0
            # A new session resets the sequence space, so any half-assembled
            # fragment belongs to the DEAD one. Leaving it armed makes the next
            # first-fragment append into a stale accumulator, and its 4-byte
            # length field gets read as payload — poisoning every fragmented
            # message that follows, forever. Both current new-session paths swap
            # in a fresh SOEProtocol so this is defensive today, but a
            # server-initiated resync on a live object would hit it.
            # (GLM-5.2 review, 2026-07-12.)
            self.session.fragments = None
            self.session.fragment_length = 0
            # In-order state belongs to the DEAD session. Carrying next_expected or a
            # half-open gap into a fresh sequence space would reject every new packet
            # as a "duplicate" — silent deafness. Reset it with everything else.
            self.session.next_expected = 0
            self.session.initialized = False
            self.session.bootstrap_streak = 0
            self.session.boot_origin = 0
            self.session.gap_min = None
            self.session.gap_since = None
            return [{"type": "SessionResponse",
                     "connection_id": self.session.connection_id,
                     "crc_seed": self.session.crc_seed}]

        elif header == 0x0003:  # MultiPacket — NOT sent by our peer; drop it.
            # The old code recursed into decode() for each sub-packet. That was a
            # DOUBLE-DECRYPT: the outer packet is already decrypted here, so each
            # sub-packet got decrypted a second time — corrupting it, and turning a
            # reliable sub-packet's header into a RANDOM 16-bit sequence stamp fed
            # straight into sequence state. (It also sliced a 3-byte trailer that
            # sub-packets do not carry, eating real payload.)
            #
            # Core3 NEVER sends this. BaseMultiPacket::add() emits
            # `insertShort(0x0900); insertShort(0); insertShort(0x1900)` — a
            # DataChannelA (0x0009) carrying operand 0x0019 — which is handled by
            # the _decode_multi_swg path below. Verified 2026-07-12.
            #
            # So: we have never seen one, and cannot test a parser for it. Writing an
            # unverifiable parser for a packet that never arrives is strictly worse
            # than not having one — a mis-parse injects garbage into the sequence
            # layer, which is the exact bug class this work exists to kill. If one
            # ever DOES arrive, something is badly wrong (corruption, or a packet
            # from a peer that is not ours). Say so loudly and drop it.
            self.session.multipacket_dropped += 1
            print(f"[soe] WARN: received a 0x0003 MultiPacket ({len(buf)}b) — Core3 never sends "
                  f"these. Dropping (corruption or foreign peer?).")
            return []

        elif header == 0x0005:  # Disconnect
            return [{"type": "Disconnect",
                     "connection_id": struct.unpack_from(">I", buf, 2)[0],
                     "reason": buf[6]}]

        elif header == 0x0008:  # ServerNetStatusUpdate
            return []

        elif header == 0x0009:  # DataChannelA
            if not self._accept_sequence(buf):      # wrap-aware; see _reliable_incoming_id
                return []

            operands = struct.unpack_from(">H", buf, 4)[0]

            if operands == 0x0019:  # Multi-SWG indicator
                return self._decode_multi_swg(buf, 6)
            else:
                opcode = struct.unpack_from("<I", buf, 6)[0]
                msg_data = buf[10:-3] if len(buf) > 13 else b""
                msg = self._decode_swg_message(opcode, bytes(msg_data))
                return [msg] if msg else []

        elif header == 0x000d:  # FragmentA
            if not self._accept_sequence(buf):      # wrap-aware; see _reliable_incoming_id
                return []

            if self.session.fragments is None:
                self.session.fragment_length = struct.unpack_from(">I", buf, 4)[0]
                self.session.fragments = bytearray(buf[8:-3])
            else:
                self.session.fragments.extend(buf[4:-3])

                if len(self.session.fragments) >= self.session.fragment_length:
                    reassembled = self.session.fragments
                    self.session.fragments = None
                    operands = struct.unpack_from("<H", reassembled, 0)[0]
                    opcode = struct.unpack_from("<I", reassembled, 2)[0]
                    msg = self._decode_swg_message(opcode, bytes(reassembled[6:]))
                    return [msg] if msg else []
                elif len(self.session.fragments) > self.session.fragment_length:
                    self.session.fragments = None

            return []

        elif header == 0x0015:  # Ack
            return [{"type": "Ack", "sequence": struct.unpack_from(">H", buf, 2)[0]}]

        elif header == 0x0019:  # MultiSWG_A (multiple SWG messages)
            if not self._accept_sequence(buf):      # wrap-aware; see _reliable_incoming_id
                return []
            return self._decode_multi_swg(buf, 4)

        return []

    def _decode_multi_swg(self, buf: bytearray, start: int) -> list:
        """Decode multiple length-prefixed SWG messages."""
        results = []
        offset = start
        while offset < len(buf) - 3:
            pkt_len = buf[offset]
            offset += 1
            if pkt_len == 0xFF:
                if offset + 2 > len(buf) - 3:
                    break
                pkt_len = struct.unpack_from(">H", buf, offset)[0]
                offset += 2
            if pkt_len >= 6:
                sub_operands = struct.unpack_from("<H", buf, offset)[0]
                opcode = struct.unpack_from("<I", buf, offset + 2)[0]
                msg_data = buf[offset + 6:offset + pkt_len]
                msg = self._decode_swg_message(opcode, bytes(msg_data))
                if msg:
                    results.append(msg)
            offset += pkt_len
        return results

    def _decode_swg_message(self, opcode: int, data: bytes) -> Optional[dict]:
        """Decode a SWG game message by opcode."""
        if self.verbose:
            name = OPCODE_NAMES.get(opcode, f"0x{opcode:08x}")
            print(f"  [SWG] {name} ({len(data)} bytes)")

        if opcode == 0xaab296c6:  # LoginClientToken
            length = struct.unpack_from("<I", data, 0)[0]
            # Store entire blob (session string + embedded accountID) — sent back in ClientIdMsg
            self.session.session_key = data[4:4 + length]
            station_id = struct.unpack_from("<I", data, 4 + length)[0]
            off = 4 + length + 4
            username, off = _read_astring(data, off)
            return {"type": "LoginClientToken", "session_key": self.session.session_key,
                    "station_id": station_id, "username": username}

        elif opcode == 0xc11c63b9:  # LoginEnumCluster
            servers = {}
            count = struct.unpack_from("<I", data, 0)[0]
            off = 4
            for _ in range(count):
                server_id = struct.unpack_from("<I", data, off)[0]
                off += 4
                name, off = _read_astring(data, off)
                distance = struct.unpack_from("<i", data, off)[0]
                off += 4
                servers[server_id] = {"name": name, "distance": distance}
            return {"type": "LoginEnumCluster", "servers": servers}

        elif opcode == 0x3436aeb6:  # LoginClusterStatus
            servers = {}
            count = struct.unpack_from("<I", data, 0)[0]
            off = 4
            for _ in range(count):
                server_id = struct.unpack_from("<I", data, off)[0]
                off += 4
                ip, off = _read_astring(data, off)
                port = struct.unpack_from("<H", data, off)[0]
                ping_port = struct.unpack_from("<H", data, off + 2)[0]
                population = struct.unpack_from("<i", data, off + 4)[0]
                max_cap = struct.unpack_from("<i", data, off + 8)[0]
                off += 25
                servers[server_id] = {"ip": ip, "port": port, "ping_port": ping_port,
                                      "population": population, "max_capacity": max_cap}
            return {"type": "LoginClusterStatus", "servers": servers}

        elif opcode == 0x65ea4574:  # EnumerateCharacterId
            characters = {}
            count = struct.unpack_from("<I", data, 0)[0]
            off = 4
            for _ in range(count):
                name, off = _read_ustring(data, off)
                race_crc = struct.unpack_from("<I", data, off)[0]
                char_id = data[off + 4:off + 12]
                server_id = struct.unpack_from("<I", data, off + 12)[0]
                status = struct.unpack_from("<I", data, off + 16)[0]
                off += 20
                characters[name] = {"name": name, "character_id": char_id,
                                    "server_id": server_id, "status": status}
            return {"type": "EnumerateCharacterId", "characters": characters}

        elif opcode == 0xe00730e5:  # ClientPermissions
            return {"type": "ClientPermissions",
                    "galaxy_open": data[0], "char_slot_open": data[1],
                    "unlimited_char": data[2]}

        elif opcode == 0xd5899226:  # ClientIdMsg
            length = struct.unpack_from("<I", data, 4)[0]
            session_key = data[8:8 + length]
            self.session.session_key = session_key
            return {"type": "ClientIdMsg", "session_key": session_key}

        elif opcode == 0x43fd1c22:  # CmdSceneReady
            return {"type": "CmdSceneReady"}

        elif opcode == 0x3ae6dfae:  # CmdStartScene
            off = 0
            ignore_layout = data[off]
            off += 1
            char_id = struct.unpack_from("<Q", data, off)[0]
            off += 8
            terrain, off = _read_astring(data, off)
            pos_x = struct.unpack_from("<f", data, off)[0]
            pos_z = struct.unpack_from("<f", data, off + 4)[0]
            pos_y = struct.unpack_from("<f", data, off + 8)[0]
            off += 12
            shared_template, off = _read_astring(data, off)
            galactic_time = struct.unpack_from("<Q", data, off)[0]
            return {"type": "CmdStartScene", "character_id": char_id,
                    "terrain": terrain, "x": pos_x, "z": pos_z, "y": pos_y,
                    "template": shared_template}

        elif opcode == 0xfe89ddea:  # SceneCreateObjectByCrc
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            # Quaternion (4 floats) + position (3 floats)
            qw, qx, qy, qz = struct.unpack_from("<4f", data, 8)
            px, pz, py = struct.unpack_from("<3f", data, 24)
            obj_crc = struct.unpack_from("<I", data, 36)[0]
            return {"type": "SceneCreateObjectByCrc", "object_id": obj_id,
                    "x": px, "z": pz, "y": py, "crc": obj_crc}

        elif opcode == 0x4d45d504:  # SceneDestroyObject
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            return {"type": "SceneDestroyObject", "object_id": obj_id}

        elif opcode == 0x2c436037:  # SceneEndBaselines
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            return {"type": "SceneEndBaselines", "object_id": obj_id}

        elif opcode == 0x68a75f0c:  # BaselinesMessage
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            type_tag = data[8:12]
            baseline_num = data[12]
            payload_size = struct.unpack_from("<I", data, 13)[0]
            return {"type": "BaselinesMessage", "object_id": obj_id,
                    "type_tag": type_tag.decode("ascii", errors="replace"),
                    "baseline_num": baseline_num, "size": payload_size,
                    "data": data[17:17 + payload_size]}

        elif opcode == 0x12862153:  # DeltasMessage
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            type_tag = data[8:12]
            delta_num = data[12]
            return {"type": "DeltasMessage", "object_id": obj_id,
                    "type_tag": type_tag.decode("ascii", errors="replace"),
                    "delta_num": delta_num}

        elif opcode == 0x80ce5e46:  # ObjControllerMessage
            header1 = struct.unpack_from("<I", data, 0)[0]
            header2 = struct.unpack_from("<I", data, 4)[0]
            obj_id = struct.unpack_from("<Q", data, 8)[0]
            controller_data = data[20:]  # skip header1(4) + header2(4) + objID(8) + pad(4)
            return {"type": "ObjControllerMessage", "header1": header1,
                    "header2": header2, "object_id": obj_id, "data": controller_data}

        elif opcode == 0x1b24f808:  # UpdateTransformMessage
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            x = struct.unpack_from("<h", data, 8)[0] / 4.0
            z = struct.unpack_from("<h", data, 10)[0] / 4.0
            y = struct.unpack_from("<h", data, 12)[0] / 4.0
            return {"type": "UpdateTransformMessage", "object_id": obj_id,
                    "x": x, "z": z, "y": y}

        elif opcode == 0xc867ab5a:  # UpdateTransformWithParent
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            cell_id = struct.unpack_from("<Q", data, 8)[0]
            x = struct.unpack_from("<h", data, 16)[0] / 8.0
            z = struct.unpack_from("<h", data, 18)[0] / 8.0
            y = struct.unpack_from("<h", data, 20)[0] / 8.0
            return {"type": "UpdateTransformWithParent", "object_id": obj_id,
                    "cell_id": cell_id, "x": x, "z": z, "y": y}

        elif opcode == 0x0bde6b41:  # UpdatePostureMessage
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            posture = data[8] if len(data) > 8 else 0
            return {"type": "UpdatePostureMessage", "object_id": obj_id, "posture": posture}

        elif opcode == 0x56cbde9e:  # UpdateContainmentMessage
            obj_id = struct.unpack_from("<Q", data, 0)[0]
            container_id = struct.unpack_from("<Q", data, 8)[0]
            slot = struct.unpack_from("<i", data, 16)[0]
            return {"type": "UpdateContainmentMessage", "object_id": obj_id,
                    "container_id": container_id, "slot": slot}

        elif opcode == 0x6d2a6413:  # ChatSystemMessage
            off = 0
            flags = struct.unpack_from("<I", data, off)[0]
            off += 4
            message, off = _read_ustring(data, off)
            return {"type": "ChatSystemMessage", "message": message}

        elif opcode == 0xcd4ce444:  # ChatRoomMessage
            off = 0
            _, off = _read_astring(data, off)  # SWG
            _, off = _read_astring(data, off)  # Server
            char_name, off = _read_astring(data, off)
            room_id = struct.unpack_from("<I", data, off)[0]
            off += 4
            message, off = _read_ustring(data, off)
            return {"type": "ChatRoomMessage", "character": char_name,
                    "room_id": room_id, "message": message}

        elif opcode == 0x3c565ced:  # ChatInstantMessageToClient
            off = 0
            _, off = _read_astring(data, off)  # SWG
            _, off = _read_astring(data, off)  # Server
            player_name, off = _read_astring(data, off)
            message, off = _read_ustring(data, off)
            return {"type": "ChatInstantMessageToClient", "player": player_name,
                    "message": message}

        elif opcode == 0x70deb197:  # ChatRoomList
            rooms = {}
            count = struct.unpack_from("<I", data, 0)[0]
            off = 4
            for _ in range(count):
                room_id = struct.unpack_from("<I", data, off)[0]
                is_public = struct.unpack_from("<I", data, off + 4)[0] > 0
                is_moderated = data[off + 8] > 0
                off += 9
                room_path, off = _read_astring(data, off)
                _, off = _read_astring(data, off)  # SWG
                _, off = _read_astring(data, off)  # Galaxy
                owner, off = _read_astring(data, off)
                _, off = _read_astring(data, off)  # SWG
                _, off = _read_astring(data, off)  # Galaxy
                creator, off = _read_astring(data, off)
                title, off = _read_ustring(data, off)
                # Moderators list
                mod_count = struct.unpack_from("<I", data, off)[0]
                off += 4
                for _ in range(mod_count):
                    _, off = _read_astring(data, off)
                    _, off = _read_astring(data, off)
                    _, off = _read_astring(data, off)
                # Users list
                user_count = struct.unpack_from("<I", data, off)[0]
                off += 4
                for _ in range(user_count):
                    _, off = _read_astring(data, off)
                    _, off = _read_astring(data, off)
                    _, off = _read_astring(data, off)
                rooms[room_id] = {"path": room_path, "owner": owner}
            return {"type": "ChatRoomList", "rooms": rooms}

        elif opcode == 0x35d7cc9f:  # ChatOnCreateRoom
            off = 0
            error = struct.unpack_from("<I", data, off)[0]; off += 4
            room_id = struct.unpack_from("<I", data, off)[0]; off += 4
            _private = struct.unpack_from("<I", data, off)[0]; off += 4
            _moderated = data[off]; off += 1
            room_path, off = _read_astring(data, off)
            return {"type": "ChatOnCreateRoom", "error": error,
                    "room_id": room_id, "room_path": room_path}

        elif opcode == 0xc4de864e:  # ChatQueryRoomResults
            off = 0
            # Skip player/invited/moderator/banned lists
            for _ in range(4):
                count = struct.unpack_from("<I", data, off)[0]; off += 4
                for _ in range(count):
                    _, off = _read_astring(data, off)  # SWG
                    _, off = _read_astring(data, off)  # Galaxy
                    _, off = _read_astring(data, off)  # Name
            request_id = struct.unpack_from("<I", data, off)[0]; off += 4
            room_id = struct.unpack_from("<I", data, off)[0]; off += 4
            _private = struct.unpack_from("<I", data, off)[0]; off += 4
            _moderated = data[off]; off += 1
            room_path, off = _read_astring(data, off)
            return {"type": "ChatQueryRoomResults", "room_id": room_id,
                    "room_path": room_path, "request_id": request_id}

        elif opcode == 0xe69bdc0a:  # ChatOnEnteredRoom
            off = 0
            _, off = _read_astring(data, off)  # SWG
            _, off = _read_astring(data, off)  # Galaxy
            player_name, off = _read_astring(data, off)
            error = struct.unpack_from("<I", data, off)[0]
            room_id = struct.unpack_from("<I", data, off + 4)[0]
            return {"type": "ChatOnEnteredRoom", "player": player_name,
                    "room_id": room_id, "error": error}

        elif opcode == 0x60b5098b:  # ChatOnLeaveRoom
            # Same wire layout as ChatOnEnteredRoom (Core3 ChatOnLeaveRoom.h):
            # ChatAvatar (SWG/Galaxy/Name astrings) + error + room_id + request_id.
            # Without decoding player/room_id the handler cannot tell its own
            # leave from the broadcast of every other member leaving the room.
            off = 0
            _, off = _read_astring(data, off)  # SWG
            _, off = _read_astring(data, off)  # Galaxy
            player_name, off = _read_astring(data, off)
            error = struct.unpack_from("<I", data, off)[0]
            room_id = struct.unpack_from("<I", data, off + 4)[0]
            return {"type": "ChatOnLeaveRoom", "player": player_name,
                    "room_id": room_id, "error": error}

        elif opcode == 0x1DB575CC:  # ClientCreateCharacterSuccess
            char_id = struct.unpack_from("<Q", data, 0)[0]
            return {"type": "ClientCreateCharacterSuccess", "character_id": char_id}

        elif opcode == 0xDF333C6E:  # ClientCreateCharacterFailed
            error, _ = _read_astring(data, 0)
            return {"type": "ClientCreateCharacterFailed", "error": error}

        elif opcode == 0xb5abf91a:  # ErrorMessage
            off = 0
            title, off = _read_astring(data, off)
            message, off = _read_astring(data, off)
            fatal = data[off] if off < len(data) else 0
            return {"type": "ErrorMessage", "title": title, "message": message, "fatal": fatal}

        elif opcode == 0x0f5d5325:  # ClientInactivity
            return {"type": "ClientInactivity", "flag": data[0]}

        elif opcode == 0x2e365218:  # ConnectPlayer
            return {"type": "ConnectPlayer"}

        elif opcode == 0x6137556f:  # ConnectPlayerResponse
            return {"type": "ConnectPlayerResponse"}

        elif opcode == 0x31805ee0:  # LagRequest
            return {"type": "LagRequest"}

        elif opcode == 0x1590f63c:  # ConnectionServerLagResponse
            return {"type": "ConnectionServerLagResponse"}

        elif opcode == 0x789a4e0a:  # GameServerLagResponse
            return {"type": "GameServerLagResponse"}

        elif opcode == 0xc5ed2f85:  # LagReport
            return {"type": "LagReport"}

        else:
            name = OPCODE_NAMES.get(opcode, f"0x{opcode:08x}")
            if self.verbose:
                print(f"  [SWG] Unhandled: {name} ({len(data)} bytes)")
            return {"type": name, "_raw": True}


# --- String helpers ---

def _read_astring(data: bytes, off: int) -> tuple:
    """Read an ASCII string: [uint16 LE length][bytes]."""
    length = struct.unpack_from("<H", data, off)[0]
    s = data[off + 2:off + 2 + length].decode("ascii", errors="replace")
    return s, off + 2 + length


def _read_ustring(data: bytes, off: int) -> tuple:
    """Read a Unicode string: [uint32 LE char_count][UTF-16LE pairs]."""
    length = struct.unpack_from("<I", data, off)[0]
    s = data[off + 4:off + 4 + length * 2].decode("utf-16-le", errors="replace")
    return s, off + 4 + length * 2


def _write_astring(buf: bytearray, off: int, s: str) -> int:
    """Write an ASCII string: [uint16 LE length][bytes]."""
    encoded = s.encode("ascii")
    struct.pack_into("<H", buf, off, len(encoded))
    buf[off + 2:off + 2 + len(encoded)] = encoded
    return off + 2 + len(encoded)


def _write_ustring(buf: bytearray, off: int, s: str) -> int:
    """Write a Unicode string: [uint32 LE char_count][UTF-16LE pairs]."""
    encoded = s.encode("utf-16-le")
    struct.pack_into("<I", buf, off, len(s))
    buf[off + 4:off + 4 + len(encoded)] = encoded
    return off + 4 + len(encoded)


# Opcode name lookup (subset — add more as needed)
OPCODE_NAMES = {
    0x41131f96: "LoginClientID",
    0xaab296c6: "LoginClientToken",
    0xc11c63b9: "LoginEnumCluster",
    0x3436aeb6: "LoginClusterStatus",
    0x65ea4574: "EnumerateCharacterId",
    0xb5098d76: "SelectCharacter",
    0xe00730e5: "ClientPermissions",
    0xd5899226: "ClientIdMsg",
    0x43fd1c22: "CmdSceneReady",
    0x3ae6dfae: "CmdStartScene",
    0xfe89ddea: "SceneCreateObjectByCrc",
    0x4d45d504: "SceneDestroyObject",
    0x2c436037: "SceneEndBaselines",
    0x68a75f0c: "BaselinesMessage",
    0x12862153: "DeltasMessage",
    0x1b24f808: "UpdateTransformMessage",
    0xc867ab5a: "UpdateTransformWithParent",
    0x80ce5e46: "ObjControllerMessage",
    0x6d2a6413: "ChatSystemMessage",
    0xcd4ce444: "ChatRoomMessage",
    0x20e4dbe3: "ChatSendToRoom",
    0x84bb21f7: "ChatInstantMessageToCharacter",
    0x3c565ced: "ChatInstantMessageToClient",
    0x88dbb381: "ChatOnSendInstantMessage",
    0x35d7cc9f: "ChatOnCreateRoom",
    0xc4de864e: "ChatQueryRoomResults",
    0xe69bdc0a: "ChatOnEnteredRoom",
    0x60b5098b: "ChatOnLeaveRoom",
    0x70deb197: "ChatRoomList",
    0xbc6bddf2: "ChatEnterRoomById",
    0x4c3d2cfa: "ChatRequestRoomList",
    0x0f5d5325: "ClientInactivity",
    0x2e365218: "ConnectPlayer",
    0x6137556f: "ConnectPlayerResponse",
    0x31805ee0: "LagRequest",
    0x1590f63c: "ConnectionServerLagResponse",
    0x789a4e0a: "GameServerLagResponse",
    0xc5ed2f85: "LagReport",
    0xB97F3074: "ClientCreateCharacter",
    0x1DB575CC: "ClientCreateCharacterSuccess",
    0xDF333C6E: "ClientCreateCharacterFailed",
    0xa16cf9af: "HeartBeat",
    0x56cbde9e: "UpdateContainmentMessage",
    0x08a1c126: "UpdatePvpStatusMessage",
}
