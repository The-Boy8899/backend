"""
MIFARE Classic Encoder (PC/SC)
- Writes length-prefixed UTF-8 JSON payload
- Supports dual Key A / Key B authentication
- Clears unused blocks
- Safe for card reuse
Requires: pyscard
"""

import argparse
import json
import sys
import time
from smartcard.System import readers

# ================= CONFIG =================
KEY_A = bytes.fromhex("FFFFFFFFFFFF")
KEY_B = bytes.fromhex("FFFFFFFFFFFF")

# All usable data blocks for MIFARE Classic 1K (excluding sector trailers and block 0 of sector 0)
SAFE_BLOCKS = [
    1, 2,  # sector 0 (skip block 0, manufacturer)
    *[b for s in range(1, 16) for b in range(s * 4, s * 4 + 3)]  # blocks 0,1,2 of sectors 1-15
]


# ================= HELPERS =================
def pad16(b: bytes) -> bytes:
    return b.ljust(16, b"\x00")[:16]


def load_key(conn, key: bytes, slot: int):
    apdu = [0xFF, 0x82, 0x00, slot, 0x06] + list(key)
    _, sw1, _ = conn.transmit(apdu)
    return sw1 == 0x90


def auth_block(conn, blk: int) -> bool:
    """
    Try Key A first, then Key B.
    Key A → slot 0
    Key B → slot 1
    """
    # Try Key A
    apdu_a = [0xFF, 0x86, 0x00, 0x00, 0x05,
              0x01, 0x00, blk, 0x60, 0x00]
    _, sw1, _ = conn.transmit(apdu_a)
    if sw1 == 0x90:
        return True

    # Try Key B
    apdu_b = [0xFF, 0x86, 0x00, 0x00, 0x05,
              0x01, 0x00, blk, 0x61, 0x01]
    _, sw1, _ = conn.transmit(apdu_b)
    return sw1 == 0x90


# ================= MAIN LOGIC =================
def init_database(db_path):
    """Ensure database and tables exist"""
    import sqlite3
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Create members table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  member_id TEXT UNIQUE NOT NULL,
                  name TEXT NOT NULL,
                  expiry TEXT NOT NULL,
                  issued_at INTEGER NOT NULL,
                  member_type TEXT DEFAULT 'member',
                  status TEXT DEFAULT 'active',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()


def lookup_uid_in_database(uid, db_path="../community_id.db"):
    """Look up a member by UID in the database"""
    import sqlite3
    
    # Ensure database is initialized
    init_database(db_path)
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Query the members table
        c.execute('''SELECT member_id, name, expiry, status FROM members 
                    WHERE member_id = ? 
                    LIMIT 1''', (uid,))
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                "member_id": row[0],
                "name": row[1],
                "expiry": row[2],
                "status": row[3]
            }
        else:
            return None
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error looking up UID: {e}", file=sys.stderr)
        return None

def write_blocks_pcsc(payload: dict, verbose=False, add_uid=False):
    """Write payload to MIFARE Classic card via PC/SC reader"""
    try:
        r = readers()
        if not r:
            raise RuntimeError("No PC/SC readers found")

        reader = next((rr for rr in r if "ACR" in str(rr)), r[0])
        conn = reader.createConnection()
        conn.connect()

        if verbose:
            print(f"Using reader: {reader}")

        # Load keys
        if not load_key(conn, KEY_A, 0):
            raise RuntimeError("Failed to load Key A")

        if not load_key(conn, KEY_B, 1):
            raise RuntimeError("Failed to load Key B")

        # Optional UID binding - read from card if requested
        if add_uid:
            resp, sw1, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            if sw1 == 0x90:
                uid_hex = bytes(resp).hex().upper()
                payload["uid"] = uid_hex
                if verbose:
                    print(f"Read UID from card: {uid_hex}")

        # Prepare minimal payload (UID, member_id, name, status)
        minimal_payload = {
            "uid": payload.get("uid", ""),
            "member_id": payload.get("member_id", ""),
            "name": payload.get("name", ""),
            "status": payload.get("status", "active")
        }
        
        payload_bytes = json.dumps(minimal_payload, separators=(",", ":")).encode("utf-8")
        length = len(payload_bytes)
        raw = length.to_bytes(2, "big") + payload_bytes

        chunks = [pad16(raw[i:i + 16]) for i in range(0, len(raw), 16)]

        if len(chunks) > len(SAFE_BLOCKS):
            raise RuntimeError(f"Payload too large ({len(chunks)} chunks) for available blocks ({len(SAFE_BLOCKS)})")

        # Write blocks
        for i, chunk in enumerate(chunks):
            blk = SAFE_BLOCKS[i]

            if not auth_block(conn, blk):
                raise RuntimeError(f"Authentication failed for block {blk}")

            write_apdu = [0xFF, 0xD6, 0x00, blk, 0x10] + list(chunk)
            _, sw1, _ = conn.transmit(write_apdu)
            if sw1 != 0x90:
                raise RuntimeError(f"Write failed for block {blk}")

            if verbose:
                print(f"Wrote block {blk}")

        # Clear unused blocks
        for blk in SAFE_BLOCKS[len(chunks):]:
            if not auth_block(conn, blk):
                continue
            zero_apdu = [0xFF, 0xD6, 0x00, blk, 0x10] + [0x00] * 16
            conn.transmit(zero_apdu)

        if verbose:
            print("Payload written successfully")
        return 0
        
    except Exception as e:
        print(f"Write error: {e}", file=sys.stderr)
        return 1


# ================= ENTRY POINT =================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read card UID and lookup/encode member data to card")
    from pathlib import Path
    default_db = str(Path(__file__).resolve().parent.parent / "community_id.db")
    parser.add_argument("--db", help="Path to SQLite database", default=default_db)
    parser.add_argument("--member-id", help="Member ID to encode (optional, will use card UID if not provided)")
    parser.add_argument("--write", action="store_true", help="Write member data to card")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    try:
        # Read UID from card
        r = readers()
        if not r:
            print("ERROR: No PC/SC readers found. Please connect a card reader.", file=sys.stderr)
            sys.exit(1)
        
        reader = next((rr for rr in r if "ACR" in str(rr)), r[0])
        if args.verbose:
            print(f"Using reader: {reader}")
        
        conn = reader.createConnection()
        conn.connect()
        
        # Get card UID
        get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        resp, sw1, sw2 = conn.transmit(get_uid)
        
        if sw1 != 0x90:
            print(f"ERROR: Failed to read UID from card - SW1={sw1:02X}, SW2={sw2:02X}", file=sys.stderr)
            sys.exit(1)
        
        card_uid = bytes(resp).hex().upper()
        print(f"Card UID: {card_uid}")
        
        # Determine member ID to lookup
        lookup_id = args.member_id if args.member_id else card_uid
        
        # Lookup in database
        result = lookup_uid_in_database(lookup_id, db_path=args.db)
        
        if result:
            print(f"\n✓ Member found in database:")
            print(f"  Member ID: {result['member_id']}")
            print(f"  Name: {result['name']}")
            print(f"  Expiry: {result['expiry']}")
            print(f"  Status: {result['status']}")
            
            # If write flag is set, encode to card
            if args.write:
                print(f"\nWriting member data to card...")
                payload = {
                    "uid": card_uid,
                    "member_id": result['member_id'],
                    "name": result['name'],
                    "status": result['status']
                }
                exit_code = write_blocks_pcsc(payload, verbose=args.verbose, add_uid=True)
                if exit_code == 0:
                    print("✓ Successfully encoded member data to card")
                else:
                    print("ERROR: Failed to write data to card", file=sys.stderr)
                    sys.exit(1)
        else:
            print(f"✗ No member found for: {lookup_id}")
            if args.write:
                print("ERROR: Cannot write to card - member not found in database", file=sys.stderr)
                sys.exit(1)

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
