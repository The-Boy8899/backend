"""
MIFARE Classic Reader (PC/SC)
- Length-prefixed UTF-8 JSON
- Dual Key A / Key B auth
- Zero-padding safe
Requires: pyscard
"""

import json
import sys
from smartcard.System import readers

KEY_A = bytes.fromhex("FFFFFFFFFFFF")
KEY_B = bytes.fromhex("FFFFFFFFFFFF")

SAFE_BLOCKS = [1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14]


def load_key(conn, key: bytes, slot: int) -> bool:
    """Load authentication key into reader"""
    apdu = [0xFF, 0x82, 0x00, slot, 0x06] + list(key)
    _, sw1, _ = conn.transmit(apdu)
    return sw1 == 0x90


def auth_block(conn, blk: int) -> bool:
    """Authenticate to a block using Key A, fallback to Key B"""
    # Try Key A first (slot 0)
    apdu_a = [0xFF, 0x86, 0x00, 0x00, 0x05,
              0x01, 0x00, blk, 0x60, 0x00]
    _, sw1, _ = conn.transmit(apdu_a)
    if sw1 == 0x90:
        return True

    # Try Key B (slot 1)
    apdu_b = [0xFF, 0x86, 0x00, 0x00, 0x05,
              0x01, 0x00, blk, 0x61, 0x01]
    _, sw1, _ = conn.transmit(apdu_b)
    return sw1 == 0x90


def read_card_uid(verbose=False):
    """
    Read card UID and return it as hex string.
    Returns: (success: bool, result: str)
    """
    try:
        r = readers()
        if not r:
            return False, "No PC/SC readers found"

        reader = next((rr for rr in r if "ACR" in str(rr)), r[0])
        conn = reader.createConnection()
        conn.connect()

        if verbose:
            print(f"Using reader: {reader}")

        # Get UID command
        get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        resp, sw1, sw2 = conn.transmit(get_uid)
        
        if sw1 == 0x90:
            uid_hex = bytes(resp).hex().upper()
            if verbose:
                print(f"Card UID: {uid_hex}")
            return True, uid_hex
        else:
            return False, f"Failed to read UID: SW1={sw1:02X}, SW2={sw2:02X}"
            
    except Exception as e:
        return False, str(e)


def read_card_data(verbose=False):
    """
    Read card data blocks and parse JSON payload.
    Returns: (success: bool, data: dict)
    """
    try:
        r = readers()
        if not r:
            return False, {"error": "No PC/SC readers found"}

        reader = next((rr for rr in r if "ACR" in str(rr)), r[0])
        conn = reader.createConnection()
        conn.connect()

        if verbose:
            print(f"Using reader: {reader}")

        # Load keys
        if not load_key(conn, KEY_A, 0):
            return False, {"error": "Failed to load Key A"}

        if not load_key(conn, KEY_B, 1):
            return False, {"error": "Failed to load Key B"}

        # Get UID
        get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        resp, sw1, _ = conn.transmit(get_uid)
        if sw1 != 0x90:
            return False, {"error": "Failed to read UID"}
        
        card_uid = bytes(resp).hex().upper()
        if verbose:
            print(f"Card UID: {card_uid}")

        # Read blocks
        raw_data = b""
        for blk in SAFE_BLOCKS:
            if not auth_block(conn, blk):
                if verbose:
                    print(f"Skipping block {blk} - auth failed")
                continue

            read_apdu = [0xFF, 0xB0, 0x00, blk, 0x10]
            resp, sw1, _ = conn.transmit(read_apdu)
            
            if sw1 == 0x90:
                raw_data += bytes(resp)
                if verbose:
                    print(f"Read block {blk}")
            else:
                if verbose:
                    print(f"Failed to read block {blk}")

        if not raw_data:
            return False, {"error": "No data read from card"}

        # Parse length-prefixed data
        if len(raw_data) < 2:
            return False, {"error": "Invalid data format"}

        payload_length = int.from_bytes(raw_data[0:2], "big")
        if payload_length > len(raw_data) - 2:
            return False, {"error": f"Invalid payload length: {payload_length}"}

        payload_bytes = raw_data[2:2 + payload_length]
        
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            if verbose:
                print(f"Parsed payload: {payload}")
            # Ensure UID is included
            if "uid" not in payload:
                payload["uid"] = card_uid
            return True, payload
        except json.JSONDecodeError as e:
            return False, {"error": f"Failed to parse JSON: {e}"}

    except Exception as e:
        return False, {"error": str(e)}


def read_card():
    """
    Main function to read card - tries to get full data, falls back to UID only.
    Returns: (success: bool, data: dict)
    """
    # Try to read full data first
    ok, data = read_card_data()
    if ok:
        return True, data
    
    # Fallback: just read UID
    ok, uid = read_card_uid()
    if ok:
        return True, {"uid": uid, "status": "unknown"}
    
    # Complete failure
    return False, {"error": "Could not read card"}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Read MIFARE Classic card data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--uid-only", action="store_true", help="Only read card UID")
    args = parser.parse_args()

    if args.uid_only:
        ok, uid = read_card_uid(verbose=args.verbose)
        if ok:
            print(f"Card UID: {uid}")
        else:
            print(f"Error: {uid}", file=sys.stderr)
            sys.exit(1)
    else:
        ok, data = read_card(verbose=args.verbose)
        if ok:
            # Print JSON for parsing
            print(json.dumps(data))
        else:
            print(f"Error: {data.get('error', 'Unknown error')}", file=sys.stderr)
            sys.exit(1)
