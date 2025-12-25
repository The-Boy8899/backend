from fastapi.responses import JSONResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Header
import asyncio, logging, time
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, json, datetime, subprocess, sys, sqlite3, hashlib, jwt, secrets
from typing import List, Optional
from pydantic import BaseModel
from pathlib import Path
from contextlib import asynccontextmanager

# Device monitor task reference
device_monitor_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan event handler for startup and shutdown"""
    global device_monitor_task
    
    # Startup
    async def device_monitor():
        """Start background task to monitor NFC/PCSC readers and broadcast device events."""
        last_state = None
        while True:
            try:
                reader_list = []
                if pcsc_readers is not None:
                    try:
                        r = pcsc_readers()
                        reader_list = list(r) if r else []
                    except Exception:
                        reader_list = []

                reader_present = len(reader_list) > 0
                writer_present = write_blocks_pcsc is not None
                # If state changed, broadcast
                if last_state is None:
                    last_state = reader_present
                if reader_present != last_state:
                    last_state = reader_present
                    payload = {
                        "reader_available": reader_present,
                        "writer_available": writer_present,
                        "readers": [str(x) for x in reader_list],
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }
                    logger.info(f"NFC device presence changed: {payload}")
                    try:
                        await manager.broadcast({"type": "device_event", "payload": payload})
                    except Exception:
                        logger.exception("Failed to broadcast device_event")

            except Exception:
                logger.exception("Device monitor error")
            await asyncio.sleep(3)

    device_monitor_task = asyncio.create_task(device_monitor())
    yield
    
    # Shutdown
    if device_monitor_task and not device_monitor_task.done():
        device_monitor_task.cancel()
        try:
            await device_monitor_task
        except asyncio.CancelledError:
            pass

app = FastAPI(title="Community ID - Event Relay", lifespan=lifespan)

# Enable CORS for web frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
DB_PATH = Path(__file__).resolve().parent.parent / "community_id.db"

def init_database():
    """Initialize SQLite database for member management and authentication"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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
    c.execute('''CREATE TABLE IF NOT EXISTS card_reads
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  member_id TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  status TEXT,
                  FOREIGN KEY(member_id) REFERENCES members(member_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  is_admin BOOLEAN DEFAULT 0,
                  status TEXT DEFAULT 'active',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

# Authentication constants
ADMIN_USERNAME = "BROCHGATE"
ADMIN_PASSWORD = "adedayomi*76"
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hash

def create_token(username: str, is_admin: bool) -> str:
    """Create JWT token for user"""
    payload = {
        "username": username,
        "is_admin": is_admin,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None

# Prefer importing local encoder/reader modules (PC/SC) for direct calls
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from encoder.encoder import write_blocks_pcsc
except Exception:
    write_blocks_pcsc = None

try:
    from reader.reader import read_card
except Exception:
    read_card = None

# Try to import PC/SC readers() helper for device presence checks
try:
    from smartcard.System import readers as pcsc_readers
except Exception:
    pcsc_readers = None

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend")

## EncoderRequest model removed; accept dict instead

class MemberUpdate(BaseModel):
    status: str  # 'active', 'suspended', 'expired', etc.

class ReaderRequest(BaseModel):
    action: str = "read"

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str

class UserStatusUpdate(BaseModel):
    status: str  # 'active', 'suspended'

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected (total={len(self.active_connections)})")
        try:
            await self.broadcast({"type": "connection_event", "payload": {"connected": True, "count": len(self.active_connections)}})
        except Exception:
            pass
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected (total={len(self.active_connections)})")
            try:
                # inform remaining clients
                import datetime as _dt
                asyncio.create_task(self.broadcast({"type": "connection_event", "payload": {"connected": False, "count": len(self.active_connections), "timestamp": _dt.datetime.utcnow().isoformat()}}))
            except Exception:
                pass
    async def broadcast(self, message: dict):
        data = json.dumps(message)
        to_remove = []
        for conn in list(self.active_connections):
            try:
                await conn.send_text(data)
            except Exception:
                to_remove.append(conn)
        for r in to_remove:
            self.disconnect(r)

manager = ConnectionManager()

# ============== HELPER FUNCTION FOR TOKEN VALIDATION ==============
def get_auth_token(authorization: str = Header(None)) -> Optional[str]:
    """Extract and validate token from Authorization header"""
    if not authorization:
        return None
    if authorization.startswith("Bearer "):
        return authorization[7:]
    return None

# ============== AUTHENTICATION ENDPOINTS ==============

@app.post("/auth/admin-login")
async def admin_login(request: LoginRequest):
    """Admin login with hardcoded credentials"""
    if request.username == ADMIN_USERNAME and request.password == ADMIN_PASSWORD:
        token = create_token(request.username, is_admin=True)
        return {
            "status": "success",
            "token": token,
            "username": request.username,
            "is_admin": True
        }
    else:
        return {
            "status": "error",
            "message": "Invalid admin credentials"
        }

@app.post("/auth/user-login")
async def user_login(request: LoginRequest):
    """User login - checks database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, is_admin, status FROM users WHERE username = ?', (request.username,))
        user = c.fetchone()
        conn.close()
        
        if user and user[4] == 'active':
            user_id, username, password_hash, is_admin, status = user
            if verify_password(request.password, password_hash):
                token = create_token(username, is_admin=bool(is_admin))
                return {
                    "status": "success",
                    "token": token,
                    "username": username,
                    "is_admin": bool(is_admin)
                }
        
        return {
            "status": "error",
            "message": "Invalid credentials or account suspended"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/auth/create-user")
async def create_user(request: CreateUserRequest, authorization: str = Header(None)):
    """Create new user (admin only)"""
    try:
        # Verify token
        token = get_auth_token(authorization)
        if not token:
            return {"status": "error", "message": "Missing authorization token"}
        
        payload = verify_token(token)
        if not payload or not payload.get('is_admin'):
            return {"status": "error", "message": "Unauthorized - Admin only"}
        
        # Check if username exists
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (request.username,))
        if c.fetchone():
            conn.close()
            return {"status": "error", "message": "Username already exists"}
        
        # Create user
        password_hash = hash_password(request.password)
        c.execute('''INSERT INTO users (username, password_hash, is_admin, status)
                    VALUES (?, ?, 0, 'active')''',
                 (request.username, password_hash))
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "message": f"User {request.username} created successfully"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/auth/users")
async def list_users(authorization: str = Header(None)):
    """List all users (admin only)"""
    try:
        token = get_auth_token(authorization)
        if not token:
            return {"status": "error", "message": "Missing authorization token"}
        
        payload = verify_token(token)
        if not payload or not payload.get('is_admin'):
            return {"status": "error", "message": "Unauthorized - Admin only"}
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, username, is_admin, status, created_at FROM users')
        users = c.fetchall()
        conn.close()
        
        return {
            "status": "success",
            "users": [
                {
                    "id": u[0],
                    "username": u[1],
                    "is_admin": bool(u[2]),
                    "status": u[3],
                    "created_at": u[4]
                } for u in users
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.patch("/auth/users/{username}/status")
async def update_user_status(username: str, request: UserStatusUpdate, authorization: str = Header(None)):
    """Update user status (active/suspended) - admin only"""
    try:
        token = get_auth_token(authorization)
        if not token:
            return {"status": "error", "message": "Missing authorization token"}
        
        payload = verify_token(token)
        if not payload or not payload.get('is_admin'):
            return {"status": "error", "message": "Unauthorized - Admin only"}
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE users SET status = ? WHERE username = ?', (request.status, username))
        
        if c.rowcount == 0:
            conn.close()
            return {"status": "error", "message": "User not found"}
        
        conn.commit()
        conn.close()
        
        action = "suspended" if request.status == "suspended" else "activated"
        return {
            "status": "success",
            "message": f"User {username} {action}"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.delete("/auth/users/{username}")
async def delete_user(username: str, authorization: str = Header(None)):
    """Delete user - admin only"""
    try:
        token = get_auth_token(authorization)
        if not token:
            return {"status": "error", "message": "Missing authorization token"}
        
        payload = verify_token(token)
        if not payload or not payload.get('is_admin'):
            return {"status": "error", "message": "Unauthorized - Admin only"}
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        
        if c.rowcount == 0:
            conn.close()
            return {"status": "error", "message": "User not found"}
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "message": f"User {username} deleted"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/members/add")
async def add_member(request: Request):
    """Add a new member to the database with full details."""
    try:
        data = await request.json()
        member_id = data.get('uid')
        name = data.get('name')
        expiry = data.get('expiry')
        member_type = data.get('member_type', 'member')
        status = data.get('status', 'active')
        
        # Validate required fields
        if not member_id or not name or not expiry:
            return {"status": "error", "message": "Member ID, Name, and Expiry Date are required"}
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Insert or replace member with all details
        c.execute('''INSERT OR REPLACE INTO members 
                    (member_id, name, expiry, issued_at, member_type, status, updated_at) 
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
                 (member_id, name, expiry, int(time.time()), member_type, status))
        conn.commit()
        conn.close()
        
        return {
            "status": "success", 
            "message": f"Member {name} added successfully", 
            "member_id": member_id,
            "name": name,
            "expiry": expiry
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/nfc/uid")
async def nfc_uid():
    """Read card UID and return it for frontend auto-fill."""
    try:
        # Prefer direct PC/SC reader if available
        try:
            from reader.reader import read_card_uid
        except Exception:
            return JSONResponse({"status": "error", "message": "Reader module not available"}, status_code=500)
        ok, uid = read_card_uid()
        if ok:
            return {"status": "success", "uid": uid}
        else:
            return {"status": "error", "message": uid}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/nfc/encode")
async def nfc_encode(request: Request):
    """Encode member data to NFC card - lookup from database and write"""
    try:
        data = await request.json()
        member_id = data.get('member_id')
        
        if not member_id:
            return {"status": "error", "message": "member_id is required"}

        # Lookup member in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT member_id, name, expiry, status FROM members 
                    WHERE member_id = ?''', (member_id,))
        member = c.fetchone()
        conn.close()
        
        if not member:
            return {"status": "error", "message": f"Member {member_id} not found in database"}

        # Prepare payload with member data
        payload = {
            "member_id": member[0],
            "name": member[1],
            "expiry": member[2],
            "status": member[3]
        }
        
        # Write to card via PC/SC reader
        if write_blocks_pcsc is not None:
            try:
                rc = write_blocks_pcsc(payload, add_uid=True)
                if rc == 0:
                    try:
                        await manager.broadcast({
                            "type": "write_event",
                            "payload": {
                                "member_id": member_id,
                                "status": "success",
                                "message": "Card encoded successfully"
                            }
                        })
                    except Exception:
                        pass
                    return {
                        "status": "success",
                        "message": f"Card encoded with {member[1]} data",
                        "member_id": member_id
                    }
                else:
                    return {"status": "error", "message": "Encoder failed"}
            except Exception as e:
                return {"status": "error", "message": f"Encoder error: {str(e)}"}
        else:
            # Fallback to subprocess
            result = subprocess.run(
                [sys.executable, '../encoder/encoder.py', '--member-id', member_id, '--write', '-v'],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent / 'encoder'),
                timeout=120
            )
            if result.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Card encoded with {member[1]} data",
                    "member_id": member_id
                }
            else:
                error_msg = result.stderr or result.stdout
                return {"status": "error", "message": f"Encoder failed: {error_msg}"}
                
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/nfc/decode")
async def nfc_decode():
    """Read card and verify member - cross-check with database"""
    try:
        # Try direct reader if available
        if read_card is not None:
            try:
                ok, card_data = read_card()
                if not ok:
                    return {"status": "error", "message": card_data.get("error", "Read failed")}
                
                # Extract UID and member_id from card
                card_uid = card_data.get("uid")
                card_member_id = card_data.get("member_id", card_uid)
                card_status = card_data.get("status", "active")
                
                # Look up in database
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('''SELECT member_id, name, expiry, status FROM members 
                           WHERE member_id = ?''', (card_member_id,))
                db_member = c.fetchone()
                
                # Log the read
                if card_member_id:
                    c.execute('''INSERT INTO card_reads (member_id, timestamp, status) 
                               VALUES (?, CURRENT_TIMESTAMP, ?)''',
                             (card_member_id, card_status))
                    conn.commit()
                
                conn.close()
                
                # Prepare response with verification status
                if db_member:
                    return {
                        "status": "success",
                        "card_uid": card_uid,
                        "member_id": db_member[0],
                        "name": db_member[1],
                        "expiry": db_member[2],
                        "db_status": db_member[3],
                        "card_status": card_status,
                        "verified": True,
                        "card_data": card_data
                    }
                else:
                    return {
                        "status": "success",
                        "card_uid": card_uid,
                        "member_id": card_member_id,
                        "card_status": card_status,
                        "verified": False,
                        "message": "Card readable but member not found in database",
                        "card_data": card_data
                    }
                    
            except Exception as e:
                return {"status": "error", "message": f"Reader error: {str(e)}"}
        
        # Fallback to subprocess
        result = subprocess.run(
            [sys.executable, '../reader/reader.py', '-v'],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent / 'reader'),
            timeout=120
        )
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout
            return {"status": "error", "message": f"Reader failed: {error_msg}"}
        
        # Parse output
        try:
            card_data = json.loads(result.stdout.strip())
            card_uid = card_data.get("uid")
            card_member_id = card_data.get("member_id", card_uid)
            card_status = card_data.get("status", "active")
            
            # Look up in database
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''SELECT member_id, name, expiry, status FROM members 
                       WHERE member_id = ?''', (card_member_id,))
            db_member = c.fetchone()
            
            # Log the read
            if card_member_id:
                c.execute('''INSERT INTO card_reads (member_id, timestamp, status) 
                           VALUES (?, CURRENT_TIMESTAMP, ?)''',
                         (card_member_id, card_status))
                conn.commit()
            
            conn.close()
            
            if db_member:
                return {
                    "status": "success",
                    "card_uid": card_uid,
                    "member_id": db_member[0],
                    "name": db_member[1],
                    "expiry": db_member[2],
                    "db_status": db_member[3],
                    "card_status": card_status,
                    "verified": True,
                    "card_data": card_data
                }
            else:
                return {
                    "status": "success",
                    "card_uid": card_uid,
                    "member_id": card_member_id,
                    "card_status": card_status,
                    "verified": False,
                    "message": "Card readable but member not found",
                    "card_data": card_data
                }
        except json.JSONDecodeError:
            return {"status": "error", "message": "Failed to parse card data"}
            
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/events")
async def receive_event(payload: dict, request: Request):
    if 'timestamp' not in payload:
        payload['timestamp'] = datetime.datetime.utcnow().isoformat()
    await manager.broadcast({"type":"verification_event","payload":payload})
    return {"status":"ok"}


@app.get("/nfc/status")
async def nfc_status():
    """Return whether NFC reader/writer modules are available on the server."""
    try:
        return {
            "reader_available": read_card is not None,
            "writer_available": write_blocks_pcsc is not None
        }
    except Exception:
        return {"reader_available": False, "writer_available": False}

@app.get("/members")
async def get_all_members():
    """Fetch all members from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT member_id, name, expiry, member_type, status, created_at, updated_at FROM members ORDER BY created_at DESC')
        members = c.fetchall()
        conn.close()
        
        return {
            "status": "success",
            "members": [
                {
                    "member_id": m[0],
                    "name": m[1],
                    "expiry": m[2],
                    "member_type": m[3],
                    "status": m[4],
                    "created_at": m[5],
                    "updated_at": m[6]
                } for m in members
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/members/{member_id}")
async def get_member(member_id: str):
    """Fetch specific member details"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT member_id, name, expiry, member_type, status, created_at FROM members WHERE member_id = ?', (member_id,))
        member = c.fetchone()
        
        if member:
            # Get recent card reads
            c.execute('SELECT timestamp, status FROM card_reads WHERE member_id = ? ORDER BY timestamp DESC LIMIT 10', (member_id,))
            reads = c.fetchall()
            conn.close()
            
            return {
                "status": "success",
                "member": {
                    "member_id": member[0],
                    "name": member[1],
                    "expiry": member[2],
                    "member_type": member[3],
                    "status": member[4],
                    "created_at": member[5],
                    "recent_reads": [{"timestamp": r[0], "status": r[1]} for r in reads]
                }
            }
        else:
            conn.close()
            return {"status": "error", "message": "Member not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.patch("/members/{member_id}")
async def update_member_status(member_id: str, request: MemberUpdate):
    """Update member status (active, suspended, expired, etc.)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE members SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE member_id = ?',
                  (request.status, member_id))
        conn.commit()
        
        if c.rowcount == 0:
            conn.close()
            return {"status": "error", "message": "Member not found"}
        
        conn.close()
        return {
            "status": "success",
            "message": f"Member {member_id} status updated to {request.status}"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.delete("/members/{member_id}")
async def delete_member(member_id: str):
    """Delete member from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM members WHERE member_id = ?', (member_id,))
        conn.commit()
        
        if c.rowcount == 0:
            conn.close()
            return {"status": "error", "message": "Member not found"}
        
        conn.close()
        return {
            "status": "success",
            "message": f"Member {member_id} deleted"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/events")
async def receive_event(payload: dict, request: Request):
    if 'timestamp' not in payload:
        payload['timestamp'] = datetime.datetime.utcnow().isoformat()
    await manager.broadcast({"type":"verification_event","payload":payload})
    return {"status":"ok"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            # echo back for now
            await websocket.send_text(msg)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)
