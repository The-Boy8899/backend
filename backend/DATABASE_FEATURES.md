# Community ID - Database Features

## New Functionality

### Database Management
- **SQLite Database** (`community_id.db`) automatically created on startup
- **Members Table**: Stores all member information with status tracking
- **Card Reads Table**: Logs every card scan for audit purposes

### API Endpoints

#### Write Card (POST `/nfc/encode`)
- Encodes member data to NFC card
- **Automatically saves member to database**
- Request: `{ member_id, name, expiry }`
- Returns: Success/error status

#### Read Card (POST `/nfc/decode`)
- Reads and decrypts card data
- **Cross-checks against database**
- **Verifies member status**
- Logs card read event
- Returns: Verification result with card status vs database status

#### Members Management

**Get All Members** (GET `/members`)
- Lists all members in database
- Shows: member_id, name, expiry, status, created_at

**Get Single Member** (GET `/members/{member_id}`)
- Detailed member information
- Shows recent card read history (last 10 reads)

**Update Member Status** (PATCH `/members/{member_id}`)
- Change member status: `active`, `suspended`, `expired`, `inactive`
- Request: `{ status: "new_status" }`

**Delete Member** (DELETE `/members/{member_id}`)
- Permanently removes member from database

### Frontend Features

#### Members Database Tab
- **View All Members**: Browse all registered members in a table
- **Member Details**: Click any member to view full details
- **Status Management**: Update member status (active/suspended/expired/inactive)
- **Delete Members**: Remove members from the system
- **Refresh**: Reload member list from database

#### Enhanced Card Reading
- **Verification**: Card data is cross-checked against database
- **Status Display**: Shows both card expiry status and database member status
- **Verification Badge**: Clear indication if card is verified or unverified
- **Card History**: Each card read is logged for audit trail

### Security Notes

**Current Implementation:**
- AES-GCM encryption for card data (as before)
- Database stores member information separately
- Card reads are logged with timestamps for audit

**Recommended Security Improvements:**
1. Add API key authentication for all endpoints
2. Implement HTTPS for production
3. Add password hashing for admin access
4. Enable database encryption at rest
5. Implement rate limiting on API endpoints
6. Add user roles (admin, reader, encoder)
7. Log all status changes with user attribution

## Database Schema

### Members Table
```sql
CREATE TABLE members (
    id INTEGER PRIMARY KEY,
    member_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    expiry TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
```

### Card Reads Table
```sql
CREATE TABLE card_reads (
    id INTEGER PRIMARY KEY,
    member_id TEXT NOT NULL,
    timestamp TIMESTAMP,
    status TEXT,
    FOREIGN KEY(member_id) REFERENCES members(member_id)
)
```

## Usage Flow

1. **Create Member**: Use "Write Card" tab
   - Fill in member details (ID, name, expiry)
   - Tap card to device
   - Member is automatically saved to database

2. **Verify Member**: Use "Read Card" tab
   - Tap card to device
   - System verifies card data against database
   - Shows card status and member database status

3. **Manage Members**: Use "Members Database" tab
   - View all members
   - Update member status (e.g., suspend a member)
   - Delete member from system

## Example Scenarios

### Scenario 1: Member Card Read
1. User taps member card on reader
2. Card data is decrypted
3. System checks database for member_id
4. Verifies expiry date
5. Shows: "Card Verified - Member Active (active)"

### Scenario 2: Unregistered Card
1. User taps card on reader
2. Card data is decrypted
3. System checks database - member not found
4. Shows: "Card Unverified - Not found in database"

### Scenario 3: Expired Member
1. User taps card on reader
2. Card data is decrypted
3. System checks database - member exists
4. Checks expiry date - card is expired
5. Shows: "Card Verified - Member Expired (expired)"
6. Admin can still change database status if needed

### Scenario 4: Suspended Member
1. Admin updates member status to "suspended" via Members tab
2. When card is read, shows database status as "suspended"
3. Reader application can act on this status
