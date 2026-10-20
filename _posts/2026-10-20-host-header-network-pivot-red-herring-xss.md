---
layout: post
title: "A Header That Dials Home, and an XSS I Was Chasing by Mistake"
date: 2026-10-20
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, host-header, ssrf, dom-based, xss, postmessage, burp-suite, intruder]
excerpt: "I found two real, reproducible bugs in the same comment form. Only one of them was the lab's actual vulnerability, and I lost twenty minutes to the other one because I'd switched off the one tool that would have told me so."
lang: en
page_id: host-header-network-pivot-red-herring-xss
permalink: /posts/host-header-network-pivot-red-herring-xss/
---

A 504 Gateway Timeout that says "connecting to localhost" is not an error. It's the server telling you, by accident, exactly what it does with an header you control. I believed it immediately. Twenty minutes later, in a completely different lab, I had a real XSS payload sitting unescaped in the DOM, refusing to fire — and I spent most of that time convinced the payload was wrong, when the actual bug was somewhere I wasn't even looking.

Both labs came out of [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}), pool set to four topics this time: web cache deception, cross-site scripting, DOM-based vulnerabilities, host header attacks. PortSwigger picked one lab per roll, same as always. I just got to narrow which four buckets it could come from.

## Setup

Lab one had a login page and nothing else worth clicking, so the scan ran against a plain `GET /`. Lab two was a "Mystery challenge" — no visible hint of the topic at all, just a blog with comments, and DOM Invader to find out what was actually listening.

## Lab one: a header that turned out to be a network address

### 1. Scanning the login, finding a request to a different host entirely

The scan on `GET /` came back with a finding I hadn't asked for on a different request: **External service interaction (HTTP)**, severity High, confidence Certain, on `POST /login`. The scanner had replaced the `Host` header on a login replay with a Burp Collaborator address, and the server had gone and made an outbound HTTP request to it. Confirmed, not inferred — Collaborator doesn't report a maybe.

That single finding says more than it looks like at first read: the application — or something in front of it — takes the `Host` header and uses it to open a real network connection, not just to read a string back in a template.

### 2. Testing the theory on purpose: `Host: localhost`

Scanner findings earn a manual check before they earn a sentence in a post. I sent `GET /my-account` with `Host: localhost` and got:

```
HTTP/2 504 Gateway Timeout
Content-Length: 149

<html><head><title>Server Error: Gateway Timeout</title></head><body><h1>Server Error: Gateway Timeout (3) connecting to localhost</h1></body></html>
```

That error message is doing the scanner's job for free. It doesn't say "invalid host" or "bad request" — it says *connecting to localhost*, present tense, as if dialing a phone number I handed it. The front-end isn't validating the `Host` header against a list of known names. It's using it to pick a destination and then trying to reach it. `localhost` from inside their infrastructure just happens to have nothing listening on the expected port, so it hangs until it gives up.

### 3. Localhost is a dead end. The internal network isn't.

`Host: localhost` proved the mechanism and solved nothing — there's no admin panel running on the proxy's own loopback. But if the header is read as "which machine do I dial," the obvious next move isn't a single guess, it's a sweep. I put the request in Intruder, set the payload position on the last octet, and ran `192.168.0.$0$` from 0 to 255.

One result broke the pattern:

```
GET / HTTP/2
Host: 192.168.0.74
```

```
HTTP/2 302 Found
Location: /admin
```

Every other address in the range either timed out or came back as the public site. `.74` redirected straight to `/admin` — something on that internal address treats the request as already authorized, which the public-facing version of the same app clearly doesn't.

### 4. Following the redirect, then closing the lab

`GET /admin` with `Host: 192.168.0.74` loaded the real panel: a user list, a delete action per row, and a CSRF token sitting in the form on that same page. I grabbed it from there — not from the login page, not reused from an earlier request, straight off the page I was about to submit against, because a stale token from a different context is exactly the kind of thing that fails silently and wastes the next ten minutes.

```
POST /admin/delete HTTP/2
Host: 192.168.0.74
Cookie: session=...

csrf=68J2lfcefhrO1CB1zGZnYkFbbwFWcafO&username=carlos
```

`carlos` gone, lab solved. The entire attack never touched a single line of application logic — it was a header value, pointed first at a diagnostic dead end, then at the right internal address.

## Lab two: an XSS that worked, and still wasn't the bug

### 1. A comment form that puts "website" into an `href`

No scanner needed for this one — Elements panel was enough. Every comment author name is a link, and the link's `href` comes straight from the "website" field of the comment form:

```html
<a id="author" href="https://foo.com">matteo</a>
```

### 2. Two layers of validation, and only one that actually matters

A bare `"><b>test</b>` never reached the page the way I expected — there's client-side validation on the field (it wants something URL-shaped before it'll even submit), and sending the raw request through Repeater showed the server checks the same thing independently. Neither layer is a style preference; the second one is the one that counts, since the client-side check only has to be true at the moment the browser decides to submit, not at the moment the server decides to store.

### 3. A payload that starts right and ends wrong, on purpose

The server-side check turned out to only care about the start of the value. I sent, via Repeater:

```
https://foo" onmouseover=alert(1)
```

and the comment came back with this in the DOM:

```html
<a id="author" href="https://foo.com" onmouseover="alert(1)">matteo</a>
```

Unescaped double quote, closed `href`, a brand-new attribute sitting right next to it. The format check passed because the value starts with `https://`; nothing downstream re-checked or re-encoded what came after. A real, working attribute-injection XSS, confirmed in the DOM.

### 4. Hovering, nothing happening, and twenty minutes of looking at the wrong thing

I moved the mouse over the link. No alert. My first read was that the payload itself was broken — maybe the encoding was different from what the DOM inspector showed, maybe the browser was somehow treating the quote as literal text after all. I tested that hypothesis directly, typing `&quot;` by hand into the website field instead of a literal `"`, which predictably just produced a comment with `&quot;` as inert text in the `href` value — a dead end that at least ruled out one theory, but didn't explain the original failure, because it was never testing the original failure. I was debugging a payload that had already proven itself correct in the DOM, convinced the fix had to be in that same spot.

### 5. The actual cause was a tool I'd turned off

DOM Invader had been switched off since the start of the session. Once I turned it back on and reloaded the page, it flagged something I hadn't looked at once: a `message` listener, nowhere near the comment form, doing this:

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
});
```

The `onmouseover` XSS was real. It was also never the lab's intended path — the actual sink had been sitting in a different file the whole time, and the only reason I hadn't seen it is that the tool built to surface exactly this kind of listener was off, and I'd filled the resulting silence with a theory about my own payload instead of going looking for what DOM Invader would have handed me directly.

### 6. A check that confirms presence, not shape

`url.indexOf('http:') > -1` answers one question: does this substring appear anywhere in the string. It says nothing about where, or what surrounds it, or whether the rest of the value is safe to hand to `location.href`. A scheme and a comment marker both fit inside those constraints:

```
javascript:print()//http:
```

`indexOf('http:')` finds it, at the end, inside what JavaScript reads as a comment once the expression starts executing. The check passes. `location.href` gets a string that starts with `javascript:`, which the browser doesn't navigate to — it executes.

### 7. Delivery

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:', '*')"></iframe>
```

`onload`, because the listener only exists once the page has loaded. `'*'` as target origin, because the receiver — correctly, for this lab's purposes — never checks who sent the message either. Store, deliver, `print()` fires, lab solved. The href injection stayed exactly where it was: real, reproducible, and not the thing that was ever being graded.

## What the two labs have in common

Neither bug lived in a place that was hard to reach — the `Host` header and the `website` field were both right there, both trivially editable, both reflected back almost immediately. What took time in both labs was figuring out what the receiving side actually trusted, versus what it only appeared to check.

The `Host` header looked like metadata and turned out to be a literal network destination — the 504 said so outright, I just had to believe the error message instead of assuming it was noise. The `indexOf('http:')` check looked like URL validation and turned out to be a presence check with no opinion on structure. And the XSS in between those two moments was a reminder that finding *a* working exploit on the page isn't the same as finding *the* bug the lab wants solved — the href injection fired exactly as designed and still had nothing to do with the actual objective, a mistake that cost real time only because the tool that would have shown the real sink immediately was sitting there, switched off.

## Exam and field

**Lab one — Host header network pivot to internal admin access**

| | Exam | Field |
|---|---|---|
| What to recognise | an unexplained outbound request on a scanned endpoint, or a 504/500 whose message names a destination you just supplied | shared hosting, reverse-proxy routing by name, internal admin panels reachable only from "trusted" internal IP ranges |
| Where the time goes | the Intruder sweep across an internal range once `localhost` proves the mechanism but doesn't open anything | finding which internal ranges exist at all; the lab hands you `192.168.0.0/24`, real networks don't |
| Common trap | stopping at the Collaborator finding and not manually testing `Host: localhost`, missing the error message that explains the whole mechanism | assuming a network-level trust boundary (internal IP = trusted) is equivalent to an identity check; it isn't, and SSRF is exactly the gap between the two |
| Real limit | one scripted deletion, fixed internal IP | depends entirely on what's reachable from the vulnerable server — cloud metadata endpoints, internal APIs, other tenants, all through the same single header |

Defence: validate the `Host` header against an explicit allow-list before using it for routing, and never let application-layer access control depend on which network segment a request appears to originate from.

**Lab two — DOM-based open redirect turned XSS via postMessage**

| | Exam | Field |
|---|---|---|
| What to recognise | a `message` listener assigning `e.data` (or a substring-checked version of it) to `location.href` or `window.location` | "open redirect" endpoints and redirect allow-lists implemented as a substring or regex check instead of actual URL parsing |
| Where the time goes | not chasing a working-but-irrelevant XSS found elsewhere on the same page, and running DOM Invader before trusting your own read of the page | the `javascript:` bypass itself is trivial once the sink is found; the actual work is noticing the listener exists at all on a page with no visible trigger for it |
| Common trap | mistaking a real, reproducible bug for the lab's objective just because it fires reliably | trusting `indexOf`/`includes`-style checks on redirect targets because they "look" like validation in a code review |
| Real limit | needs a victim to load a page you control, same as any postMessage-based attack | if the app also checks `e.origin`, or parses the value with the `URL()` constructor instead of a substring match, this exact bypass closes |

Defence: never validate a URL by checking whether a substring appears in it — parse it with `new URL()` and check the actual `protocol` and `host` fields, and always check `e.origin` before trusting message content at all.

## What comes next

The `Host` header pivot worked because the internal range was small and the lab handed me its boundaries implicitly — `192.168.0.0/24` is the kind of thing you brute-force in minutes. A real internal network doesn't come with that gift. The open question I'm carrying into the next session isn't about the payload, it's about reconnaissance: how much of a target's internal topology can actually be mapped through an SSRF-capable header before the sweep itself becomes the bottleneck, and what a defender's rate limiting would need to look like to make that sweep expensive instead of free.

## Takeaways

- An error message that names a destination ("connecting to X") is telling you how a value is actually used, not just how it's displayed — read it literally before assuming it's noise.
- `indexOf()` / `includes()` on a URL-like value checks presence, not shape. It will not tell you whether the string *is* a safe URL, only whether a safe-looking substring happens to appear somewhere in it.
- A working exploit is not proof you found the lab's intended bug. Confirm it against the stated objective before building the rest of your time around it.
- Don't debug a payload that already proved itself correct in the DOM. If it's not firing, the failure is more likely downstream (a tool switched off, a different sink entirely) than in the string you already verified.
- Grab tokens (CSRF or otherwise) fresh from the page you're about to submit against — a token reused from a different context is a silent failure waiting to eat your next ten minutes.

## Useful references

- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [PortSwigger Web Security Academy: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: URL()](https://developer.mozilla.org/docs/Web/API/URL/URL)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
