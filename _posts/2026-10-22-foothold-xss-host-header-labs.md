---
layout: post
title: "Four Labs, One Question: What Is This Input Allowed to Become?"
date: 2026-10-22
categories: [web-security, walkthrough]
tags: [portswigger, dom-xss, reflected-xss, host-header, password-reset-poisoning, document-write, param-miner, burp-suite]
excerpt: "Param Miner ran for eleven minutes, sent 1,232 requests, and came back with zero findings on a header that was genuinely poisonable — because the only place it broke anything was an email the tool never looked at."
lang: en
page_id: foothold-xss-host-header-labs
permalink: /posts/foothold-xss-host-header-labs/
---

`Completed request with key ... 1 of 1 in 681 seconds with 1232 requests, 0 candidates and 0 findings`. Eleven minutes, over a thousand requests, and Param Miner's verdict was: nothing here. I'd have believed it, except I already knew the header worked — I just hadn't looked in the one place where it actually mattered. That gap between "the tool found nothing" and "the bug is real" is the thread running through all four labs in this session.

## Setup

Four PortSwigger labs, rolled back to back, all sitting under the same umbrella: getting a foothold as a user, the step before you're inside anything privileged. I went in loosely aiming at DOM XSS, auth, host header attacks, and cache poisoning, and let each lab tell me on arrival which of those actually applied — no login form meant no auth angle, no `Cache-Control` on the landing page meant no cache poisoning. What was left, lab by lab, turned out to be more interesting than the category labels suggested.

## The session

### 1. A postMessage listener that trusts everything it receives

DOM Invader flagged this one immediately: a `message` listener with no check on `e.origin`, parsing whatever JSON arrived and switching on a `type` field. One case, `load-channel`, took a `url` straight from the message and assigned it to an iframe's `src` — no validation on the scheme at all.

```js
case "load-channel":
    ACMEplayer.element.src = d.url;
    break;
```

Delivered via the exploit server:

```html
<iframe src="https://TARGET-LAB/" onload="this.contentWindow.postMessage(JSON.stringify({type: 'load-channel', url: 'javascript:alert(document.domain)'}), '*')"></iframe>
```

I've already walked through this exact pattern — untrusted postMessage data landing in a sink that doesn't care what scheme it's handed — in a [previous post]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %}), so I'm not re-running the full session here. Same bug, same fix (check `e.origin`, validate the URL scheme before it touches `src`), lab solved in a couple of minutes this time around because I already knew what I was looking for.

### 2. The scanner finds it, but the string-escaping logic is the actual lesson

A search box, scanned with Burp Scanner, came back with a reflected XSS finding. The reflected context was telling:

```js
var searchTerms = 'zzz\'<>';
```

That `\'` matters more than the `<>`. The server is HTML-encoding or passing through the angle brackets, but it's actively escaping the single quote — replacing `'` with `\'` wherever it finds one in the input. The mistake is what it's *not* escaping: the backslash character itself.

The payload that actually solved it, decoded from the request that worked:

```
zzz'<>40186\';alert(1)//500
```

Walking through what the server does to this: it scans the input for `'` characters and prepends a `\` to each one it finds. My input already contains one `\` right before a `'`. The server doesn't recognize that backslash as anything special — it only reacts to quotes — so it adds its own escape in front of the quote I sent, giving:

```
zzz'<>40186\\';alert(1)//500
```

Dropped into the template (`var searchTerms = '...';`), the JS parser reads `\\` as a single escaped backslash (consuming both characters as one unit), which means the `'` immediately after is no longer "protected" by anything — it closes the string for real. Everything after that is parsed as live JavaScript: `;alert(1)` runs the popup, and `//` comments out whatever the template's own closing `';` would otherwise have contributed, so there's no leftover syntax to trip over.

The part worth sitting with: quote-escaping alone is not quote-*validation*. If the escape character itself isn't on the blocklist, an attacker who sends their own copy of it gets to choose which quote in the final string is "real."

### 3. A CSRF finding that wasn't the bug, and a scanner that couldn't see the real one

This lab had a `forgot-password` flow and the word "middleware" in its name — worth taking literally. A scan of the endpoint surfaced an informational CSRF finding (unauthenticated endpoint, cookie-only session identification, textbook). Interesting, but severity "Information" for a reason: it wasn't the actual vulnerability, just a side effect of the endpoint not requiring auth in the first place.

The real angle was which header the backend trusts when it builds the absolute URL for the reset link. In an architecture with a reverse proxy in front of the app, the proxy often preserves the client's original host in `X-Forwarded-Host` while rewriting `Host` itself for its own internal routing — so the backend, if it's building a link for an email, may trust `X-Forwarded-Host` specifically because it assumes the proxy already validated it. It didn't; it just forwarded it.

I pointed Param Miner's "Guess headers" at the request to find exactly which header the backend reads, and got the result that opened this post: `0 candidates and 0 findings`, after 1,232 requests over eleven minutes. Here's why that's not actually a contradiction: Param Miner works by diffing the HTTP *response* against a baseline. If a header changes something inside the response, it shows up as a candidate. But the effect of a poisoned `X-Forwarded-Host` here isn't in the response to the `forgot-password` request at all — the confirmation page looks identical no matter what you send. The effect lands in the password reset *email*, a channel the tool never touches. Zero observable difference in the response means zero findings, whether or not the bug is sitting right there.

Checking the lab's email client directly settled it: sending the request for `carlos` with `X-Forwarded-Host` pointed at the exploit server put my domain straight into his reset link. Captured his token from the exploit server's access log, took the structure of a legitimate `reset-password` request (the one generated for my own `wiener` account, so I knew the exact shape), swapped in Carlos's stolen token, and reset his password. Account takeover, no password guessing, no XSS — just a header the backend trusted more than it should have.

### 4. Same sink, completely different escaping rules than lab 2

An e-commerce page with a "check stock" feature per product — plausible SSRF bait — but the actual bug was in the store selector next to it:

```js
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<option selected>'+store+'</option>');
```

`document.write` again, same function name as the mental model from lab 2 — but a completely different context, and that difference is the whole point. In lab 2, `store`-equivalent data landed inside a JS string literal, so the escaping that mattered was about quotes. Here, `store` lands as raw HTML content between two tags, with zero encoding applied. There's no quote to neutralize, no attribute to break out of — it's already sitting in a spot where any tag you hand it gets parsed as a tag.

```
?storeId=<script>alert(document.domain)</script>
```

This works specifically because `document.write` is called while the browser is still parsing the original document. A `<script>` injected this way lands in the live parse stream and executes like it was always part of the page source — unlike, say, assigning the same string to `innerHTML`, where an injected `<script>` tag is inert by design. Same sink function as lab 2's mental category ("HTML built with string concatenation"), same general warning sign, but the bypass has nothing in common: lab 2 needed a backslash to defeat an escape; this one needed nothing at all, because there was no escaping to defeat.

## The pattern

Four labs, four completely different mechanisms, and one question underneath all of them: *what context does this input land in, and does whatever reads it there actually enforce that context, or just assume it?* A cross-window message assumed any sender is a legitimate one. A quote-escaping routine assumed an attacker wouldn't bring their own backslash. A password-reset flow assumed a forwarded header was pre-validated because something upstream of it looked like it should have. A string concatenation into `document.write` assumed nobody would notice there was no encoding at all.

| Lab | Input lands in | What broke |
|---|---|---|
| 1 — postMessage | an `iframe.src` assignment | no origin check, no scheme validation |
| 2 — search | a JS string literal | quotes escaped, backslash wasn't |
| 3 — forgot-password | a server-built email URL | header trusted without re-validating it |
| 4 — store selector | raw HTML via `document.write` | no encoding applied at all |

The other half of the pattern is about tooling, not code: Param Miner and Burp Scanner both do their job by watching the HTTP response for a change. That's a correct and useful technique for an enormous share of bugs — and it says nothing whatsoever about a bug whose only observable effect lives somewhere the tool isn't looking, like an outbound email. "The scanner found nothing" is a statement about the channel the scanner watched, not a statement about the application.

## Exam and field

| | Exam | Field |
|---|---|---|
| What to recognise | `document.write`/string-concatenation sinks in view-source, and header names like `X-Forwarded-Host` next to anything that emails a link | the same sinks turn up in legacy product filters, store/locale selectors, and any "forgot password" flow sitting behind a reverse proxy or CDN |
| Where the time goes | reading the *exact* escaping logic from the reflected output (which character is escaped, which isn't) rather than guessing a generic payload; realizing a 0-finding automated scan doesn't mean a header-trust bug doesn't exist | confirming whether the app actually builds absolute URLs from a client-controlled header at all — most modern frameworks default to a hardcoded base URL, so this bug is less common than the lab makes it look, but devastating when present |
| Common trap | throwing a standard `'-alert(1)-'` payload at every quote-escaping filter and giving up when it doesn't fire, instead of checking what the escape routine actually targets | trusting an automated scanner's "no findings" on anything whose effect isn't reflected back in the HTTP response — emails, logs, async side effects, webhook deliveries |
| Real limit | each lab hands you a visible reflection point or a test mailbox to confirm against | the victim still has to receive and click a password reset email, or load a page that fires the postMessage — none of this is a "no interaction" attack |

Defence notes, one per lab: validate `event.origin` before trusting anything from `postMessage`, and never let message data touch a sink like `src` without checking its scheme; use context-aware encoding (a JSON-safe escape, not a quote blocklist) whenever user input lands inside a JS string literal; never build absolute URLs for emails or redirects from a client-supplied header — use a server-side configured base URL instead; and encode output the same way regardless of whether it's going into an attribute, a string, or raw HTML markup, because "it's just `document.write`" is not a security boundary.

## What comes next

Lab 3 is the one I want to push further: the exploit worked because the lab's email client made the poisoned link visible to me directly. On a real target I wouldn't have that view — I'd be working from exploit-server logs and guesswork about what the email template actually renders. That's the gap between "I can poison this header" and "I can reliably exfiltrate a token from someone who clicks a link I never see delivered," and it's not something a lab this contained really tests.

## Takeaways

- Quote-escaping is not quote-validation — if the escape character itself isn't also neutralized, an attacker can supply their own and decide which quote in the output actually closes the string.
- The same sink (`document.write`, `innerHTML`, whatever) can require a completely different bypass depending on whether your input lands inside a JS string, an HTML attribute, or raw markup — don't carry a payload from one context into another without re-checking where it actually lands.
- A header-brute-forcing tool reporting zero findings only means zero differences in the *HTTP response* — it says nothing about effects that surface elsewhere, like an email, a log line, or a downstream webhook.
- `X-Forwarded-Host` (and friends) exist for legitimate proxy use, which is exactly why backends sometimes trust them more than they trust the client-facing `Host` header — check which one actually feeds a security-relevant decision.
- An informational finding from a scanner (like a bare CSRF flag on an unauthenticated endpoint) is worth a glance and then moving on — it's not automatically the bug the lab is testing for.

## Useful references

- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [Param Miner on GitHub](https://github.com/PortSwigger/param-miner)
- [DOM XSS via web messages and a JavaScript URL]({% post_url 2026-10-12-dom-xss-web-messages-javascript-url %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
