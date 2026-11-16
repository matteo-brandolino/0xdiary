---
layout: post
title: "First Roll of Step Two: The CSRF Token That Guarded the Wrong Thing"
date: 2026-11-16
categories: [web-security, walkthrough]
tags: [portswigger, bscp, csrf, crlf-injection, response-header-injection, account-takeover, mystery-lab, burp-suite]
excerpt: "First time spinning my Mystery Pool through the escalation step: the change-email form screamed CSRF, the token actually held, and the scanner kept pointing at the search bar instead — which turned out to be the other half of the same attack."
lang: en
page_id: csrf-token-tied-to-non-session-cookie
permalink: /posts/csrf-token-tied-to-non-session-cookie/
---

The scanner was pointing at the wrong place and it took me a minute to admit it wasn't. I'd logged in, seen the change-email form, filed it as CSRF before I'd touched anything — the reflex you want in the exam — and then the scan came back with its one red flag planted not on the form but on the *search bar*: HTTP response header injection. For a moment that felt like a detour, a second unrelated bug to triage later. It wasn't. The search bar was the reason the CSRF was exploitable at all. The token on the form was real and it held; the way in was to stop attacking the token and start attacking the thing it was tied to.

This was the first time I'd pointed my own [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) tool at the **second** BSCP step — privilege escalation — rather than the foothold cluster I'd been grinding. Different phase, different mindset: step one is "run something in a browser," step two is "become the admin or steal their data." The wheel opened the account with it.

## The setup

Since the last time I wrote about the tool, it had grown enough that pointing it at step two was actually pleasant. The recent commits, for the record:

- topics are now **grouped by exam phase** — Foothold, Escalation, Exfiltration — each its own card with a select-all toggle, so "roll me step two" is three clicks, not twenty checkboxes;
- the roll logic moved into a **DOM-free module with tests** (`assets/roll.js`), so the random pick is unit-tested instead of tangled in the page;
- I added **direct topics** the Mystery Lab doesn't cover — OS command injection, Clickjacking, WebSockets, GraphQL, API testing, race conditions, NoSQL, Web LLM, cache deception, and prototype pollution split into client-side and server-side — generated straight from the all-labs page. The Mystery Lab endpoint answers *"no labs"* for those, so the tool picks one itself and opens it the direct way;
- server-side prototype pollution sits in Escalation next to the client-side topic, and its one RCE lab became a topic of its own over in Exfiltration.

I ticked the Escalation card and rolled. One small honest detail from the screen: **Access control was greyed out**. In the Mystery Lab widget that category only exists at Apprentice level, and I had the filter on Practitioner, so the tool correctly refused to pretend it had a lab to give me. Good — I'd rather see a dead option disabled than roll into a "no labs match your request" wall.

Tooling for the session: Burp, the scanner pointed at individual inputs rather than a broad crawl, Repeater for everything else.

## The session

### 1. The obvious candidate that wasn't the point

Log in as `wiener:peter`, and the first thing on the account page is a button to update the email. In step two, a form that changes account state is a CSRF candidate before you've read a single byte — so that's where my head went.

Then I intercepted the submit, and the obvious reading fell apart:

```http
POST /my-account/change-email HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU; session=g9NrFqqwnOp8oV2DneR2u8OweUSaHnVL; LastSearchTerm=test
...
email=test1%40gmail.com&csrf=WnX9ZKcGmOFmd2p8y4lhW8YtB1fmejT6
```

There's a `csrf` token in the body, and it's not decorative — drop it or mangle it and the server rejects the request. The naive CSRF ("just omit the token and see if it passes") dies here. The form *has* a defence and the defence *works*. If this were the whole story, the lab would be unexploitable, which is a strong hint it isn't the whole story.

### 2. The scanner points at the search bar instead

I ran the scanner and it put its one high-severity finding somewhere I wasn't looking: **HTTP response header injection** on the search parameter. The probe in the request made the mechanism plain:

```http
GET /?search=00eei%0d%0a3hpxk HTTP/2
```

`00eei` and `3hpxk` are just the scanner's random markers bracketing the injection point. The payload between them is `%0d%0a` — a **CRLF**. The scanner was telling me those two bytes came back *raw* in a response header, splitting it. My first instinct was to file it as a separate bug for later. That instinct was wrong, and noticing why is the whole lab.

Look back at the cookies on the change-email request: `LastSearchTerm=test`. **The search bar writes a cookie.** The thing the scanner flagged — raw CRLF reflected into a `Set-Cookie` header — is a primitive for writing *arbitrary* cookies into the victim's browser. Hold that thought.

### 3. The click: the token is tied to a cookie, not the session

Back to the token. For a CSRF token to be worth anything, it has to be anchored to something the attacker can't control — normally **the session**. The server remembers "session `g9Nr...` has token `WnX9...`" and checks the two together. The attacker knows neither, so they can't forge a valid pair.

This token isn't tied to the session. It's tied to that **second cookie**, `csrfKey`. The validation rule is just:

> the `csrf` in the body must pair with the `csrfKey` in the cookie.

The session never enters the check. You confirm it in ten seconds, and this is the identification step that matters under exam pressure: take one account's `csrfKey` + `csrf` pair and replay the change-email on a *different* session — it still succeeds. Or strip the `session` cookie entirely and leave `csrfKey` + `csrf`: the CSRF check still passes. The token knows nothing about who you are; it only knows about `csrfKey`.

That's the moment it clicked, and it reframes the whole attack. The point of a CSRF token is that the attacker can't obtain a valid pair *for the victim*. But I have my own account, so I have my **own** valid pair — `csrfKey=ItjP...` / `csrf=WnX9...`. I don't need to guess the victim's token. I need to make the victim **use my pair**. And half of my pair lives in a cookie — a cookie I just learned I can write, via the search bar.

Two missing defences, each harmless-looking alone, lethal together: the token anchored to a writable cookie, and a cookie writable from the outside.

### 4. The primitive: CRLF in the search to plant my `csrfKey`

Keep the two layers separate, because they fail independently.

**HTTP layer.** The search function takes `?search=...` and echoes it into a response header that remembers your last search:

```http
Set-Cookie: LastSearchTerm=test
```

An HTTP header ends with `\r\n`. The app writes my value into that header without stripping control characters, so if I send a `\r\n` (`%0d%0a`) the browser treats the line as finished and reads whatever follows as a *new header of my own*:

```http
GET /?search=test%0d%0aSet-Cookie:%20csrfKey%3dItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU%3b%20SameSite%3dNone HTTP/2
```

which produces:

```http
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU; SameSite=None   ← injected
```

The browser honours both `Set-Cookie` lines, so `csrfKey` in the victim's browser becomes *my* value. The `SameSite=None` matters: that cookie has to ride along on a cross-site POST later, and without `None` the browser wouldn't attach it.

**Logic layer.** Why can I make the victim visit that URL at all? Because **the search has no CSRF protection of its own** — it's a plain GET with no token, so I can trigger it from the victim's browser with a bare `<img src="...">`. If search had wanted a token too, I couldn't force it and the chain would die right here. One defence (the token) makes `csrfKey` the weak link; the other hole (search, unprotected and CRLF-injectable) is how I reach that link.

### 5. The ordering: the image is the sequencer

Now I have two actions to make the victim perform, in a strict order:

1. GET the search → plant `csrfKey=ItjP...` (mine).
2. POST change-email with `csrf=WnX9...` → pairs with the key just planted → executed.

Reverse them and the POST fires while the victim still holds *their own* old `csrfKey`, my token doesn't pair, rejected. So the exploit server has to guarantee "cookie first, form second." The payload that does it:

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@YOUR-EXPLOIT-SERVER.exploit-server.net" />
      <input type="hidden" name="csrf" value="WnX9ZKcGmOFmd2p8y4lhW8YtB1fmejT6" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU%3b%20SameSite=None"
         onerror="document.forms[0].submit()">
  </body>
</html>
```

The `<img>` fires the search GET. The response is HTML, not an image, so the load **fails** — and a failed load is exactly the point at which the `Set-Cookie` has already been received by the browser. `onerror` runs *then*, and only then calls `document.forms[0].submit()`. The image isn't decoration, it's the **sequencer**: it turns "I hope the GET lands first" into "the POST cannot fire until the GET has returned."

The `history.pushState('', '', '/')` on top rewrites the exploit server's URL so the POST's `Referer` looks clean — free insurance if the server also checks Referer, harmless if it doesn't.

Deliver to the victim, the email flips to mine, and from a changed email a password reset is the usual next step. Account takeover.

## The pattern

Name the pattern, not the instance: **a CSRF token is only as strong as the thing it's anchored to.** The token itself was fine — unpredictable, validated, impossible to guess. It was tied to the wrong anchor. Anchoring it to `csrfKey` instead of the session means the defence rests on "the attacker can't set this cookie," and the moment a *different* endpoint lets an attacker set cookies in the victim's browser, the token defends nothing. You don't break the token. You replace the anchor and bring your own matching token.

The second, more general lesson is the one I nearly fumbled: **the scanner names symptoms on isolated inputs; chaining is on you.** It flagged "header injection on search" and "a CSRF-looking form" as two findings, on two pages, in two different severities. They're one attack. The header injection is useless on its own (who cares that I can set my own cookies in my own browser) and the CSRF token is unbreakable on its own. The exploit exists only in the seam between them, and nothing in the issues list draws that line for you.

Keep the HTTP and the logic layers separate while you reason, because they fail for different reasons: CRLF is an HTTP-parsing failure (control bytes written into a header), the token weakness is an application-logic failure (wrong anchor), and the delivery works because of a browser behaviour (cookies auto-attached, `SameSite` permitting). Three layers, three independent mistakes, one chain.

## Exam and field

**In the exam**, this is squarely Stage 2 — privilege escalation via account takeover. The spot-it-fast tells are concrete: a hidden `csrf` field *plus a separate `csrfKey` cookie* is the giveaway — two cookies where one does identity and the other anchors the token. Confirm in seconds by replaying the token pair under a different session; if it still validates, the token isn't session-bound and you're hunting for a cookie-set primitive. That primitive is usually CRLF/response-header injection somewhere boring — a search box, a language selector, anything that echoes input into `Set-Cookie`. Interaction profile: the victim only has to *open* your exploit-server page; no click, no typing. The rabbit holes that cost minutes here: treating the search-bar header injection as a separate bug to come back to (it's the key to the lab), and getting the exploit **ordering** wrong — fire the form before the cookie lands and it silently fails with a valid-looking payload.

**In the field**, the shape recurs well beyond this lab: any token, nonce, or anti-CSRF value is only as trustworthy as its binding. Bind it to the session and server-side state; never to a cookie the client — or a bug — can overwrite. And the enabling bug, CRLF into a response header, is the quiet one: on its own it's a low-severity curiosity, but it's a cookie-injection and cache-poisoning primitive that upgrades the severity of whatever it's chained to. Strip `\r\n` from anything that reaches a header, and the chain loses its first link.

## What comes next

This was roll one of step two, and it already drew the map for the rest of the phase: escalation is mostly *account takeover by some other road* — CSRF here, but next to it in the pool sit password reset flaws, JWT, OAuth, and prototype pollution, all pointing at the same prize from different angles. The open thread is the step-two mindset itself: in the foothold step I was happy to land an `alert(1)`; here the win condition is someone else's account, and every lab is a different answer to "how do I become you." The wheel's still spinning.

## Takeaways

- A CSRF token is only as strong as its anchor: tied to a cookie instead of the session, it defends nothing once a cookie-set primitive exists — you don't break the token, you replace the anchor and bring your own matching pair.
- Confirm the weakness in seconds: replay one account's `csrfKey` + `csrf` under a different session; if the change still goes through, the token isn't session-bound.
- CRLF injection (`%0d%0a`) into a reflected `Set-Cookie` header is a cookie-writing primitive — low severity alone, lethal as the first link of a chain.
- Order matters in multi-step exploits: use `<img ... onerror="form.submit()">` so the cookie is planted *before* the form fires; reversed, it fails silently.
- The scanner flags symptoms on isolated inputs; the chain is yours to see. "Header injection on search" and "a CSRF form" were one attack filed as two findings.

## Useful references

- [PortSwigger Web Security Academy: CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger: CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
- [OWASP: CRLF injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger: SameSite cookies](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — the tool this roll came from]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
