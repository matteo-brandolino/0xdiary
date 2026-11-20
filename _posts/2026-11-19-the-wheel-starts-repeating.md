---
layout: post
title: "The Wheel Starts Repeating: Ten Step-Two Rolls, Four I'd Already Beaten"
date: 2026-11-19
categories: [web-security, walkthrough]
tags: [portswigger, bscp, sql-injection, jwt, graphql, server-side-parameter-pollution, prototype-pollution, csrf, mass-assignment, mystery-lab, burp-suite]
excerpt: "I spun my Mystery Pool ten times through step two and four of the rolls landed on labs I'd already solved — one I'd written a whole post about five days earlier. That's not a wasted session; it's the moment the drilling starts paying out in seconds instead of minutes."
lang: en
page_id: the-wheel-starts-repeating
permalink: /posts/the-wheel-starts-repeating/
---

I filed it as CSRF before I'd clicked anything — the change-email form, the reflex you want in the exam — and then I realized I wasn't recognizing a *vulnerability class*. I was recognizing a *lab*. I'd written thirteen hundred words about this exact one five days ago: the CRLF on the search bar, the `Set-Cookie: csrf=`, the double-submit defense that collapses when you can plant the cookie yourself. All of it. The wheel had come back around, and the only thing new was how fast I saw it.

That's the whole of this post. I rolled my [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) ten times through the escalation step, and four of the ten were reruns — labs I'd already solved, one of them already *published*. For a minute that felt like a failure of the tool. It isn't. Step two has a finite number of faces, and when you've drilled it enough, the wheel starts showing you the same ones — and the clock you used to spend identifying them collapses to nothing. The reruns aren't filler here. They're the measurement.

## The setup

Same tool, Escalation card ticked, Practitioner level. The pool had nine topics checked — SQL injection, CSRF, OAuth, JWT, access control, API testing, GraphQL, client-side and server-side prototype pollution — everything except insecure deserialization, which I'd left out because my tool files it under exfiltration, not escalation. That detail matters at the end.

As before, several rolls came up as **direct topics** — categories the official Mystery Lab doesn't cover, which my tool pulls straight from the all-labs page and opens by their real launch URL. The price I keep paying is that a direct lab shows its title the moment it loads, so the surprise ends early. I'd still rather roll broadly across step two than keep every title hidden.

Tooling: Burp with the scanner aimed at single insertion points (never a broad crawl), Repeater, the native GraphQL tab, the JWT Editor extension; sqlmap for the blind and UNION work; DOM Invader for prototype pollution; and — once, usefully this time — hashcat.

## The session

### Roll 1 — The gadget the response handed me (server-side prototype pollution)

A direct topic, title spoiled: *privilege escalation via server-side prototype pollution*. Node/Express, and the way in was the "update billing and delivery address" form — a `POST /my-account/change-address` carrying JSON.

The canonical detection for server-side pollution is the `json spaces` trick: pollute `Object.prototype` with `"json spaces": 10` and watch Express re-indent every JSON response. I never needed it. The change-address endpoint **echoes the order object straight back**, and sitting in that response was a field the form never sends:

```json
{ "username": "wiener", "isAdmin": false, ... }
```

The gadget was named in the reply. So I didn't detect anything clever — I just wrote to the property the server had already shown me:

```json
{
  "address_line_1": "Wiener HQ",
  "...": "...",
  "__proto__": { "isAdmin": true }
}
```

The merge binds my `__proto__` onto the prototype chain, the user object inherits `isAdmin: true`, the admin panel appears on the next load, and `carlos` is one DELETE away. **The rabbit hole here is reaching for the `json spaces` probe when the response already tells you the gadget's name.** Identification was reading, not fingerprinting. Stage 2, non-interactive.

### Roll 2 — The scan I'd already written off (UNION SQLi, randomized schema)

`GET /filter?category=...`, the obvious injectable. I pointed a SQLi-only scan configuration at the `category` insertion point and it came back with nothing, so I'd half-filed it as clean and started looking elsewhere — and *then* the scan landed the finding, a beat late. The manual confirm was the oldest tell in the book:

```
GET /filter?category=Lifestyle'      → error
GET /filter?category=Lifestyle''     → no error
```

A single quote breaks the string, doubling it repairs it. SQL injection, in-band, PostgreSQL. Unlike every cookie-SQLi I keep hitting, this time the obvious input really was the one. sqlmap closed it — but with a catch worth naming:

```bash
sqlmap -u ".../filter?category=Lifestyle" -p category \
  --dbms=postgres --technique=U --batch --hex --exclude-sysdbs \
  --tables -D public -T users_fpqvvh \
  -C username_hdrsqx,password_ieynbr --dump
```

Those names — `users_fpqvvh`, `username_hdrsqx`, `password_ieynbr` — are **randomized per instance**. You cannot guess `users`/`username`; you enumerate the schema first and *then* dump. **The rabbit hole is typing the table names you know by heart into a lab that deliberately scrambled them.** `--technique=U` forces UNION and skips the noisy time-based probes. Admin credentials out, login, done. Non-interactive.

### Roll 3 — The method nobody uses (unused API endpoint)

Direct topic, API testing. The product page quietly fetched its price through `GET /api/products/1/price`. The whole exploit is one question most people never ask of an endpoint: *what else does it answer to?*

```http
OPTIONS /api/products/1/price HTTP/2
```

```http
Allow: GET, PATCH
```

`PATCH` — a verb the UI never issues. So I issued it:

```http
PATCH /api/products/1/price HTTP/2
Content-Type: application/json

{ "price": 0 }
```

Jacket, free. **The identification step is `OPTIONS`**: the `Allow` header enumerates the methods for you, and the unused one is the whole bug. (An honest aside: my `Referer` on that request was a mess of `__proto__[...]` and `constructor[prototype]` strings — DOM Invader's prototype-pollution fuzzer firing in the background on every page, completely unrelated to this lab. The tools leave fingerprints on each other.) Non-interactive.

### Roll 4 — Same sink, the usual cookie (blind SQLi, conditional responses)

And here the reruns start. `GET /filter?category=...` with a `TrackingId` cookie — I scanned the cookie *first* this time, because the [last two sessions]({% post_url 2026-11-17-five-rolls-into-step-two %}) taught me the SQLi usually hides there, not in the parameter the page hands you. Boolean-based blind, confirmed by the `Welcome back` message appearing on a true condition and vanishing on false. sqlmap, cookie injection marked with `*`:

```bash
sqlmap -u ".../filter?category=Pets" \
  --cookie="TrackingId=L2MBBFD8DbUvt0PC*; session=..." \
  --batch --dbms=postgresql --technique=B --string="Welcome back" \
  -D public -T users -C username,password --dump
```

The only thing worth saying that I haven't said in a prior post: contrast it with roll 2. Identical SQL sink, but there the schema names were randomized and the channel was in-band UNION; here the names are the boring standard `users`/`username`/`password` and the channel is blind-in-a-cookie. **The sink doesn't pick the technique — the surrounding reality does.** I've written that sentence before. It keeps being true. Non-interactive.

### Roll 5 — The pollution that isn't pollution (server-side parameter pollution)

The roll came up and I thought *another prototype pollution* — and that reflex is exactly the trap. The lab was **server-side parameter pollution in a query string**, which shares a word with prototype pollution and nothing else.

The shape: the forgot-password form feeds your username into an *internal* API call the front-end makes on your behalf, something like `GET /api/internal/v1/users?username=administrator&field=email`. Because your input lands inside that query string unencoded, the structural characters become yours — `%26` adds a parameter, `%23` truncates everything after it. One request did the whole job:

```http
POST /forgot-password
csrf=...&username=administrator%26field=reset_token%23
```

Decoded, the internal call becomes `...?username=administrator&field=reset_token#&field=email` — my `field=reset_token` injected, the original `field=email` commented out by the `#`. The response handed back the administrator's **reset token**, and a plain `GET /forgot-password?reset_token=<token>` let me set a new password. **The rabbit hole is the name**: read the mechanism, not the word. Identification is noticing that your input triggers a server-to-server call and then poking it with a single URL-encoded `#`. Non-interactive.

### Roll 6 — The endpoint that denied it existed (hidden GraphQL)

API/GraphQL. The endpoint was hidden, so phase one was finding it; phase two was making it talk after it claimed it wouldn't. A universal probe confirms any GraphQL endpoint:

```
GET /api?query=query{__typename}
```

A valid endpoint answers `{"data":{"__typename":"query"}}`. Introspection, though, was "disabled" — by a filter so naive it only looked for the literal string `__schema{`. Two cheap bypasses stacked together beat it: a **newline** between `__schema` and its brace, and sending the whole query as a **GET** (the block was only wired up for POST):

```
GET /api?query=query IntrospectionQuery { __schema%0a { ... } }
```

`%0a` is the newline — enough to dodge the regex, invisible to the parser. The schema came back whole, and in it were two operations: one to read a user, one to delete one. I read `carlos`'s id, called the delete mutation, lab solved. **Identification is the `{__typename}` probe plus knowing the `__schema{` filter is skin-deep.** Non-interactive.

### Roll 7 — The lab I'd already published (CSRF, token tied to non-session cookie)

This is the one from the opening. Change-email form, filed as CSRF on sight — and then recognized not as a class but as a specific lab I'd [written up five days earlier]({% post_url 2026-11-16-csrf-token-tied-to-non-session-cookie %}). The token is real and it holds; the weakness is that it's validated against a `csrf` *cookie* that isn't tied to your session, and the search bar reflects into a `Set-Cookie` header via CRLF, so you set that cookie yourself.

The only new wrinkle was my own exploit. Burp Pro generated the PoC with the auto-submit `<img>` nested *inside* a `<script>` block — where it's parsed as JavaScript, not HTML, so the `onerror` never fires. I'd pasted it without reading. Unwrapped, it works:

```html
<form action="https://LAB/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.net" />
  <input type="hidden" name="csrf" value="fake" />
</form>
<img src="https://LAB/?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
     onerror="document.forms[0].submit();" />
```

The `<img>` fires the CRLF GET that plants `csrf=fake`, fails to load, and auto-submits the form whose body `csrf=fake` now matches the cookie. Here's the measurement: the first time I met this lab it took me a minute to admit the search bar *was* the attack. This time I was at the exploit server before the page finished loading. **That minute-to-seconds collapse is the only thing the exam actually rewards.** Stage 2, interactive — it needs the victim to load the exploit, delivered from the exploit server.

### Roll 8 — The discount I'd already abused (mass assignment)

Second rerun, back to back. *Exploiting a mass assignment vulnerability* — the [checkout lab]({% post_url 2026-11-17-five-rolls-into-step-two %}) where the `GET /api/checkout` response admits to a `chosen_discount` field the POST never sends. Copy it into the body, set `percentage` to 100, order placed at zero. I'd documented this one in full a week earlier, so there's nothing to add technically — except that two reruns in a row is the wheel telling you something. Non-interactive.

### Roll 9 — The tool that returned nothing, and meant it (JWT kid path traversal)

Another change-email, and I reached for CSRF again — then looked at the cookie and found a JWT. Header: `{"kid":"ea7c48d4-...","alg":"HS256"}`. `HS256` is symmetric, so there's a shared secret, so — unlike the [RS256 token that embarrassed me last week]({% post_url 2026-11-18-three-rolls-nothing-on-screen %}) — hashcat is genuinely the right tool this time. I ran it against a wordlist and it cracked **nothing**.

That null is the whole lesson. A password-cracker pointed at a correct HS256 token that still finds no secret isn't a failure; it's a **signpost** — the key is strong, so the door isn't the key. It's the `kid`. That header names the file the server loads as the verification key, and it's vulnerable to path traversal. Point it at an empty file and you know the key: nothing.

In JWT Editor: a new symmetric key with an **empty `k`**, the header's `kid` set to `../../../../../../../dev/null`, the payload's `sub` set to `administrator`, then Sign. The server reads `/dev/null` (empty) as the key, my signature over an empty key matches, and the token is admin. **The rabbit hole is brute-forcing a strong secret forever instead of reading what `kid` points at.** Non-interactive.

### Roll 10 — One button (client-side prototype pollution)

Last roll, client-side prototype pollution — and the fourth rerun, the DOM XSS lab from [two sessions ago]({% post_url 2026-11-17-five-rolls-into-step-two %}). DOM Invader flagged the source (`__proto__[property]=value in search`) on load; "Scan for gadgets" found the sink (`script.src` reached through the `transport_url` gadget); and its **Exploit** button solved the lab in a single click. Congratulations banner, no typing.

Which is the uncomfortable coda to the whole session: I didn't exploit this, the extension did. The source → gadget → sink chain — `?__proto__[transport_url]=data:,alert(1)` poisoning a property the page reads into a script `src` — I understand it only because I [walked it by hand once]({% post_url 2026-11-17-five-rolls-into-step-two %}). On a fresh exam gadget the tool doesn't list, the button is gone and the understanding is all that's left. Stage 2, interactive (DOM XSS).

## The pattern

Four of ten rolls were labs I'd already beaten, one already published. Strip the reruns and six genuinely new techniques remain — server-side prototype pollution, a UNION SQLi against a randomized schema, method tampering on an unused endpoint, server-side parameter pollution, a hidden GraphQL endpoint, and JWT `kid` traversal. But the reruns are the finding, not the waste. **Step two has a bounded vocabulary, and I've drilled enough of it that the wheel now repeats — and every repeat resolved in seconds.** That's the shape of a step you've nearly finished: not fewer rolls, but faster ones, and a rising share you've seen before.

Two deeper threads ran under it.

**A tool returning nothing is information.** hashcat's `null` on roll 9 wasn't a dead end — it was the proof that the weakness lived in the `kid`, not the secret. The same logic ran through roll 2's scan landing a beat after I'd written it off, and roll 6's endpoint denying it existed. Absence is a reading, if you let it be one.

**Once you know the shape, the tooling collapses the exploit.** sqlmap dumps the table, DOM Invader's button solves the XSS, JWT Editor forges the token. On a drilled step two the hard part is no longer *how do I exploit this* — it's *which insertion point* (the cookie, not the parameter) and *which of two near-identical labs am I in* (the `redirect_uri` error, the randomized schema, the `kid` vs the secret). The skill migrated from exploitation to identification, which is exactly where the exam puts the clock.

And the oldest thread, still unbroken across every post in this series: **the server keeps leaking the thing you need.** `isAdmin` in a response body, `chosen_discount` in a GET, a `reset_token` field, an introspected type, a `kid` naming a file. Identification is reading what the server volunteers before you throw a single payload.

## Exam and field

**In the exam**, all ten are Stage 2 — privilege escalation, each a different road to someone else's account. Most are **non-interactive**, which is the profile you want under the clock: the server-side prototype pollution, both SQLis, the API method tampering, the parameter pollution, the hidden GraphQL, the JWT forgery — you query the server yourself and never wait on a victim. Only two need interaction: the CSRF (deliver the PoC from the exploit server and wait for the victim to load it) and a weaponized client-side prototype-pollution XSS. The recognition tells are the whole game and worth over-rehearsing: scan **cookies** for SQLi, not just parameters; read an endpoint's `OPTIONS`/`Allow` before assuming its verbs; test a server-to-server input with a single `%23`; probe GraphQL with `{__typename}` and treat the `__schema{` block as skin-deep; and when hashcat finds nothing on a valid HS256, stop cracking and read the `kid`.

**In the field**, the ranking is by blast radius. The two SQLis exfiltrate the whole user table. The JWT `kid` traversal is total auth bypass — you mint any identity you like. Server-side prototype pollution is the quiet structural one: today it was `isAdmin`, but the same unsafe merge escalates to RCE in the wrong Node app. Mass assignment and parameter pollution are business-logic holes that scale to whatever field the object or the internal API happens to expose. The single discipline that closes most of them is the one this whole series keeps circling: never trust an input because the UI didn't offer it — cookies, `__proto__` keys, extra JSON fields, `kid` values and URL-encoded `&`/`#` are all attacker-controlled, and the server has to treat them that way before it reads a byte.

## What comes next

Step two is, functionally, mapped. Across three posts I've now rolled it enough that the wheel repeats more often than it surprises, and the one topic I never drew — insecure deserialization — is the one my tool deliberately files under *exfiltration*, because its endgame is remote code execution, not a stolen session. That's not a gap in step two. It's the on-ramp to step three. The rest of that stage is waiting there too: XXE, SSRF, SSTI, path traversal, file upload, OS command injection — the techniques whose goal isn't *become admin* but *read the file / run the command*. The wheel's pointed at exfiltration next, and this time I'll have to leave the cookie behind and go after the filesystem.

## Takeaways

- A tool that returns nothing is giving you a finding: hashcat cracking no secret on a valid **HS256** token means the key is strong and the door is elsewhere — read the `kid`, don't keep brute-forcing.
- Name traps cost minutes: **server-side parameter pollution** is not prototype pollution. Read the mechanism (`%26`/`%23` into an internal query string), not the shared word.
- The server leaks the gadget — `isAdmin` in a response, `chosen_discount` in a GET, a `reset_token` field, an introspected type. Identification is reading what's volunteered, not guessing.
- Drilling pays out in seconds: the CSRF lab that cost me a minute last time, I recognized before the page loaded. Exam speed is a trained reflex, and reruns are how you measure it.
- When the shape is known, the tooling collapses the exploit (sqlmap, DOM Invader's one-click, JWT Editor) — so the remaining skill is identification: the right insertion point, and telling two near-identical labs apart.

## Useful references

- [PortSwigger: Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)
- [PortSwigger: SQL injection — listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
- [PortSwigger: Exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint)
- [PortSwigger: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PortSwigger: Exploiting server-side parameter pollution in a query string](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string)
- [PortSwigger: Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-finding-hidden-endpoint)
- [PortSwigger: CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
- [PortSwigger: Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- [PortSwigger: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
- [PortSwigger: DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/dom-xss/lab-dom-xss-via-client-side-prototype-pollution)
- [sqlmap](https://sqlmap.org/) · [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) · [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — the tool these rolls came from]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
